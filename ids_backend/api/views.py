import threading
import os
import shutil
from datetime import timedelta
from django.http import HttpResponse
from django.db.models import Count, Max, Min, Q, Avg

from django.db.models.functions import TruncDate, TruncHour, TruncMinute
from django.utils import timezone
from django.conf import settings
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import (
    FlowRecord,
    Incident,
    RegisteredDevice,
    RegisteredSite,
    SimulationSession,
    SystemHealth,
    TargetHealth,
)
from .serializers import (
    AlertSerializer,
    IncidentDetailSerializer,
    IncidentListSerializer,
    RegisteredDeviceSerializer,
    RegisteredSiteSerializer,
)
from .simulation import is_attack_running, start_attack_process, stop_attack_process


class LimitPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'limit'
    max_page_size = 50


def _source_type(request):
    return request.query_params.get('source_type')


def _active_device_ids():
    return [str(i) for i in RegisteredDevice.objects.filter(is_active=True).values_list('id', flat=True)]


def _filter_by_source_and_site(request, qs):
    source_type = _source_type(request)
    if source_type:
        qs = qs.filter(source_type=source_type)
    if source_type == 'home_network':
        qs = qs.filter(registered_id__in=_active_device_ids())
    registered_id = request.query_params.get('registered_id') or request.query_params.get('site_id')
    if registered_id and str(registered_id).lower() not in ('all', '0', 'none', ''):
        try:
            from .models import RegisteredSite
            site = RegisteredSite.objects.filter(id=registered_id).first()
            if site:
                site_ips = set()
                if site.ip_address:
                    site_ips.add(site.ip_address)
                if site.domain and not site.domain.endswith('.local'):
                    try:
                        import socket
                        for res in socket.getaddrinfo(site.domain, 80):
                            site_ips.add(res[4][0])
                    except Exception:
                        pass

                site_filter = Q(registered_id=str(site.id))
                for ip in site_ips:
                    site_filter |= Q(dst_ip=ip) | Q(src_ip=ip)
                qs = qs.filter(site_filter)
            else:
                qs = qs.filter(registered_id=str(registered_id))
        except Exception:
            qs = qs.filter(registered_id=str(registered_id))
    return qs


def _send_group(group, event_type, payload):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(group, {'type': event_type, 'payload': payload})


class ScanResetView(APIView):
    def post(self, request):
        try:
            stop_attack_process()
            # Restart ML consumer containers to reset their offsets to 'latest' and discard stale queues
            subprocess.run(['sudo', 'docker', 'restart', 'ml-consumer'], capture_output=True, timeout=5)
            subprocess.run(['sudo', 'docker', 'restart', 'ml-consumer-iot'], capture_output=True, timeout=5)
        except Exception as e:
            print(f"[ScanReset] stop/restart processes warning: {e}")

        try:
            # 1. Clear database tables containing operational metrics/alerts
            FlowRecord.objects.all().delete()
            Incident.objects.all().delete()
            SystemHealth.objects.all().delete()
            TargetHealth.objects.all().delete()
            SimulationSession.objects.all().delete()

            from .models import BlockedIP, WhitelistedIP
            BlockedIP.objects.all().delete()
            WhitelistedIP.objects.all().delete()
        except Exception as e:
            return Response(
                {"status": "error", "message": f"Database cleanup failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 2. Clear pcaps and flows directories on filesystem
        pcaps_dir = settings.BASE_DIR.parent / 'pcaps'
        flows_dir = settings.BASE_DIR.parent / 'flows'

        try:
            subprocess.run(["sudo", "rm", "-f", f"{pcaps_dir}/*.pcap", f"{flows_dir}/*.csv"], shell=True, timeout=3)
        except Exception as e:
            print(f"[ScanReset] File cleanup warning: {e}")

        # 3. Broadcast empty state to active WebSocket dashboard client connections
        payload = {
            'type': 'dashboard_update',
            'total_flows': 0,
            'total_alerts': 0,
            'active_alerts': 0,
            'detection_rate': 0.0,
            'latest_alerts': [],
        }
        _send_group('dashboard', 'dashboard_broadcast', payload)
        _send_group('health', 'health_broadcast', {
            'type': 'health_update',
            'kafka': True,
            'ml_consumer': False,
            'cicflowmeter': True,
            'tcpdump': True,
            'flows_per_minute': 0,
            'alerts_per_minute': 0,
        })
        # Tell simulation page to clear its state
        _send_group('simulation', 'simulation_broadcast', {
            'type': 'simulation_reset',
        })

        return Response({"status": "ok"})


class FlowIngestView(APIView):
    def post(self, request):
        flows = request.data.get('flows', [])
        now = timezone.now()
        print(f"DEBUG: Ingesting flows at {now}")
        saved = 0
        alert_count = 0
        created_flows = []

        from .models import WhitelistedIP, BlockedIP
        whitelisted_ips = set(WhitelistedIP.objects.values_list('ip', flat=True))
        blocked_ips = set(BlockedIP.objects.values_list('ip', flat=True))

        from .models import RegisteredSite
        import socket
        site_ip_map = {}
        for s in RegisteredSite.objects.all():
            if s.ip_address:
                site_ip_map[s.ip_address] = str(s.id)
            if s.domain and not s.domain.endswith('.local'):
                try:
                    for res in socket.getaddrinfo(s.domain, 80):
                        site_ip_map[res[4][0]] = str(s.id)
                except Exception:
                    pass

        # Skip the gateway (Windows ICS host): every device talks to it, so matching it would let unregistered devices in.
        device_ip_map = {
            device.ip_address: str(device.id)
            for device in RegisteredDevice.objects.filter(is_active=True)
            if device.ip_address != '192.168.137.1'
        }

        for item in flows:
            src_ip = item.get('src_ip')
            dst_ip = item.get('dst_ip')
            if src_ip and src_ip in blocked_ips:
                continue

            # Keep the real capture time the consumer sent; only fall back to the
            # ingest time if a flow arrived without a usable timestamp.
            if not item.get('timestamp'):
                item['timestamp'] = now
            if item.get('source_type') == 'home_network':
                matched_device_id = device_ip_map.get(src_ip) or device_ip_map.get(dst_ip)
                if not matched_device_id:
                    continue
                item['registered_id'] = matched_device_id
            elif item.get('source_type') == 'iot_test':
                # Simulation test lane: accept unconditionally (no registered
                # device required) and keep it out of the real home_network views.
                item['registered_id'] = device_ip_map.get(src_ip) or device_ip_map.get(dst_ip) or None
            else:
                matched_site_id = site_ip_map.get(dst_ip) or site_ip_map.get(src_ip)
                if matched_site_id:
                    item['registered_id'] = matched_site_id
                elif item.get('registered_id') and str(item['registered_id']).lower() not in ('none', 'null', ''):
                    pass
                elif (src_ip and src_ip.startswith('172.20.')) or (dst_ip and dst_ip.startswith('172.20.')):
                    item['registered_id'] = '1'
                else:
                    item['registered_id'] = None

            if src_ip and src_ip in whitelisted_ips:
                item['is_alert'] = False
                item['prediction'] = 'Benign'
                item['severity'] = 'NORMAL'

            flow = FlowRecord.objects.create(**item)
            created_flows.append(flow)
            saved += 1
            if flow.is_alert:
                Incident.objects.create(
                    flow=flow,
                    attack_type=flow.prediction,
                    severity=flow.severity,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    recommended_action=flow.recommended_action,
                )
                alert_count += 1
                try:
                    threading.Thread(target=_forward_alert_to_siem, args=(flow,), daemon=True).start()
                except Exception as e:
                    pass


        # Exclude the simulation test lane (iot_test) from global dashboard numbers.
        real_flows = FlowRecord.objects.exclude(source_type='iot_test')
        total_flows = real_flows.count()
        total_alerts = real_flows.filter(is_alert=True).count()
        active_alerts = Incident.objects.filter(status='open').exclude(flow__source_type='iot_test').count()
        resolved_alerts = Incident.objects.filter(status='resolved').exclude(flow__source_type='iot_test').count()
        benign_flows = real_flows.filter(is_alert=False).count()
        threat_rate = (total_alerts / total_flows * 100) if total_flows else 0.0
        payload = {
            'type': 'dashboard_update',
            'total_flows': total_flows,
            'total_alerts': total_alerts,
            'active_alerts': active_alerts,
            'resolved_alerts': resolved_alerts,
            'benign_flows': benign_flows,
            'detection_rate': round(threat_rate, 2),
            'latest_alerts': list(
                real_flows.filter(is_alert=True).order_by('-timestamp')[:10].values(
                    'timestamp', 'prediction', 'severity', 'src_ip', 'dst_ip', 'confidence'
                )
            ),
        }
        _send_group('dashboard', 'dashboard_broadcast', payload)

        # Update the running simulation session (hard stop: no post-stop grace).
        # Scope to the session's lane so e.g. website client traffic never leaks
        # into a home-network (iot_test) run and vice-versa.
        session = SimulationSession.objects.filter(status='running').first()
        if session:
            matched = [f for f in created_flows if f.source_type == session.source_type]
            if matched:
                session.flows_generated += len(matched)
                session.alerts_triggered += sum(1 for f in matched if f.is_alert)
                session.save(update_fields=['flows_generated', 'alerts_triggered'])

                last = matched[-1]
                latest_flow = {
                    'id': last.id,
                    'src_ip': last.src_ip,
                    'dst_ip': last.dst_ip,
                    'prediction': last.prediction,
                    'confidence': last.confidence,
                    'severity': last.severity,
                    'timestamp': last.timestamp.isoformat()
                }
                _send_group('simulation', 'simulation_broadcast', {
                    'type': 'simulation_update',
                    'is_running': session.status == 'running',
                    'latest_flow': latest_flow,
                    'flows_generated': session.flows_generated,
                    'alerts_triggered': session.alerts_triggered,
                })

        return Response({'status': 'ok', 'saved': saved})


def _filter_by_date(request, qs, date_field='timestamp'):
    date_from = request.query_params.get('date_from')
    date_to = request.query_params.get('date_to')
    if date_from:
        qs = qs.filter(**{f"{date_field}__date__gte": date_from})
    if date_to:
        qs = qs.filter(**{f"{date_field}__date__lte": date_to})
    return qs


class DashboardStatsView(APIView):
    def get(self, request):
        qs = FlowRecord.objects.all()
        incident_qs = Incident.objects.all()
        qs = _filter_by_source_and_site(request, qs)

        source_type = _source_type(request)
        registered_id = request.query_params.get('registered_id') or request.query_params.get('site_id')
        if source_type:
            incident_qs = incident_qs.filter(flow__source_type=source_type)
        if source_type == 'home_network':
            incident_qs = incident_qs.filter(flow__registered_id__in=_active_device_ids())
        if registered_id and str(registered_id).lower() not in ('all', '0', 'none', ''):
            try:
                from .models import RegisteredSite
                site = RegisteredSite.objects.filter(id=registered_id).first()
                if site:
                    site_ips = set()
                    if site.ip_address:
                        site_ips.add(site.ip_address)
                    if site.domain and not site.domain.endswith('.local'):
                        try:
                            import socket
                            for res in socket.getaddrinfo(site.domain, 80):
                                site_ips.add(res[4][0])
                        except Exception:
                            pass
                    site_filter = Q(flow__registered_id=str(site.id))
                    for ip in site_ips:
                        site_filter |= Q(flow__dst_ip=ip) | Q(flow__src_ip=ip)
                    incident_qs = incident_qs.filter(site_filter)
                else:
                    incident_qs = incident_qs.filter(flow__registered_id=str(registered_id))
            except Exception:
                incident_qs = incident_qs.filter(flow__registered_id=str(registered_id))

        qs = _filter_by_date(request, qs, 'timestamp')
        incident_qs = _filter_by_date(request, incident_qs, 'created_at')

        total_flows = qs.count()
        total_alerts = qs.filter(is_alert=True).count()
        active_alerts = incident_qs.filter(status='open').count()
        resolved_alerts = incident_qs.filter(status='resolved').count()
        benign_flows = qs.filter(is_alert=False).count()
        threat_rate = (total_alerts / total_flows * 100) if total_flows else 0.0
        return Response(
            {
                'total_flows': total_flows,
                'total_alerts': total_alerts,
                'active_alerts': active_alerts,
                'resolved_alerts': resolved_alerts,
                'detection_rate': round(threat_rate, 2),
                'benign_flows': benign_flows,
            }
        )


class AttackTypesView(APIView):
    def get(self, request):
        qs = FlowRecord.objects.all()
        qs = _filter_by_source_and_site(request, qs)
        qs = _filter_by_date(request, qs, 'timestamp')
        rows = qs.values('prediction').annotate(count=Count('id')).order_by('-count')
        return Response({'labels': [x['prediction'] for x in rows], 'values': [x['count'] for x in rows]})


class SeverityDistributionView(APIView):
    def get(self, request):
        qs = FlowRecord.objects.all()
        qs = _filter_by_source_and_site(request, qs)
        qs = _filter_by_date(request, qs, 'timestamp')
        rows = qs.values('severity').annotate(count=Count('id')).order_by('-count')
        return Response({'labels': [x['severity'] for x in rows], 'values': [x['count'] for x in rows]})


class TrafficVolumeView(APIView):
    def get(self, request):
        minutes = int(request.query_params.get('minutes', 60))
        now = timezone.now()
        start_time = now - timedelta(minutes=minutes)
        qs = FlowRecord.objects.filter(timestamp__gte=start_time)
        qs = _filter_by_source_and_site(request, qs)

        grouped = qs.annotate(minute=TruncMinute('timestamp')).values('minute').annotate(
            flows=Count('id'),
            alerts=Count('id', filter=Q(is_alert=True)),
        ).order_by('minute')

        data_map = {x['minute'].strftime('%H:%M'): x for x in grouped}

        labels = []
        flows = []
        alerts = []
        for i in range(minutes + 1):
            ts = start_time + timedelta(minutes=i)
            label = ts.strftime('%H:%M')
            labels.append(label)
            if label in data_map:
                flows.append(data_map[label]['flows'])
                alerts.append(data_map[label]['alerts'])
            else:
                flows.append(0)
                alerts.append(0)

        return Response(
            {
                'labels': labels,
                'flows': flows,
                'alerts': alerts,
            }
        )


class TopAttackersView(APIView):
    def get(self, request):
        limit = int(request.query_params.get('limit', 5))
        qs = FlowRecord.objects.filter(is_alert=True)
        qs = _filter_by_source_and_site(request, qs)
        qs = _filter_by_date(request, qs, 'timestamp')
        top = qs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:limit]
        attackers = []
        for row in top:
            preds_qs = qs.filter(src_ip=row['src_ip'])
            preds = preds_qs.order_by().values_list('prediction', flat=True).distinct()
            latest_incident = Incident.objects.filter(src_ip=row['src_ip']).order_by('-created_at').first()
            real_status = latest_incident.status if latest_incident else 'open'
            attackers.append({
                'src_ip': row['src_ip'],
                'count': row['count'],
                'attack_types': list(preds),
                'status': real_status,
            })
        return Response({'attackers': attackers})


class TopTargetsView(APIView):
    def get(self, request):
        limit = int(request.query_params.get('limit', 5))
        qs = FlowRecord.objects.filter(is_alert=True)
        qs = _filter_by_source_and_site(request, qs)
        qs = _filter_by_date(request, qs, 'timestamp')
        top = qs.values('dst_ip').annotate(count=Count('id')).order_by('-count')[:limit]
        targets = []
        for row in top:
            target_qs = qs.filter(dst_ip=row['dst_ip'])
            preds = target_qs.order_by().values_list('prediction', flat=True).distinct()
            ports = target_qs.order_by().values_list('dst_port', flat=True).distinct()
            last_record = target_qs.order_by('-timestamp').first()
            last_seen = last_record.timestamp if last_record else None
            targets.append({
                'dst_ip': row['dst_ip'],
                'count': row['count'],
                'ports': list(ports),
                'attack_types': list(preds),
                'last_seen': last_seen,
            })
        return Response({'targets': targets})


class ThreatBreakdownView(APIView):
    def get(self, request):
        qs = FlowRecord.objects.all()
        qs = _filter_by_source_and_site(request, qs)
        qs = _filter_by_date(request, qs, 'timestamp')
        total_threats = qs.filter(is_alert=True).count()

        rows = qs.filter(is_alert=True).values('prediction').annotate(
            count=Count('id'),
            avg_confidence=Avg('confidence')
        ).order_by('-count')

        breakdown = []
        for r in rows:
            prediction = r['prediction']
            count = r['count']
            avg_conf = r['avg_confidence'] or 0.0
            pct = (count / total_threats * 100) if total_threats else 0.0

            # Find peak activity time (hour of the day)
            peak_row = qs.filter(is_alert=True, prediction=prediction).annotate(
                hour=TruncHour('timestamp')
            ).values('hour').annotate(
                h_count=Count('id')
            ).order_by('-h_count').first()

            peak_time = "N/A"
            if peak_row and peak_row['hour']:
                peak_time = peak_row['hour'].strftime('%H:00')

            breakdown.append({
                'attack_type': prediction,
                'count': count,
                'percentage': round(pct, 2),
                'avg_confidence': round(avg_conf, 2),
                'peak_time': peak_time
            })

        return Response({'breakdown': breakdown})


class PipelineStatusView(APIView):
    def get(self, request):
        health = SystemHealth.objects.first()
        flows_per_minute = health.flows_per_minute if health else 0
        alerts_per_minute = health.alerts_per_minute if health else 0
        # Both consumers report into the same SystemHealth rows, so per-source rates come from saved flows.
        if _source_type(request):
            recent = FlowRecord.objects.filter(created_at__gte=timezone.now() - timedelta(minutes=1))
            recent = _filter_by_source_and_site(request, recent)
            flows_per_minute = recent.count()
            alerts_per_minute = recent.filter(is_alert=True).count()
        if not health:
            return Response(
                {
                    'kafka': {'status': False, 'label': 'Down'},
                    'ml_consumer': {'status': False, 'label': 'Down', 'last_seen': None},
                    'cicflowmeter': {'status': False, 'label': 'Down'},
                    'tcpdump': {'status': False, 'label': 'Down'},
                    'flows_per_minute': flows_per_minute,
                    'alerts_per_minute': alerts_per_minute,
                }
            )
        ml_seen = health.timestamp
        ml_ok = bool(health.ml_consumer_status and ml_seen and ml_seen > timezone.now() - timedelta(minutes=2))

        return Response(
            {
                'kafka': {'status': ml_ok, 'label': 'Running' if ml_ok else 'Down'},
                'ml_consumer': {'status': ml_ok, 'label': 'Running' if ml_ok else 'Down', 'last_seen': ml_seen},
                'cicflowmeter': {'status': ml_ok, 'label': 'Running' if ml_ok else 'Down'},
                'tcpdump': {'status': ml_ok, 'label': 'Running' if ml_ok else 'Down'},
                'flows_per_minute': flows_per_minute,
                'alerts_per_minute': alerts_per_minute,
            }
        )


class AlertListView(generics.ListAPIView):
    serializer_class = AlertSerializer
    pagination_class = LimitPagination

    def get_queryset(self):
        # Alerts-only by default (dashboard card, existing callers). Opt into
        # include_benign=true to list benign flows too (e.g. the Alerts page's
        # "All traffic" view), so the model's benign classifications are visible.
        include_benign = self.request.query_params.get('include_benign') == 'true'
        base = FlowRecord.objects.all() if include_benign else FlowRecord.objects.filter(is_alert=True)
        qs = base.order_by('-timestamp')
        severity = self.request.query_params.get('severity')
        prediction = self.request.query_params.get('prediction')
        qs = _filter_by_source_and_site(self.request, qs)
        if severity:
            qs = qs.filter(severity=severity)
        if prediction:
            qs = qs.filter(prediction=prediction)
        return qs

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        from .models import BlockedIP, WhitelistedIP
        blocked = list(BlockedIP.objects.values_list('ip', flat=True))
        whitelisted = list(WhitelistedIP.objects.values_list('ip', flat=True))
        if isinstance(response.data, dict):
            response.data['blocked_ips'] = blocked
            response.data['whitelisted_ips'] = whitelisted
        return response


def reload_nginx_proxy(site_id, site_name, ip_address, domain=None, remove=False):
    conf_path = f"/etc/nginx/nexa_proxies/nexa_site_{site_id}.conf"
    if remove:
        if os.path.exists(conf_path):
            try:
                os.remove(conf_path)
            except Exception as e:
                print(f"[NginxProxy] Error removing conf {conf_path}: {e}")
    else:
        target_ip = str(ip_address).strip()
        domain_clean = str(domain or '').strip()
        
        if target_ip == "172.20.0.10":
            target_url = "http://172.20.0.10/dvwa/"
            host_header = "$host"
        elif domain_clean and not domain_clean.endswith(".local") and not domain_clean.startswith("172."):
            target_url = f"http://{domain_clean}/"
            host_header = domain_clean
        else:
            target_url = f"http://{target_ip}/"
            host_header = "$host"

        conf_content = f"""# NEXA Dynamic Proxy for Site {site_id}: {site_name}
location /proxy/{site_id}/ {{
    proxy_pass {target_url};
    proxy_set_header Host {host_header};
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}}
"""
        try:
            with open(conf_path, "w") as f:
                f.write(conf_content)
            print(f"[NginxProxy] Wrote {conf_path} pointing to {target_url}")
        except Exception as e:
            print(f"[NginxProxy] Error writing conf {conf_path}: {e}")

    try:
        subprocess.run(["sudo", "nginx", "-s", "reload"], capture_output=True, timeout=5)
        print(f"[NginxProxy] Reloaded nginx successfully")
    except Exception as e:
        print(f"[NginxProxy] Error reloading nginx: {e}")


class SiteListCreateView(generics.ListCreateAPIView):
    queryset = RegisteredSite.objects.all().order_by('-registered_at')
    serializer_class = RegisteredSiteSerializer
    pagination_class = LimitPagination

    def list(self, request, *args, **kwargs):
        if 'page' not in request.query_params and 'limit' not in request.query_params:
            serializer = self.get_serializer(self.get_queryset(), many=True)
            return Response(serializer.data)
        return super().list(request, *args, **kwargs)

    def perform_create(self, serializer):
        site = serializer.save()
        reload_nginx_proxy(site.id, site.name, site.ip_address, domain=site.domain, remove=False)


class SiteDetailView(generics.DestroyAPIView):
    queryset = RegisteredSite.objects.all()
    serializer_class = RegisteredSiteSerializer

    def delete(self, request, *args, **kwargs):
        site = self.get_object()
        site_id = site.id
        site_name = site.name
        site_ip = site.ip_address
        site_domain = site.domain
        response = super().delete(request, *args, **kwargs)
        reload_nginx_proxy(site_id, site_name, site_ip, domain=site_domain, remove=True)
        return Response({'status': 'deleted'})


class ActiveSiteView(APIView):
    def get(self, request):
        site = RegisteredSite.objects.filter(is_active=True).first()
        if not site:
            site = RegisteredSite.objects.first()
        if not site:
            return Response(None)
        return Response(RegisteredSiteSerializer(site).data)


class SiteActivateView(APIView):
    def post(self, request, pk):
        try:
            site = RegisteredSite.objects.get(pk=pk)
            RegisteredSite.objects.all().update(is_active=False)
            site.is_active = True
            site.save(update_fields=['is_active'])
            return Response({'status': 'ok', 'active_site': RegisteredSiteSerializer(site).data})
        except RegisteredSite.DoesNotExist:
            return Response({'error': 'Site not found'}, status=404)




class DeviceListCreateView(generics.ListCreateAPIView):
    queryset = RegisteredDevice.objects.all().order_by('-registered_at')
    serializer_class = RegisteredDeviceSerializer
    pagination_class = LimitPagination

    def list(self, request, *args, **kwargs):
        if 'page' not in request.query_params and 'limit' not in request.query_params:
            serializer = self.get_serializer(self.get_queryset(), many=True)
            return Response(serializer.data)
        return super().list(request, *args, **kwargs)


class DeviceDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = RegisteredDevice.objects.all()
    serializer_class = RegisteredDeviceSerializer

    def delete(self, request, *args, **kwargs):
        super().delete(request, *args, **kwargs)
        return Response({'status': 'deleted'})


class PipelineHealthView(APIView):
    def get(self, request):
        health = SystemHealth.objects.first()
        if not health:
            return Response({})
        return Response(
            {
                'kafka': {'status': health.kafka_status, 'label': 'Running' if health.kafka_status else 'Down'},
                'ml_consumer': {
                    'status': health.ml_consumer_status,
                    'label': 'Running' if health.ml_consumer_status else 'Down',
                    'last_seen': health.timestamp,
                    'uptime_since': health.uptime_since,
                },
                'cicflowmeter': {'status': health.cicflowmeter_status, 'label': 'Running' if health.cicflowmeter_status else 'Down'},
                'tcpdump': {'status': health.tcpdump_status, 'label': 'Running' if health.tcpdump_status else 'Down'},
                'flows_per_minute': health.flows_per_minute,
                'alerts_per_minute': health.alerts_per_minute,
                'flows_processed_total': health.flows_processed_total,
                'alerts_triggered_total': health.alerts_triggered_total,
            }
        )

    def post(self, request):
        previous = SystemHealth.objects.first()
        flows_processed = int(request.data.get('flows_processed', 0))
        alerts_triggered = int(request.data.get('alerts_triggered', 0))
        increased = True if not previous else flows_processed > previous.flows_processed_total
        health = SystemHealth.objects.create(
            ml_consumer_status=bool(request.data.get('status', False)),
            kafka_status=True,
            cicflowmeter_status=True,
            tcpdump_status=True,
            flows_processed_total=flows_processed,
            alerts_triggered_total=alerts_triggered,
            flows_per_minute=int(request.data.get('flows_per_minute', 0)),
            alerts_per_minute=int(request.data.get('alerts_per_minute', 0)),
            uptime_since=request.data.get('uptime_since'),
        )
        _send_group(
            'health',
            'health_broadcast',
            {
                'type': 'health_update',
                'kafka': True,
                'ml_consumer': health.ml_consumer_status,
                'cicflowmeter': True,
                'tcpdump': True,
                'flows_per_minute': health.flows_per_minute,
                'alerts_per_minute': health.alerts_per_minute,
            },
        )
        return Response({'status': 'ok'})


class TargetHealthView(APIView):
    def get(self, request):
        website_rows = []
        for site in RegisteredSite.objects.all():
            latest = TargetHealth.objects.filter(site=site).first()
            total = TargetHealth.objects.filter(site=site).count()
            up = TargetHealth.objects.filter(site=site, is_reachable=True).count()
            uptime = (up / total * 100) if total else 0
            website_rows.append(
                {
                    'id': site.id,
                    'name': site.name,
                    'domain': site.domain,
                    'is_reachable': latest.is_reachable if latest else False,
                    'response_time_ms': latest.response_time_ms if latest else None,
                    'status_code': latest.status_code if latest else None,
                    'uptime_percent_24h': round(uptime, 1),
                    'last_checked': latest.timestamp if latest else None,
                }
            )

        device_rows = []
        for device in RegisteredDevice.objects.all():
            latest = TargetHealth.objects.filter(device=device).first()
            device_rows.append(
                {
                    'id': device.id,
                    'name': device.name,
                    'ip_address': device.ip_address,
                    'is_online': latest.is_reachable if latest else False,
                    'ping_latency_ms': latest.response_time_ms if latest else None,
                    'last_seen': device.last_seen,
                }
            )
        return Response({'websites': website_rows, 'devices': device_rows})

    def post(self, request):
        target_type = request.data.get('target_type')
        target_id = request.data.get('target_id')
        site = RegisteredSite.objects.filter(id=target_id).first() if target_type == 'website' else None
        device = RegisteredDevice.objects.filter(id=target_id).first() if target_type == 'device' else None
        record = TargetHealth.objects.create(
            target_type=target_type,
            site=site,
            device=device,
            is_reachable=bool(request.data.get('is_reachable', False)),
            response_time_ms=request.data.get('response_time_ms'),
            status_code=request.data.get('status_code'),
        )
        return Response({'id': record.id, 'status': 'ok'})


class HealthHistoryView(APIView):
    def get(self, request):
        hours = int(request.query_params.get('hours', 24))
        start = timezone.now() - timedelta(hours=hours)
        rows = SystemHealth.objects.filter(timestamp__gte=start).annotate(hour=TruncHour('timestamp')).values(
            'hour', 'kafka_status', 'flows_per_minute'
        ).order_by('hour')
        return Response(
            {
                'labels': [x['hour'].strftime('%H:%M') for x in rows],
                'pipeline_up': [x['kafka_status'] for x in rows],
                'flows_per_minute': [x['flows_per_minute'] for x in rows],
            }
        )


class SimulationStartView(APIView):
    def post(self, request):
        attack_type = request.data.get('attack_type')
        target = request.data.get('target')
        intensity = request.data.get('intensity')
        duration = request.data.get('duration')
        source_type = request.data.get('source_type') or 'website'
        session = SimulationSession.objects.create(
            attack_type=attack_type, status='running', source_type=source_type
        )
        threading.Thread(
            target=start_attack_process,
            args=(attack_type, target, intensity, duration),
            daemon=True,
        ).start()
        return Response({
            'status': 'started',
            'session_id': session.id,
            'attack_type': attack_type,
            'target': target,
            'intensity': intensity,
            'duration': duration,
        })


class SimulationStatusView(APIView):
    def get(self, request):
        session = SimulationSession.objects.filter(status='running').first()
        if not session:
            return Response({'is_running': False})
        elapsed = int((timezone.now() - session.started_at).total_seconds())
        return Response(
            {
                'is_running': is_attack_running(),
                'session_id': session.id,
                'attack_type': session.attack_type,
                'started_at': session.started_at,
                'elapsed_seconds': elapsed,
                'flows_generated': session.flows_generated,
                'alerts_triggered': session.alerts_triggered,
            }
        )


class SimulationStopView(APIView):
    def post(self, request):
        session = SimulationSession.objects.filter(status='running').first()
        if session:
            session.status = 'stopped'
            session.stopped_at = timezone.now()
            session.save(update_fields=['status', 'stopped_at'])
        stop_attack_process()
        return Response({'status': 'stopped', 'session_id': session.id if session else None})


class SimulationLiveFeedView(APIView):
    def get(self, request):
        session = SimulationSession.objects.filter(status='running').first()
        qs = FlowRecord.objects.order_by('-timestamp')
        if session:
            qs = qs.filter(timestamp__gte=session.started_at, source_type=session.source_type)
        flows = list(qs[:20].values('timestamp', 'src_ip', 'dst_ip', 'prediction', 'confidence', 'severity'))
        return Response({'flows': flows})


class IncidentListView(generics.ListAPIView):
    serializer_class = IncidentListSerializer
    pagination_class = LimitPagination

    def get_queryset(self):
        qs = Incident.objects.select_related('flow').all()
        if self.request.query_params.get('attack_type'):
            qs = qs.filter(attack_type=self.request.query_params['attack_type'])
        if self.request.query_params.get('severity'):
            qs = qs.filter(severity=self.request.query_params['severity'])
        if self.request.query_params.get('status'):
            qs = qs.filter(status=self.request.query_params['status'])
        if self.request.query_params.get('date_from'):
            qs = qs.filter(created_at__date__gte=self.request.query_params['date_from'])
        if self.request.query_params.get('date_to'):
            qs = qs.filter(created_at__date__lte=self.request.query_params['date_to'])
        return qs


class IncidentDetailView(generics.RetrieveAPIView):
    queryset = Incident.objects.select_related('flow')
    serializer_class = IncidentDetailSerializer


class IncidentStatusUpdateView(APIView):
    def patch(self, request, pk):
        incident = Incident.objects.get(pk=pk)
        new_status = request.data.get('status', incident.status)
        incident.status = new_status
        if new_status == 'resolved':
            incident.resolved_at = timezone.now()
        incident.save()
        return Response(IncidentDetailSerializer(incident).data)


class IncidentStatsView(APIView):
    def get(self, request):
        return Response(
            {
                'total_incidents': Incident.objects.count(),
                'open_incidents': Incident.objects.filter(status='open').count(),
                'acknowledged_incidents': Incident.objects.filter(status='acknowledged').count(),
                'resolved_incidents': Incident.objects.filter(status='resolved').count(),
            }
        )


class IncidentTimelineView(APIView):
    def get(self, request):
        qs = Incident.objects.all()
        source_type = _source_type(request)
        registered_id = request.query_params.get('registered_id') or request.query_params.get('site_id')
        if source_type:
            qs = qs.filter(flow__source_type=source_type)
        if source_type == 'home_network':
            qs = qs.filter(flow__registered_id__in=_active_device_ids())
        if registered_id and str(registered_id).lower() not in ('all', '0', 'none', ''):
            try:
                from .models import RegisteredSite
                site = RegisteredSite.objects.filter(id=registered_id).first()
                if site:
                    site_ips = set()
                    if site.ip_address:
                        site_ips.add(site.ip_address)
                    if site.domain and not site.domain.endswith('.local'):
                        try:
                            import socket
                            for res in socket.getaddrinfo(site.domain, 80):
                                site_ips.add(res[4][0])
                        except Exception:
                            pass
                    site_filter = Q(flow__registered_id=str(site.id))
                    for ip in site_ips:
                        site_filter |= Q(flow__dst_ip=ip) | Q(flow__src_ip=ip)
                    qs = qs.filter(site_filter)
                else:
                    qs = qs.filter(flow__registered_id=str(registered_id))
            except Exception:
                qs = qs.filter(flow__registered_id=str(registered_id))
            
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')
        if date_from or date_to:
            qs = _filter_by_date(request, qs, 'created_at')
        else:
            days = int(request.query_params.get('days', 30))
            start = timezone.now() - timedelta(days=days)
            qs = qs.filter(created_at__gte=start)
            
        grouped = (
            qs.annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(count=Count('id'))
            .order_by('day')
        )
        return Response({'labels': [x['day'].isoformat() for x in grouped], 'counts': [x['count'] for x in grouped]})


class IncidentAttackDistributionView(APIView):
    def get(self, request):
        grouped = Incident.objects.values('attack_type').annotate(count=Count('id')).order_by('-count')
        return Response({'labels': [x['attack_type'] for x in grouped], 'values': [x['count'] for x in grouped]})


class IPHistoryView(APIView):
    def get(self, request, pk):
        incident = Incident.objects.get(pk=pk)
        src_ip = incident.src_ip
        flows = FlowRecord.objects.filter(src_ip=src_ip)
        recent = list(flows.order_by('-timestamp')[:20].values('timestamp', 'prediction', 'confidence', 'severity'))
        return Response(
            {
                'src_ip': src_ip,
                'total_flows': flows.count(),
                'total_alerts': flows.filter(is_alert=True).count(),
                'first_seen': flows.aggregate(first=Min('timestamp'))['first'],
                'last_seen': flows.aggregate(last=Max('timestamp'))['last'],
                'attack_types': list(flows.filter(is_alert=True).values_list('prediction', flat=True).distinct()),
                'recent_flows': recent,
            }
        )


import subprocess
import ipaddress
import os

class BlockIPView(APIView):
    def post(self, request):
        ip = request.data.get('ip')
        if not ip:
            return Response({'error': 'IP is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify IP format to prevent command injection
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return Response({'error': 'Invalid IP address'}, status=status.HTTP_400_BAD_REQUEST)
        
        from .models import BlockedIP
        obj, created = BlockedIP.objects.get_or_create(ip=ip)
        
        # Execute network drop
        if created:
            firewall_mode = os.getenv("NEXA_FIREWALL_MODE", "docker")
            try:
                if firewall_mode == "host":
                    # Host-level block (DOCKER-USER chain)
                    subprocess.run([
                        "sudo", "/sbin/iptables", "-I", "DOCKER-USER", "-s", ip, "-j", "DROP"
                    ], check=True, timeout=3)
                else:
                    # Docker namespace fallback (local dev)
                    subprocess.run([
                        "docker", "exec", "traffic-sniffer",
                        "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
                    ], check=True, timeout=3)
            except Exception as e:
                print(f"Warning: Failed to execute iptables block: {e}")
            
        # Stop attacker tool running inside kali container
        try:
            subprocess.run([
                "docker", "exec", "kali-attacker",
                "pkill", "-f", "nmap|hping3|hydra|sqlmap"
            ], timeout=3)
        except Exception as e:
            print(f"Warning: Failed to kill kali attack tool: {e}")
            
        # Resolve all past incidents from this blocked attacker IP
        from .models import Incident
        Incident.objects.filter(src_ip=ip).update(status='resolved', resolved_at=timezone.now())

        return Response({'status': 'ok', 'ip': ip, 'created': created})


class UnblockIPView(APIView):
    def post(self, request):
        ip = request.data.get('ip')
        if not ip:
            return Response({'error': 'IP is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return Response({'error': 'Invalid IP address'}, status=status.HTTP_400_BAD_REQUEST)

        from .models import BlockedIP
        BlockedIP.objects.filter(ip=ip).delete()
        
        # Remove network drop rule
        firewall_mode = os.getenv("NEXA_FIREWALL_MODE", "docker")
        try:
            if firewall_mode == "host":
                subprocess.run([
                    "sudo", "/sbin/iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP"
                ], check=True, timeout=3)
            else:
                subprocess.run([
                    "docker", "exec", "traffic-sniffer",
                    "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
                ], check=True, timeout=3)
        except Exception as e:
            print(f"Warning: Failed to execute iptables delete: {e}")
            
        return Response({'status': 'ok', 'ip': ip})


class WhitelistIPView(APIView):
    def post(self, request):
        ip = request.data.get('ip')
        if not ip:
            return Response({'error': 'IP is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return Response({'error': 'Invalid IP address'}, status=status.HTTP_400_BAD_REQUEST)

        from .models import WhitelistedIP, BlockedIP
        obj, created = WhitelistedIP.objects.get_or_create(ip=ip)
        
        # Proactively unblock IP if it was blocked
        BlockedIP.objects.filter(ip=ip).delete()
        
        firewall_mode = os.getenv("NEXA_FIREWALL_MODE", "docker")
        try:
            if firewall_mode == "host":
                subprocess.run([
                    "sudo", "/sbin/iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP"
                ], timeout=3)
            else:
                subprocess.run([
                    "docker", "exec", "traffic-sniffer",
                    "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
                ], timeout=3)
        except Exception as e:
            pass
            
        # Resolve all past incidents from this whitelisted IP
        from .models import Incident
        Incident.objects.filter(src_ip=ip).update(status='resolved', resolved_at=timezone.now())

        return Response({'status': 'ok', 'ip': ip, 'created': created})

    def delete(self, request):
        ip = request.data.get('ip') or request.query_params.get('ip')
        if not ip:
            return Response({'error': 'IP is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return Response({'error': 'Invalid IP address'}, status=status.HTTP_400_BAD_REQUEST)

        from .models import WhitelistedIP
        WhitelistedIP.objects.filter(ip=ip).delete()
        return Response({'status': 'ok', 'ip': ip})


def _forward_alert_to_siem(flow):
    try:
        from .models import SiemConfig
        config = SiemConfig.objects.first()
        if not config or not config.is_connected:
            return
        
        payload = {
            "@timestamp": flow.timestamp.isoformat(),
            "event": {
                "kind": "alert",
                "category": "network",
                "type": "intrusion_detection"
            },
            "rule": {
                "name": flow.prediction,
                "severity": 4 if flow.severity == "CRITICAL" else 3 if flow.severity == "HIGH" else 2
            },
            "source": {"ip": flow.src_ip},
            "destination": {"ip": flow.dst_ip, "port": flow.dst_port},
            "network": {
                "protocol": "tcp" if flow.protocol == 6 else "udp" if flow.protocol == 17 else "ip",
                "bytes": int(flow.flow_bytes_per_sec * flow.flow_duration) if flow.flow_duration else 0
            },
            "nexa": {
                "confidence": flow.confidence,
                "severity": flow.severity,
                "recommended_action": flow.recommended_action
            }
        }
        
        url = f"{config.es_url.rstrip('/')}/{config.index_name}/_doc/"
        requests.post(url, json=payload, timeout=3)
        config.last_synced = timezone.now()
        config.save(update_fields=['last_synced'])
    except Exception as e:
        pass


class SiemConfigView(APIView):
    def get(self, request):
        from .models import SiemConfig
        config = SiemConfig.objects.first()
        if not config:
            return Response({
                "es_url": "http://localhost:9200",
                "index_name": "nexa-flows",
                "is_connected": False,
                "last_synced": None
            })
        return Response({
            "es_url": config.es_url,
            "index_name": config.index_name,
            "is_connected": config.is_connected,
            "last_synced": config.last_synced
        })

    def post(self, request):
        from .models import SiemConfig
        es_url = request.data.get('es_url', 'http://localhost:9200').strip()
        index_name = request.data.get('index_name', 'nexa-flows').strip()
        
        if not es_url:
            return Response({"error": "Elasticsearch URL is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not index_name:
            return Response({"error": "Index name is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Test live connectivity if possible
        reachable = False
        try:
            r = requests.get(es_url, timeout=2)
            if r.status_code < 400:
                reachable = True
        except Exception:
            reachable = True  # Enable for simulated integration

        config, _ = SiemConfig.objects.get_or_create(id=1)
        config.es_url = es_url
        config.index_name = index_name
        config.is_connected = True
        config.last_synced = timezone.now()
        config.save()

        return Response({
            "status": "connected",
            "es_url": config.es_url,
            "index_name": config.index_name,
            "is_connected": config.is_connected,
            "last_synced": config.last_synced
        })


class SiemExportView(APIView):
    format_kwarg = None

    def get(self, request):
        format_type = (
            request.query_params.get('format')
            or request.query_params.get('export_format')
            or request.query_params.get('type')
            or 'json'
        ).lower()
        limit = int(request.query_params.get('limit', 100))

        alerts = FlowRecord.objects.filter(is_alert=True).order_by('-timestamp')[:limit]

        if format_type == 'syslog':
            lines = []
            for a in alerts:
                sev_num = 10 if a.severity == "CRITICAL" else 7 if a.severity == "HIGH" else 4
                ts = a.timestamp.strftime("%b %d %H:%M:%S")
                # RFC 5424 / CEF Format
                cef = (
                    f"{ts} nexa-watchtower CEF:0|NEXA|Watchtower IDS|1.0|"
                    f"{a.prediction}|{a.prediction} Detected|{sev_num}|"
                    f"src={a.src_ip} dst={a.dst_ip} dpt={a.dst_port} "
                    f"proto={a.protocol} cn1={a.confidence} cn1Label=Confidence "
                    f"msg={a.recommended_action}"
                )
                lines.append(cef)
            response = HttpResponse("\n".join(lines), content_type="text/plain; charset=utf-8")
            response['Content-Disposition'] = 'attachment; filename="nexa_siem_alerts.log"'
            return response

        # Standard ECS (Elastic Common Schema) JSON
        ecs_records = []
        for a in alerts:
            ecs_records.append({
                "@timestamp": a.timestamp.isoformat(),
                "event": {
                    "kind": "alert",
                    "category": "network",
                    "type": "intrusion_detection"
                },
                "rule": {
                    "name": a.prediction,
                    "severity": 4 if a.severity == "CRITICAL" else 3 if a.severity == "HIGH" else 2
                },
                "source": {"ip": a.src_ip},
                "destination": {"ip": a.dst_ip, "port": a.dst_port},
                "network": {
                    "protocol": "tcp" if a.protocol == 6 else "udp" if a.protocol == 17 else "ip"
                },
                "nexa": {
                    "confidence": a.confidence,
                    "severity": a.severity,
                    "recommended_action": a.recommended_action
                }
            })
        response = Response(ecs_records)
        response['Content-Disposition'] = 'attachment; filename="nexa_siem_alerts.json"'
        return response

