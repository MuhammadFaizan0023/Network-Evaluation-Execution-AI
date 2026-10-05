from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import FlowRecord, Incident, RegisteredDevice

DEVICE_IP = '192.168.137.250'


def make_flow(registered_id, source_type='home_network', is_alert=True):
    flow = FlowRecord.objects.create(
        timestamp=timezone.now(),
        src_ip=DEVICE_IP,
        dst_ip='8.219.41.137',
        prediction='scanning' if is_alert else 'Benign',
        confidence=0.9,
        is_alert=is_alert,
        severity='HIGH' if is_alert else 'NORMAL',
        source_type=source_type,
        registered_id=registered_id,
    )
    if is_alert:
        Incident.objects.create(
            flow=flow, attack_type=flow.prediction, severity=flow.severity,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip,
        )
    return flow


class HomeDashboardRegisteredOnlyTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def stats(self, source_type='home_network'):
        return self.client.get(f'/api/dashboard/stats/?source_type={source_type}').json()

    def test_no_registered_device_shows_all_zeros(self):
        make_flow('1')

        stats = self.stats()

        self.assertEqual(stats['total_flows'], 0)
        self.assertEqual(stats['total_alerts'], 0)
        self.assertEqual(stats['active_alerts'], 0)
        self.assertEqual(stats['benign_flows'], 0)

    def test_no_registered_device_shows_no_alerts(self):
        make_flow('1')

        alerts = self.client.get('/api/alerts/?source_type=home_network&page=1&limit=10').json()

        self.assertEqual(alerts['count'], 0)

    def test_deleted_device_flows_hidden_active_device_flows_shown(self):
        old = RegisteredDevice.objects.create(name='Old', ip_address=DEVICE_IP, device_type='camera')
        make_flow(str(old.id))
        old.delete()
        new = RegisteredDevice.objects.create(name='Camera', ip_address=DEVICE_IP, device_type='camera')
        make_flow(str(new.id), is_alert=False)

        stats = self.stats()

        self.assertEqual(stats['total_flows'], 1)
        self.assertEqual(stats['total_alerts'], 0)
        self.assertEqual(stats['active_alerts'], 0)

    def test_inactive_device_flows_hidden(self):
        device = RegisteredDevice.objects.create(
            name='Camera', ip_address=DEVICE_IP, device_type='camera', is_active=False
        )
        make_flow(str(device.id))

        self.assertEqual(self.stats()['total_flows'], 0)

    def test_website_stats_unaffected(self):
        make_flow('1', source_type='website')

        self.assertEqual(self.stats('website')['total_flows'], 1)
