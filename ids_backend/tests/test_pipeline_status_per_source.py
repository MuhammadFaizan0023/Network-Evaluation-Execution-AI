from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import FlowRecord, RegisteredDevice, SystemHealth

DEVICE_IP = '192.168.137.250'


def make_flow(source_type, registered_id='1', is_alert=False):
    return FlowRecord.objects.create(
        timestamp=timezone.now(),
        src_ip=DEVICE_IP,
        dst_ip='8.219.41.137',
        prediction='scanning' if is_alert else 'Benign',
        confidence=0.9,
        is_alert=is_alert,
        source_type=source_type,
        registered_id=registered_id,
    )


class PipelineStatusPerSourceTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        SystemHealth.objects.create(ml_consumer_status=True, flows_per_minute=99, alerts_per_minute=42)
        self.device = RegisteredDevice.objects.create(name='Camera', ip_address=DEVICE_IP, device_type='camera')

    def status(self, source_type=None):
        query = f'?source_type={source_type}' if source_type else ''
        return self.client.get(f'/api/dashboard/pipeline-status/{query}').json()

    def test_rates_are_separate_per_source(self):
        make_flow('website')
        make_flow('website', is_alert=True)
        make_flow('home_network', registered_id=str(self.device.id))

        web = self.status('website')
        home = self.status('home_network')

        self.assertEqual((web['flows_per_minute'], web['alerts_per_minute']), (2, 1))
        self.assertEqual((home['flows_per_minute'], home['alerts_per_minute']), (1, 0))

    def test_flows_older_than_a_minute_not_counted(self):
        old = make_flow('website')
        FlowRecord.objects.filter(id=old.id).update(created_at=timezone.now() - timedelta(minutes=2))

        self.assertEqual(self.status('website')['flows_per_minute'], 0)

    def test_unregistered_device_flows_not_counted(self):
        make_flow('home_network', registered_id=str(self.device.id), is_alert=True)
        self.device.delete()

        home = self.status('home_network')

        self.assertEqual((home['flows_per_minute'], home['alerts_per_minute']), (0, 0))

    def test_without_source_type_uses_latest_health_report(self):
        make_flow('website')

        status = self.status()

        self.assertEqual((status['flows_per_minute'], status['alerts_per_minute']), (99, 42))
