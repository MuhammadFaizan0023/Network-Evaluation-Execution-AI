from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from api.models import FlowRecord, RegisteredDevice
from api.views import FlowIngestView

DEVICE_IP = '192.168.137.250'
OTHER_DEVICE_IP = '192.168.137.243'
GATEWAY_IP = '192.168.137.1'
INTERNET_IP = '8.219.41.137'


def home_flow(src_ip, dst_ip):
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'dst_port': 443,
        'protocol': 6,
        'prediction': 'Benign',
        'confidence': 1.0,
        'is_alert': False,
        'source_type': 'home_network',
    }


@patch('api.views._send_group')
class RegisteredDeviceTrafficTests(TestCase):
    def setUp(self):
        self.device = RegisteredDevice.objects.create(
            name='Camera', ip_address=DEVICE_IP, device_type='camera'
        )

    def ingest(self, *flows):
        request = APIRequestFactory().post(
            '/api/flows/ingest/',
            {'source_type': 'home_network', 'flows': list(flows)},
            format='json',
        )
        return FlowIngestView.as_view()(request)

    def test_accepts_registered_device_traffic(self, _send_group):
        response = self.ingest(
            home_flow(DEVICE_IP, INTERNET_IP),
            home_flow(INTERNET_IP, DEVICE_IP),
        )

        self.assertEqual(response.data['saved'], 2)
        self.assertEqual(
            set(FlowRecord.objects.values_list('registered_id', flat=True)),
            {str(self.device.id)},
        )

    def test_rejects_unregistered_device_traffic(self, _send_group):
        response = self.ingest(
            home_flow(OTHER_DEVICE_IP, INTERNET_IP),
            home_flow(INTERNET_IP, OTHER_DEVICE_IP),
        )

        self.assertEqual(response.data['saved'], 0)
        self.assertFalse(FlowRecord.objects.exists())

    def test_rejects_unregistered_device_talking_to_gateway(self, _send_group):
        response = self.ingest(home_flow(OTHER_DEVICE_IP, GATEWAY_IP))

        self.assertEqual(response.data['saved'], 0)

    def test_gateway_registered_as_device_does_not_let_others_in(self, _send_group):
        RegisteredDevice.objects.create(name='Gateway', ip_address=GATEWAY_IP, device_type='other')

        response = self.ingest(home_flow(OTHER_DEVICE_IP, GATEWAY_IP))

        self.assertEqual(response.data['saved'], 0)

    def test_keeps_unregistered_device_attacking_registered_device(self, _send_group):
        response = self.ingest(home_flow(OTHER_DEVICE_IP, DEVICE_IP))

        self.assertEqual(response.data['saved'], 1)
        self.assertEqual(FlowRecord.objects.get().registered_id, str(self.device.id))

    def test_rejects_inactive_device_traffic(self, _send_group):
        self.device.is_active = False
        self.device.save()

        response = self.ingest(home_flow(DEVICE_IP, INTERNET_IP))

        self.assertEqual(response.data['saved'], 0)
