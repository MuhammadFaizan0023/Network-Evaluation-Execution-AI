from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from api.models import FlowRecord
from api.views import FlowIngestView


class FlowIngestViewTests(TestCase):
    @patch('api.views._send_group')
    def test_rejects_unregistered_home_network_flows(self, _send_group):
        request = APIRequestFactory().post(
            '/api/flows/ingest/',
            {
                'source_type': 'home_network',
                'flows': [
                    {
                        'src_ip': '192.168.1.50',
                        'dst_ip': '192.168.1.1',
                        'dst_port': 443,
                        'protocol': 6,
                        'prediction': 'Benign',
                        'confidence': 1.0,
                        'is_alert': False,
                        'source_type': 'home_network',
                    }
                ],
            },
            format='json',
        )

        response = FlowIngestView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['saved'], 0)
        self.assertFalse(FlowRecord.objects.exists())
