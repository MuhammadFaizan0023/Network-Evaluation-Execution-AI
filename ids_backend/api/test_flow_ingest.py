from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from .models import FlowRecord
from .views import FlowIngestView


class FlowIngestViewTests(TestCase):
    @patch('api.views._send_group')
    def test_ingests_unregistered_home_network_flows_separately(self, _send_group):
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
                    }
                ],
            },
            format='json',
        )

        response = FlowIngestView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['saved'], 1)
        flow = FlowRecord.objects.get()
        self.assertEqual(flow.source_type, 'home_network')
        self.assertIsNone(flow.registered_id)
