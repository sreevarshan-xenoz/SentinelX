#!/usr/bin/env python
# SentinelX API Server Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
from fastapi.testclient import TestClient

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.api.api_server import app, get_sentinelx_instance, verify_api_key
from src.sentinelx import SentinelX


class TestAPIServer(unittest.TestCase):
    """Test the API server."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a test client
        self.client = TestClient(app)
        
        # Mock the SentinelX instance
        self.mock_sentinelx = MagicMock(spec=SentinelX)
        
        # Mock the get_sentinelx_instance function
        self.original_get_sentinelx = get_sentinelx_instance
        get_sentinelx_instance.__code__ = (lambda: self.mock_sentinelx).__code__
        
        # Mock the verify_api_key function
        self.original_verify_api_key = verify_api_key
        verify_api_key.__code__ = (lambda x: True).__code__
    
    def tearDown(self):
        """Clean up the test environment."""
        # Restore the original functions
        get_sentinelx_instance.__code__ = self.original_get_sentinelx.__code__
        verify_api_key.__code__ = self.original_verify_api_key.__code__
    
    def test_root_endpoint(self):
        """Test the root endpoint."""
        # Make a request to the root endpoint
        response = self.client.get('/')
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'message': 'SentinelX API Server is running'})
    
    def test_predict_endpoint(self):
        """Test the predict endpoint."""
        # Mock the SentinelX.predict method
        self.mock_sentinelx.predict.return_value = {
            'prediction': 'malicious',
            'probability': 0.95,
            'features': {'feature1': 1.0, 'feature2': 2.0}
        }
        
        # Make a request to the predict endpoint
        response = self.client.post(
            '/api/predict',
            json={
                'data': {'feature1': 1.0, 'feature2': 2.0},
                'model_type': 'random_forest'
            },
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['prediction'], 'malicious')
        self.assertEqual(response.json()['probability'], 0.95)
        
        # Check that the SentinelX.predict method was called correctly
        self.mock_sentinelx.predict.assert_called_once_with(
            {'feature1': 1.0, 'feature2': 2.0},
            'random_forest'
        )
    
    def test_enrich_ip_endpoint(self):
        """Test the enrich IP endpoint."""
        # Mock the SentinelX.enrich_ip method
        self.mock_sentinelx.enrich_ip.return_value = {
            'ip': '192.168.1.1',
            'reputation': 'malicious',
            'country': 'US',
            'asn': 12345
        }
        
        # Make a request to the enrich IP endpoint
        response = self.client.get(
            '/api/enrich/ip/192.168.1.1',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['ip'], '192.168.1.1')
        self.assertEqual(response.json()['reputation'], 'malicious')
        
        # Check that the SentinelX.enrich_ip method was called correctly
        self.mock_sentinelx.enrich_ip.assert_called_once_with('192.168.1.1')
    
    def test_enrich_domain_endpoint(self):
        """Test the enrich domain endpoint."""
        # Mock the SentinelX.enrich_domain method
        self.mock_sentinelx.enrich_domain.return_value = {
            'domain': 'example.com',
            'reputation': 'malicious',
            'categories': ['malware', 'phishing']
        }
        
        # Make a request to the enrich domain endpoint
        response = self.client.get(
            '/api/enrich/domain/example.com',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['domain'], 'example.com')
        self.assertEqual(response.json()['reputation'], 'malicious')
        
        # Check that the SentinelX.enrich_domain method was called correctly
        self.mock_sentinelx.enrich_domain.assert_called_once_with('example.com')
    
    def test_get_alerts_endpoint(self):
        """Test the get alerts endpoint."""
        # Mock the SentinelX.get_alerts method
        self.mock_sentinelx.get_alerts.return_value = [
            {
                'id': '12345',
                'alert_type': 'port_scan',
                'source_ip': '192.168.1.1',
                'destination_ip': '192.168.1.2',
                'severity': 'high',
                'timestamp': '2023-01-01T00:00:00',
                'status': 'new'
            },
            {
                'id': '67890',
                'alert_type': 'brute_force',
                'source_ip': '192.168.1.3',
                'destination_ip': '192.168.1.4',
                'severity': 'medium',
                'timestamp': '2023-01-02T00:00:00',
                'status': 'acknowledged'
            }
        ]
        
        # Make a request to the get alerts endpoint
        response = self.client.get(
            '/api/alerts',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 2)
        self.assertEqual(response.json()[0]['id'], '12345')
        self.assertEqual(response.json()[1]['id'], '67890')
        
        # Check that the SentinelX.get_alerts method was called correctly
        self.mock_sentinelx.get_alerts.assert_called_once()
    
    def test_get_alert_endpoint(self):
        """Test the get alert endpoint."""
        # Mock the SentinelX.get_alert method
        self.mock_sentinelx.get_alert.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20}
        }
        
        # Make a request to the get alert endpoint
        response = self.client.get(
            '/api/alerts/12345',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['id'], '12345')
        self.assertEqual(response.json()['alert_type'], 'port_scan')
        
        # Check that the SentinelX.get_alert method was called correctly
        self.mock_sentinelx.get_alert.assert_called_once_with('12345')
    
    def test_update_alert_endpoint(self):
        """Test the update alert endpoint."""
        # Mock the SentinelX.update_alert_status method
        self.mock_sentinelx.update_alert_status.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'acknowledged'
        }
        
        # Make a request to the update alert endpoint
        response = self.client.put(
            '/api/alerts/12345',
            json={'status': 'acknowledged'},
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['id'], '12345')
        self.assertEqual(response.json()['status'], 'acknowledged')
        
        # Check that the SentinelX.update_alert_status method was called correctly
        self.mock_sentinelx.update_alert_status.assert_called_once_with('12345', 'acknowledged')
    
    def test_analyze_alert_endpoint(self):
        """Test the analyze alert endpoint."""
        # Mock the SentinelX.analyze_alert method
        self.mock_sentinelx.analyze_alert.return_value = {
            'explanation': 'This is a port scan attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1046',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.'
                }
            ],
            'cve_ids': [],
            'remediation': 'Block the source IP address'
        }
        
        # Make a request to the analyze alert endpoint
        response = self.client.get(
            '/api/alerts/12345/analyze',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['explanation'], 'This is a port scan attack')
        self.assertEqual(response.json()['mitre_techniques'][0]['technique_id'], 'T1046')
        
        # Check that the SentinelX.analyze_alert method was called correctly
        self.mock_sentinelx.analyze_alert.assert_called_once_with('12345')
    
    def test_generate_report_endpoint(self):
        """Test the generate report endpoint."""
        # Mock the SentinelX.generate_alert_report method
        self.mock_sentinelx.generate_alert_report.return_value = {
            'alert_id': '12345',
            'alert_type': 'port_scan',
            'explanation': 'This is a port scan attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1046',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.'
                }
            ],
            'cve_ids': [],
            'remediation': 'Block the source IP address'
        }
        
        # Make a request to the generate report endpoint
        response = self.client.get(
            '/api/alerts/12345/report',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['alert_id'], '12345')
        self.assertEqual(response.json()['explanation'], 'This is a port scan attack')
        
        # Check that the SentinelX.generate_alert_report method was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with('12345')
    
    def test_get_interfaces_endpoint(self):
        """Test the get interfaces endpoint."""
        # Mock the SentinelX.get_available_interfaces method
        self.mock_sentinelx.get_available_interfaces.return_value = ['eth0', 'lo']
        
        # Make a request to the get interfaces endpoint
        response = self.client.get(
            '/api/network/interfaces',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), ['eth0', 'lo'])
        
        # Check that the SentinelX.get_available_interfaces method was called correctly
        self.mock_sentinelx.get_available_interfaces.assert_called_once()
    
    def test_start_capture_endpoint(self):
        """Test the start capture endpoint."""
        # Mock the SentinelX.start_network_monitoring method
        self.mock_sentinelx.start_network_monitoring.return_value = True
        
        # Make a request to the start capture endpoint
        response = self.client.post(
            '/api/network/capture/start',
            json={'interface': 'eth0'},
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'success', 'message': 'Network capture started on interface eth0'})
        
        # Check that the SentinelX.start_network_monitoring method was called correctly
        self.mock_sentinelx.start_network_monitoring.assert_called_once_with('eth0')
    
    def test_stop_capture_endpoint(self):
        """Test the stop capture endpoint."""
        # Mock the SentinelX.stop_network_monitoring method
        self.mock_sentinelx.stop_network_monitoring.return_value = True
        
        # Make a request to the stop capture endpoint
        response = self.client.post(
            '/api/network/capture/stop',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'success', 'message': 'Network capture stopped'})
        
        # Check that the SentinelX.stop_network_monitoring method was called correctly
        self.mock_sentinelx.stop_network_monitoring.assert_called_once()
    
    def test_get_packet_stats_endpoint(self):
        """Test the get packet stats endpoint."""
        # Mock the SentinelX.get_packet_stats method
        self.mock_sentinelx.get_packet_stats.return_value = {
            'total_packets': 100,
            'total_bytes': 10000,
            'protocol_stats': {'TCP': 80, 'UDP': 20},
            'port_stats': {80: 50, 443: 30}
        }
        
        # Make a request to the get packet stats endpoint
        response = self.client.get(
            '/api/network/stats/packets',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['total_packets'], 100)
        self.assertEqual(response.json()['total_bytes'], 10000)
        
        # Check that the SentinelX.get_packet_stats method was called correctly
        self.mock_sentinelx.get_packet_stats.assert_called_once()
    
    def test_get_flow_stats_endpoint(self):
        """Test the get flow stats endpoint."""
        # Mock the SentinelX.get_flow_stats method
        self.mock_sentinelx.get_flow_stats.return_value = {
            'active_flows': 10,
            'total_flows': 20,
            'expired_flows': 10
        }
        
        # Make a request to the get flow stats endpoint
        response = self.client.get(
            '/api/network/stats/flows',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['active_flows'], 10)
        self.assertEqual(response.json()['total_flows'], 20)
        
        # Check that the SentinelX.get_flow_stats method was called correctly
        self.mock_sentinelx.get_flow_stats.assert_called_once()
    
    def test_get_top_talkers_endpoint(self):
        """Test the get top talkers endpoint."""
        # Mock the SentinelX.get_top_talkers method
        self.mock_sentinelx.get_top_talkers.return_value = [
            {
                'src_ip': '192.168.1.1',
                'dst_ip': '192.168.1.2',
                'protocol': 'TCP',
                'packets': 100,
                'bytes': 10000
            },
            {
                'src_ip': '192.168.1.3',
                'dst_ip': '192.168.1.4',
                'protocol': 'UDP',
                'packets': 50,
                'bytes': 5000
            }
        ]
        
        # Make a request to the get top talkers endpoint
        response = self.client.get(
            '/api/network/stats/top-talkers',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 2)
        self.assertEqual(response.json()[0]['src_ip'], '192.168.1.1')
        self.assertEqual(response.json()[1]['src_ip'], '192.168.1.3')
        
        # Check that the SentinelX.get_top_talkers method was called correctly
        self.mock_sentinelx.get_top_talkers.assert_called_once_with(10)
    
    def test_get_system_info_endpoint(self):
        """Test the get system info endpoint."""
        # Mock the SentinelX.get_system_info method
        self.mock_sentinelx.get_system_info.return_value = {
            'hostname': 'test-host',
            'os': 'Linux',
            'cpu_usage': 10.5,
            'memory_usage': 50.2,
            'disk_usage': 30.8
        }
        
        # Make a request to the get system info endpoint
        response = self.client.get(
            '/api/system/info',
            headers={'X-API-Key': 'test_api_key'}
        )
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['hostname'], 'test-host')
        self.assertEqual(response.json()['os'], 'Linux')
        
        # Check that the SentinelX.get_system_info method was called correctly
        self.mock_sentinelx.get_system_info.assert_called_once()
    
    def test_missing_api_key(self):
        """Test that requests without an API key are rejected."""
        # Restore the original verify_api_key function
        verify_api_key.__code__ = self.original_verify_api_key.__code__
        
        # Make a request without an API key
        response = self.client.get('/api/alerts')
        
        # Check that the response is correct
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['detail'], 'API key is missing or invalid')
    
    def test_invalid_api_key(self):
        """Test that requests with an invalid API key are rejected."""
        # Restore the original verify_api_key function
        verify_api_key.__code__ = self.original_verify_api_key.__code__
        
        # Mock the ConfigManager to return a different API key
        with patch('src.api.api_server.ConfigManager') as mock_config_manager:
            mock_config_manager.get_instance.return_value.get.return_value = {'api_key': 'different_key'}
            
            # Make a request with an invalid API key
            response = self.client.get(
                '/api/alerts',
                headers={'X-API-Key': 'invalid_key'}
            )
            
            # Check that the response is correct
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()['detail'], 'API key is missing or invalid')


if __name__ == '__main__':
    unittest.main()