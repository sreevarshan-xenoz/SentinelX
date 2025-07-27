#!/usr/bin/env python
# SentinelX API Endpoints Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
from fastapi.testclient import TestClient

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.api.api_server import app
from src.api.endpoints import (
    root_endpoint, predict_endpoint, enrich_ip_endpoint, enrich_domain_endpoint,
    get_alerts_endpoint, get_alert_endpoint, update_alert_endpoint,
    analyze_alert_endpoint, generate_report_endpoint, get_interfaces_endpoint,
    start_capture_endpoint, stop_capture_endpoint, get_packet_stats_endpoint,
    get_flow_stats_endpoint, get_top_talkers_endpoint, get_system_info_endpoint
)
from src.sentinelx import SentinelX


class TestAPIEndpoints(unittest.TestCase):
    """Test the API endpoints."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a test client
        self.client = TestClient(app)
        
        # Mock the SentinelX instance
        self.mock_sentinelx = MagicMock(spec=SentinelX)
        
        # Mock the get_sentinelx_instance function
        self.get_sentinelx_patcher = patch('src.api.endpoints.get_sentinelx_instance')
        self.mock_get_sentinelx = self.get_sentinelx_patcher.start()
        self.mock_get_sentinelx.return_value = self.mock_sentinelx
        
        # Mock the verify_api_key function
        self.verify_api_key_patcher = patch('src.api.endpoints.verify_api_key')
        self.mock_verify_api_key = self.verify_api_key_patcher.start()
        self.mock_verify_api_key.return_value = True
    
    def tearDown(self):
        """Clean up the test environment."""
        # Stop the patchers
        self.get_sentinelx_patcher.stop()
        self.verify_api_key_patcher.stop()
    
    def test_root_endpoint(self):
        """Test the root endpoint."""
        # Call the endpoint directly
        response = root_endpoint()
        
        # Check that the response is correct
        self.assertEqual(response, {'message': 'SentinelX API Server is running'})
    
    def test_predict_endpoint(self):
        """Test the predict endpoint."""
        # Set up the mocks
        self.mock_sentinelx.predict.return_value = {
            'prediction': 'malicious',
            'probability': 0.95,
            'features': {'feature1': 1.0, 'feature2': 2.0}
        }
        
        # Create the request data
        request_data = {
            'data': {'feature1': 1.0, 'feature2': 2.0},
            'model_type': 'random_forest'
        }
        
        # Call the endpoint directly
        response = predict_endpoint(request_data, 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['prediction'], 'malicious')
        self.assertEqual(response['probability'], 0.95)
        
        # Check that the SentinelX.predict method was called correctly
        self.mock_sentinelx.predict.assert_called_once_with(
            {'feature1': 1.0, 'feature2': 2.0},
            'random_forest'
        )
    
    def test_enrich_ip_endpoint(self):
        """Test the enrich IP endpoint."""
        # Set up the mocks
        self.mock_sentinelx.enrich_ip.return_value = {
            'ip': '192.168.1.1',
            'reputation': 'malicious',
            'country': 'US',
            'asn': 12345
        }
        
        # Call the endpoint directly
        response = enrich_ip_endpoint('192.168.1.1', 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['ip'], '192.168.1.1')
        self.assertEqual(response['reputation'], 'malicious')
        
        # Check that the SentinelX.enrich_ip method was called correctly
        self.mock_sentinelx.enrich_ip.assert_called_once_with('192.168.1.1')
    
    def test_enrich_domain_endpoint(self):
        """Test the enrich domain endpoint."""
        # Set up the mocks
        self.mock_sentinelx.enrich_domain.return_value = {
            'domain': 'example.com',
            'reputation': 'malicious',
            'categories': ['malware', 'phishing']
        }
        
        # Call the endpoint directly
        response = enrich_domain_endpoint('example.com', 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['domain'], 'example.com')
        self.assertEqual(response['reputation'], 'malicious')
        
        # Check that the SentinelX.enrich_domain method was called correctly
        self.mock_sentinelx.enrich_domain.assert_called_once_with('example.com')
    
    def test_get_alerts_endpoint(self):
        """Test the get alerts endpoint."""
        # Set up the mocks
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
        
        # Call the endpoint directly
        response = get_alerts_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(len(response), 2)
        self.assertEqual(response[0]['id'], '12345')
        self.assertEqual(response[1]['id'], '67890')
        
        # Check that the SentinelX.get_alerts method was called correctly
        self.mock_sentinelx.get_alerts.assert_called_once()
    
    def test_get_alert_endpoint(self):
        """Test the get alert endpoint."""
        # Set up the mocks
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
        
        # Call the endpoint directly
        response = get_alert_endpoint('12345', 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['id'], '12345')
        self.assertEqual(response['alert_type'], 'port_scan')
        
        # Check that the SentinelX.get_alert method was called correctly
        self.mock_sentinelx.get_alert.assert_called_once_with('12345')
    
    def test_update_alert_endpoint(self):
        """Test the update alert endpoint."""
        # Set up the mocks
        self.mock_sentinelx.update_alert_status.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'acknowledged'
        }
        
        # Create the request data
        request_data = {'status': 'acknowledged'}
        
        # Call the endpoint directly
        response = update_alert_endpoint('12345', request_data, 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['id'], '12345')
        self.assertEqual(response['status'], 'acknowledged')
        
        # Check that the SentinelX.update_alert_status method was called correctly
        self.mock_sentinelx.update_alert_status.assert_called_once_with('12345', 'acknowledged')
    
    def test_analyze_alert_endpoint(self):
        """Test the analyze alert endpoint."""
        # Set up the mocks
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
        
        # Call the endpoint directly
        response = analyze_alert_endpoint('12345', 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['explanation'], 'This is a port scan attack')
        self.assertEqual(response['mitre_techniques'][0]['technique_id'], 'T1046')
        
        # Check that the SentinelX.analyze_alert method was called correctly
        self.mock_sentinelx.analyze_alert.assert_called_once_with('12345')
    
    def test_generate_report_endpoint(self):
        """Test the generate report endpoint."""
        # Set up the mocks
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
        
        # Call the endpoint directly
        response = generate_report_endpoint('12345', 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['alert_id'], '12345')
        self.assertEqual(response['explanation'], 'This is a port scan attack')
        
        # Check that the SentinelX.generate_alert_report method was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with('12345')
    
    def test_get_interfaces_endpoint(self):
        """Test the get interfaces endpoint."""
        # Set up the mocks
        self.mock_sentinelx.get_available_interfaces.return_value = ['eth0', 'lo']
        
        # Call the endpoint directly
        response = get_interfaces_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response, ['eth0', 'lo'])
        
        # Check that the SentinelX.get_available_interfaces method was called correctly
        self.mock_sentinelx.get_available_interfaces.assert_called_once()
    
    def test_start_capture_endpoint(self):
        """Test the start capture endpoint."""
        # Set up the mocks
        self.mock_sentinelx.start_network_monitoring.return_value = True
        
        # Create the request data
        request_data = {'interface': 'eth0'}
        
        # Call the endpoint directly
        response = start_capture_endpoint(request_data, 'test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['status'], 'success')
        self.assertEqual(response['message'], 'Network capture started on interface eth0')
        
        # Check that the SentinelX.start_network_monitoring method was called correctly
        self.mock_sentinelx.start_network_monitoring.assert_called_once_with('eth0')
    
    def test_stop_capture_endpoint(self):
        """Test the stop capture endpoint."""
        # Set up the mocks
        self.mock_sentinelx.stop_network_monitoring.return_value = True
        
        # Call the endpoint directly
        response = stop_capture_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['status'], 'success')
        self.assertEqual(response['message'], 'Network capture stopped')
        
        # Check that the SentinelX.stop_network_monitoring method was called correctly
        self.mock_sentinelx.stop_network_monitoring.assert_called_once()
    
    def test_get_packet_stats_endpoint(self):
        """Test the get packet stats endpoint."""
        # Set up the mocks
        self.mock_sentinelx.get_packet_stats.return_value = {
            'total_packets': 100,
            'total_bytes': 10000,
            'protocol_stats': {'TCP': 80, 'UDP': 20},
            'port_stats': {80: 50, 443: 30}
        }
        
        # Call the endpoint directly
        response = get_packet_stats_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['total_packets'], 100)
        self.assertEqual(response['total_bytes'], 10000)
        
        # Check that the SentinelX.get_packet_stats method was called correctly
        self.mock_sentinelx.get_packet_stats.assert_called_once()
    
    def test_get_flow_stats_endpoint(self):
        """Test the get flow stats endpoint."""
        # Set up the mocks
        self.mock_sentinelx.get_flow_stats.return_value = {
            'active_flows': 10,
            'total_flows': 20,
            'expired_flows': 10
        }
        
        # Call the endpoint directly
        response = get_flow_stats_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['active_flows'], 10)
        self.assertEqual(response['total_flows'], 20)
        
        # Check that the SentinelX.get_flow_stats method was called correctly
        self.mock_sentinelx.get_flow_stats.assert_called_once()
    
    def test_get_top_talkers_endpoint(self):
        """Test the get top talkers endpoint."""
        # Set up the mocks
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
        
        # Call the endpoint directly
        response = get_top_talkers_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(len(response), 2)
        self.assertEqual(response[0]['src_ip'], '192.168.1.1')
        self.assertEqual(response[1]['src_ip'], '192.168.1.3')
        
        # Check that the SentinelX.get_top_talkers method was called correctly
        self.mock_sentinelx.get_top_talkers.assert_called_once_with(10)
    
    def test_get_system_info_endpoint(self):
        """Test the get system info endpoint."""
        # Set up the mocks
        self.mock_sentinelx.get_system_info.return_value = {
            'hostname': 'test-host',
            'os': 'Linux',
            'cpu_usage': 10.5,
            'memory_usage': 50.2,
            'disk_usage': 30.8
        }
        
        # Call the endpoint directly
        response = get_system_info_endpoint('test_api_key')
        
        # Check that the response is correct
        self.assertEqual(response['hostname'], 'test-host')
        self.assertEqual(response['os'], 'Linux')
        
        # Check that the SentinelX.get_system_info method was called correctly
        self.mock_sentinelx.get_system_info.assert_called_once()


if __name__ == '__main__':
    unittest.main()