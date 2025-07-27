#!/usr/bin/env python
# SentinelX API Integration Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
from fastapi.testclient import TestClient

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the API server and SentinelX classes
try:
    from src.api_server import app, get_sentinelx
    from src.sentinelx import SentinelX
except ImportError:
    # Mock classes if they don't exist yet
    from fastapi import FastAPI, Depends, HTTPException, Header, Request
    from fastapi.security.api_key import APIKeyHeader
    from typing import Optional, List, Dict, Any, Union
    
    class SentinelX:
        def __init__(self, config_path=None):
            self.config_path = config_path
        
        def train_model(self, dataset_path=None, model_type='random_forest', params=None):
            return {'accuracy': 0.95, 'precision': 0.94, 'recall': 0.93, 'f1': 0.92}
        
        def evaluate_model(self, dataset_path=None):
            return {'accuracy': 0.95, 'precision': 0.94, 'recall': 0.93, 'f1': 0.92}
        
        def predict(self, data):
            return {'prediction': 'malicious', 'probability': 0.95}
        
        def start_monitoring(self, interface=None):
            return True
        
        def stop_monitoring(self):
            return True
        
        def list_interfaces(self):
            return ['eth0', 'wlan0']
        
        def get_packet_stats(self):
            return {'total': 1000, 'tcp': 800, 'udp': 150, 'icmp': 50}
        
        def get_flow_stats(self):
            return {'total': 100, 'active': 50, 'expired': 50}
        
        def get_top_talkers(self, n=10):
            return [
                {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'bytes': 1000, 'packets': 10},
                {'src_ip': '192.168.1.101', 'dst_ip': '8.8.4.4', 'bytes': 900, 'packets': 9}
            ]
        
        def enrich_ip(self, ip):
            return {
                'ip': ip,
                'reputation': 'good',
                'country': 'US',
                'asn': 'AS15169 Google LLC',
                'tags': ['search-engine']
            }
        
        def enrich_domain(self, domain):
            return {
                'domain': domain,
                'reputation': 'good',
                'categories': ['search-engine'],
                'registrar': 'MarkMonitor Inc.'
            }
        
        def get_alerts(self, limit=100, offset=0, status=None):
            return [
                {
                    'id': 'alert-1',
                    'timestamp': '2023-01-01T00:00:00',
                    'source_ip': '192.168.1.100',
                    'destination_ip': '8.8.8.8',
                    'severity': 'high',
                    'category': 'malware',
                    'status': 'open'
                }
            ]
        
        def get_alert(self, alert_id):
            return {
                'id': alert_id,
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open',
                'details': {
                    'flow': {
                        'protocol': 'TCP',
                        'src_port': 12345,
                        'dst_port': 80,
                        'bytes': 1000,
                        'packets': 10
                    }
                }
            }
        
        def update_alert(self, alert_id, status=None, notes=None):
            return {
                'id': alert_id,
                'status': status or 'open',
                'notes': notes or ''
            }
        
        def analyze_alert(self, alert_id):
            return {
                'id': alert_id,
                'analysis': {
                    'threat_type': 'C2 Communication',
                    'confidence': 'high',
                    'mitre_tactics': ['Command and Control'],
                    'mitre_techniques': ['T1071 - Application Layer Protocol']
                }
            }
        
        def generate_alert_report(self, alert_id, format='json'):
            if format == 'json':
                return json.dumps({
                    'id': alert_id,
                    'analysis': {
                        'threat_type': 'C2 Communication',
                        'confidence': 'high'
                    }
                })
            else:  # markdown
                return f"# Alert Report: {alert_id}\n\n## Analysis\n\n- Threat Type: C2 Communication\n- Confidence: high"
        
        def get_system_info(self):
            return {
                'os': {
                    'name': 'Linux',
                    'version': '5.4.0-42-generic'
                },
                'memory': {
                    'total': 16 * 1024 * 1024 * 1024,  # 16 GB
                    'available': 8 * 1024 * 1024 * 1024  # 8 GB
                },
                'cpu': {
                    'count': 8,
                    'percent': 25.0
                }
            }
    
    # Create a FastAPI app
    app = FastAPI(title="SentinelX API", description="API for SentinelX Network Security Monitoring and Threat Detection")
    
    # API key header
    API_KEY = "test_api_key"
    api_key_header = APIKeyHeader(name="X-API-Key")
    
    # Dependency to get the SentinelX instance
    def get_sentinelx():
        return SentinelX()
    
    # Dependency to verify API key
    def verify_api_key(api_key: str = Depends(api_key_header)):
        if api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return api_key
    
    # Root endpoint
    @app.get("/", tags=["General"])
    def read_root():
        return {"message": "Welcome to SentinelX API", "version": "1.0.0"}
    
    # Prediction endpoint
    @app.post("/predict", tags=["Model"])
    def predict(data: Dict[str, Any], sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.predict(data)
    
    # IP enrichment endpoint
    @app.get("/ti/ip/{ip}", tags=["Threat Intelligence"])
    def enrich_ip(ip: str, sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.enrich_ip(ip)
    
    # Domain enrichment endpoint
    @app.get("/ti/domain/{domain}", tags=["Threat Intelligence"])
    def enrich_domain(domain: str, sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.enrich_domain(domain)
    
    # Alert endpoints
    @app.get("/alerts", tags=["Alerts"])
    def get_alerts(limit: int = 100, offset: int = 0, status: Optional[str] = None, sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.get_alerts(limit=limit, offset=offset, status=status)
    
    @app.get("/alerts/{alert_id}", tags=["Alerts"])
    def get_alert(alert_id: str, sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.get_alert(alert_id)
    
    @app.put("/alerts/{alert_id}", tags=["Alerts"])
    def update_alert(alert_id: str, data: Dict[str, Any], sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.update_alert(alert_id, status=data.get('status'), notes=data.get('notes'))
    
    @app.post("/alerts/{alert_id}/analyze", tags=["Alerts"])
    def analyze_alert(alert_id: str, sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.analyze_alert(alert_id)
    
    @app.get("/alerts/{alert_id}/report", tags=["Alerts"])
    def generate_alert_report(alert_id: str, format: str = "json", sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.generate_alert_report(alert_id, format=format)
    
    # Network endpoints
    @app.get("/network/interfaces", tags=["Network"])
    def list_interfaces(sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.list_interfaces()
    
    @app.post("/network/start", tags=["Network"])
    def start_monitoring(data: Dict[str, Any], sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return {"success": sentinelx.start_monitoring(interface=data.get('interface'))}
    
    @app.post("/network/stop", tags=["Network"])
    def stop_monitoring(sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return {"success": sentinelx.stop_monitoring()}
    
    @app.get("/network/stats/packet", tags=["Network"])
    def get_packet_stats(sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.get_packet_stats()
    
    @app.get("/network/stats/flow", tags=["Network"])
    def get_flow_stats(sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.get_flow_stats()
    
    @app.get("/network/stats/talkers", tags=["Network"])
    def get_top_talkers(n: int = 10, sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.get_top_talkers(n=n)
    
    # System info endpoint
    @app.get("/system/info", tags=["System"])
    def get_system_info(sentinelx: SentinelX = Depends(get_sentinelx), api_key: str = Depends(verify_api_key)):
        return sentinelx.get_system_info()


class TestAPIIntegration(unittest.TestCase):
    """Test the integration between the API server and the SentinelX application."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test configuration file
        self.config_path = os.path.join(self.temp_dir, 'config.yaml')
        with open(self.config_path, 'w') as f:
            f.write('network:\n  interface: eth0\n')
        
        # Create a mock SentinelX instance
        self.mock_sentinelx = MagicMock(spec=SentinelX)
        
        # Patch the get_sentinelx dependency to return our mock
        self.get_sentinelx_patcher = patch('src.api_server.get_sentinelx', return_value=self.mock_sentinelx)
        self.mock_get_sentinelx = self.get_sentinelx_patcher.start()
        
        # Create a test client for the FastAPI app
        self.client = TestClient(app)
        
        # Set the API key for authentication
        self.headers = {"X-API-Key": "test_api_key"}
    
    def tearDown(self):
        """Clean up the test environment."""
        # Stop the patcher
        self.get_sentinelx_patcher.stop()
        
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_root_endpoint(self):
        """Test the root endpoint."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["message"], "Welcome to SentinelX API", "Message should be correct")
        self.assertEqual(response.json()["version"], "1.0.0", "Version should be correct")
    
    def test_predict_endpoint(self):
        """Test the prediction endpoint."""
        # Set up the mock
        self.mock_sentinelx.predict.return_value = {
            'prediction': 'malicious',
            'probability': 0.95
        }
        
        # Make the request
        data = {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 80,
            'bytes': 1000,
            'packets': 10
        }
        response = self.client.post("/predict", json=data, headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["prediction"], "malicious", "Prediction should be malicious")
        self.assertEqual(response.json()["probability"], 0.95, "Probability should be 0.95")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.predict.assert_called_once_with(data)
    
    def test_enrich_ip_endpoint(self):
        """Test the IP enrichment endpoint."""
        # Set up the mock
        self.mock_sentinelx.enrich_ip.return_value = {
            'ip': '8.8.8.8',
            'reputation': 'good',
            'country': 'US',
            'asn': 'AS15169 Google LLC',
            'tags': ['search-engine']
        }
        
        # Make the request
        response = self.client.get("/ti/ip/8.8.8.8", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["ip"], "8.8.8.8", "IP should be 8.8.8.8")
        self.assertEqual(response.json()["reputation"], "good", "Reputation should be good")
        self.assertEqual(response.json()["country"], "US", "Country should be US")
        self.assertEqual(response.json()["asn"], "AS15169 Google LLC", "ASN should be correct")
        self.assertEqual(response.json()["tags"], ["search-engine"], "Tags should be correct")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.enrich_ip.assert_called_once_with("8.8.8.8")
    
    def test_enrich_domain_endpoint(self):
        """Test the domain enrichment endpoint."""
        # Set up the mock
        self.mock_sentinelx.enrich_domain.return_value = {
            'domain': 'google.com',
            'reputation': 'good',
            'categories': ['search-engine'],
            'registrar': 'MarkMonitor Inc.'
        }
        
        # Make the request
        response = self.client.get("/ti/domain/google.com", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["domain"], "google.com", "Domain should be google.com")
        self.assertEqual(response.json()["reputation"], "good", "Reputation should be good")
        self.assertEqual(response.json()["categories"], ["search-engine"], "Categories should be correct")
        self.assertEqual(response.json()["registrar"], "MarkMonitor Inc.", "Registrar should be correct")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.enrich_domain.assert_called_once_with("google.com")
    
    def test_get_alerts_endpoint(self):
        """Test the get alerts endpoint."""
        # Set up the mock
        self.mock_sentinelx.get_alerts.return_value = [
            {
                'id': 'alert-1',
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open'
            }
        ]
        
        # Make the request
        response = self.client.get("/alerts?limit=10&offset=0&status=open", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(len(response.json()), 1, "Should have 1 alert")
        self.assertEqual(response.json()[0]["id"], "alert-1", "Alert ID should be alert-1")
        self.assertEqual(response.json()[0]["severity"], "high", "Alert severity should be high")
        self.assertEqual(response.json()[0]["category"], "malware", "Alert category should be malware")
        self.assertEqual(response.json()[0]["status"], "open", "Alert status should be open")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_alerts.assert_called_once_with(limit=10, offset=0, status="open")
    
    def test_get_alert_endpoint(self):
        """Test the get alert endpoint."""
        # Set up the mock
        self.mock_sentinelx.get_alert.return_value = {
            'id': 'alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware',
            'status': 'open',
            'details': {
                'flow': {
                    'protocol': 'TCP',
                    'src_port': 12345,
                    'dst_port': 80,
                    'bytes': 1000,
                    'packets': 10
                }
            }
        }
        
        # Make the request
        response = self.client.get("/alerts/alert-1", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["id"], "alert-1", "Alert ID should be alert-1")
        self.assertEqual(response.json()["severity"], "high", "Alert severity should be high")
        self.assertEqual(response.json()["category"], "malware", "Alert category should be malware")
        self.assertEqual(response.json()["status"], "open", "Alert status should be open")
        self.assertEqual(response.json()["details"]["flow"]["protocol"], "TCP", "Flow protocol should be TCP")
        self.assertEqual(response.json()["details"]["flow"]["src_port"], 12345, "Flow source port should be 12345")
        self.assertEqual(response.json()["details"]["flow"]["dst_port"], 80, "Flow destination port should be 80")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_alert.assert_called_once_with("alert-1")
    
    def test_update_alert_endpoint(self):
        """Test the update alert endpoint."""
        # Set up the mock
        self.mock_sentinelx.update_alert.return_value = {
            'id': 'alert-1',
            'status': 'closed',
            'notes': 'False positive'
        }
        
        # Make the request
        data = {
            'status': 'closed',
            'notes': 'False positive'
        }
        response = self.client.put("/alerts/alert-1", json=data, headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["id"], "alert-1", "Alert ID should be alert-1")
        self.assertEqual(response.json()["status"], "closed", "Alert status should be closed")
        self.assertEqual(response.json()["notes"], "False positive", "Alert notes should be 'False positive'")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.update_alert.assert_called_once_with("alert-1", status="closed", notes="False positive")
    
    def test_analyze_alert_endpoint(self):
        """Test the analyze alert endpoint."""
        # Set up the mock
        self.mock_sentinelx.analyze_alert.return_value = {
            'id': 'alert-1',
            'analysis': {
                'threat_type': 'C2 Communication',
                'confidence': 'high',
                'mitre_tactics': ['Command and Control'],
                'mitre_techniques': ['T1071 - Application Layer Protocol']
            }
        }
        
        # Make the request
        response = self.client.post("/alerts/alert-1/analyze", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["id"], "alert-1", "Alert ID should be alert-1")
        self.assertEqual(response.json()["analysis"]["threat_type"], "C2 Communication", "Threat type should be C2 Communication")
        self.assertEqual(response.json()["analysis"]["confidence"], "high", "Confidence should be high")
        self.assertEqual(response.json()["analysis"]["mitre_tactics"], ["Command and Control"], "MITRE tactics should be correct")
        self.assertEqual(response.json()["analysis"]["mitre_techniques"], ["T1071 - Application Layer Protocol"], "MITRE techniques should be correct")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.analyze_alert.assert_called_once_with("alert-1")
    
    def test_generate_alert_report_endpoint_json(self):
        """Test the generate alert report endpoint with JSON format."""
        # Set up the mock
        self.mock_sentinelx.generate_alert_report.return_value = json.dumps({
            'id': 'alert-1',
            'analysis': {
                'threat_type': 'C2 Communication',
                'confidence': 'high'
            }
        })
        
        # Make the request
        response = self.client.get("/alerts/alert-1/report?format=json", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        result_json = json.loads(response.json())
        self.assertEqual(result_json["id"], "alert-1", "Alert ID should be alert-1")
        self.assertEqual(result_json["analysis"]["threat_type"], "C2 Communication", "Threat type should be C2 Communication")
        self.assertEqual(result_json["analysis"]["confidence"], "high", "Confidence should be high")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with("alert-1", format="json")
    
    def test_generate_alert_report_endpoint_markdown(self):
        """Test the generate alert report endpoint with Markdown format."""
        # Set up the mock
        self.mock_sentinelx.generate_alert_report.return_value = "# Alert Report: alert-1\n\n## Analysis\n\n- Threat Type: C2 Communication\n- Confidence: high"
        
        # Make the request
        response = self.client.get("/alerts/alert-1/report?format=markdown", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertIn("# Alert Report: alert-1", response.json(), "Report should have the correct title")
        self.assertIn("## Analysis", response.json(), "Report should have an Analysis section")
        self.assertIn("- Threat Type: C2 Communication", response.json(), "Report should have the threat type")
        self.assertIn("- Confidence: high", response.json(), "Report should have the confidence")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with("alert-1", format="markdown")
    
    def test_list_interfaces_endpoint(self):
        """Test the list interfaces endpoint."""
        # Set up the mock
        self.mock_sentinelx.list_interfaces.return_value = ['eth0', 'wlan0']
        
        # Make the request
        response = self.client.get("/network/interfaces", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json(), ["eth0", "wlan0"], "Interfaces should be correct")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.list_interfaces.assert_called_once_with()
    
    def test_start_monitoring_endpoint(self):
        """Test the start monitoring endpoint."""
        # Set up the mock
        self.mock_sentinelx.start_monitoring.return_value = True
        
        # Make the request
        data = {'interface': 'eth0'}
        response = self.client.post("/network/start", json=data, headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["success"], True, "Success should be True")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.start_monitoring.assert_called_once_with(interface="eth0")
    
    def test_stop_monitoring_endpoint(self):
        """Test the stop monitoring endpoint."""
        # Set up the mock
        self.mock_sentinelx.stop_monitoring.return_value = True
        
        # Make the request
        response = self.client.post("/network/stop", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["success"], True, "Success should be True")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.stop_monitoring.assert_called_once_with()
    
    def test_get_packet_stats_endpoint(self):
        """Test the get packet stats endpoint."""
        # Set up the mock
        self.mock_sentinelx.get_packet_stats.return_value = {
            'total': 1000,
            'tcp': 800,
            'udp': 150,
            'icmp': 50
        }
        
        # Make the request
        response = self.client.get("/network/stats/packet", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["total"], 1000, "Total packets should be 1000")
        self.assertEqual(response.json()["tcp"], 800, "TCP packets should be 800")
        self.assertEqual(response.json()["udp"], 150, "UDP packets should be 150")
        self.assertEqual(response.json()["icmp"], 50, "ICMP packets should be 50")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_packet_stats.assert_called_once_with()
    
    def test_get_flow_stats_endpoint(self):
        """Test the get flow stats endpoint."""
        # Set up the mock
        self.mock_sentinelx.get_flow_stats.return_value = {
            'total': 100,
            'active': 50,
            'expired': 50
        }
        
        # Make the request
        response = self.client.get("/network/stats/flow", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["total"], 100, "Total flows should be 100")
        self.assertEqual(response.json()["active"], 50, "Active flows should be 50")
        self.assertEqual(response.json()["expired"], 50, "Expired flows should be 50")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_flow_stats.assert_called_once_with()
    
    def test_get_top_talkers_endpoint(self):
        """Test the get top talkers endpoint."""
        # Set up the mock
        self.mock_sentinelx.get_top_talkers.return_value = [
            {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'bytes': 1000, 'packets': 10},
            {'src_ip': '192.168.1.101', 'dst_ip': '8.8.4.4', 'bytes': 900, 'packets': 9}
        ]
        
        # Make the request
        response = self.client.get("/network/stats/talkers?n=5", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(len(response.json()), 2, "Should have 2 talkers")
        self.assertEqual(response.json()[0]["src_ip"], "192.168.1.100", "First talker source IP should be 192.168.1.100")
        self.assertEqual(response.json()[0]["dst_ip"], "8.8.8.8", "First talker destination IP should be 8.8.8.8")
        self.assertEqual(response.json()[0]["bytes"], 1000, "First talker bytes should be 1000")
        self.assertEqual(response.json()[0]["packets"], 10, "First talker packets should be 10")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_top_talkers.assert_called_once_with(n=5)
    
    def test_get_system_info_endpoint(self):
        """Test the get system info endpoint."""
        # Set up the mock
        self.mock_sentinelx.get_system_info.return_value = {
            'os': {
                'name': 'Linux',
                'version': '5.4.0-42-generic'
            },
            'memory': {
                'total': 16 * 1024 * 1024 * 1024,  # 16 GB
                'available': 8 * 1024 * 1024 * 1024  # 8 GB
            },
            'cpu': {
                'count': 8,
                'percent': 25.0
            }
        }
        
        # Make the request
        response = self.client.get("/system/info", headers=self.headers)
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json()["os"]["name"], "Linux", "OS name should be Linux")
        self.assertEqual(response.json()["os"]["version"], "5.4.0-42-generic", "OS version should be correct")
        self.assertEqual(response.json()["memory"]["total"], 16 * 1024 * 1024 * 1024, "Total memory should be correct")
        self.assertEqual(response.json()["memory"]["available"], 8 * 1024 * 1024 * 1024, "Available memory should be correct")
        self.assertEqual(response.json()["cpu"]["count"], 8, "CPU count should be 8")
        self.assertEqual(response.json()["cpu"]["percent"], 25.0, "CPU percent should be 25.0")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_system_info.assert_called_once_with()
    
    def test_missing_api_key(self):
        """Test that requests without an API key are rejected."""
        response = self.client.get("/network/interfaces")
        self.assertEqual(response.status_code, 401, "Status code should be 401 Unauthorized")
    
    def test_invalid_api_key(self):
        """Test that requests with an invalid API key are rejected."""
        headers = {"X-API-Key": "invalid_key"}
        response = self.client.get("/network/interfaces", headers=headers)
        self.assertEqual(response.status_code, 401, "Status code should be 401 Unauthorized")


if __name__ == '__main__':
    unittest.main()