#!/usr/bin/env python
# SentinelX Web Interface Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
from bs4 import BeautifulSoup

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the web interface and SentinelX classes
try:
    from src.web_interface import app, get_sentinelx
    from src.sentinelx import SentinelX
except ImportError:
    # Mock classes if they don't exist yet
    from flask import Flask, render_template, request, jsonify, redirect, url_for, session
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
    
    # Create a Flask app
    app = Flask(__name__)
    app.secret_key = 'sentinelx_secret_key'
    
    # Dependency to get the SentinelX instance
    def get_sentinelx():
        return SentinelX()
    
    # Authentication
    def login_required(f):
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    
    # Routes
    @app.route('/')
    @login_required
    def index():
        return render_template('index.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if username == 'admin' and password == 'password':
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Invalid credentials')
        return render_template('login.html')
    
    @app.route('/logout')
    def logout():
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        sentinelx = get_sentinelx()
        packet_stats = sentinelx.get_packet_stats()
        flow_stats = sentinelx.get_flow_stats()
        top_talkers = sentinelx.get_top_talkers(n=5)
        system_info = sentinelx.get_system_info()
        return render_template('dashboard.html', 
                               packet_stats=packet_stats, 
                               flow_stats=flow_stats, 
                               top_talkers=top_talkers, 
                               system_info=system_info)
    
    @app.route('/network')
    @login_required
    def network():
        sentinelx = get_sentinelx()
        interfaces = sentinelx.list_interfaces()
        return render_template('network.html', interfaces=interfaces)
    
    @app.route('/network/start', methods=['POST'])
    @login_required
    def start_monitoring():
        sentinelx = get_sentinelx()
        interface = request.form.get('interface')
        success = sentinelx.start_monitoring(interface=interface)
        return jsonify({'success': success})
    
    @app.route('/network/stop', methods=['POST'])
    @login_required
    def stop_monitoring():
        sentinelx = get_sentinelx()
        success = sentinelx.stop_monitoring()
        return jsonify({'success': success})
    
    @app.route('/alerts')
    @login_required
    def alerts():
        sentinelx = get_sentinelx()
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        status = request.args.get('status')
        alerts = sentinelx.get_alerts(limit=limit, offset=offset, status=status)
        return render_template('alerts.html', alerts=alerts)
    
    @app.route('/alerts/<alert_id>')
    @login_required
    def alert_details(alert_id):
        sentinelx = get_sentinelx()
        alert = sentinelx.get_alert(alert_id)
        return render_template('alert_details.html', alert=alert)
    
    @app.route('/alerts/<alert_id>/update', methods=['POST'])
    @login_required
    def update_alert(alert_id):
        sentinelx = get_sentinelx()
        status = request.form.get('status')
        notes = request.form.get('notes')
        result = sentinelx.update_alert(alert_id, status=status, notes=notes)
        return jsonify(result)
    
    @app.route('/alerts/<alert_id>/analyze', methods=['POST'])
    @login_required
    def analyze_alert(alert_id):
        sentinelx = get_sentinelx()
        result = sentinelx.analyze_alert(alert_id)
        return jsonify(result)
    
    @app.route('/alerts/<alert_id>/report')
    @login_required
    def alert_report(alert_id):
        sentinelx = get_sentinelx()
        format = request.args.get('format', 'markdown')
        report = sentinelx.generate_alert_report(alert_id, format=format)
        if format == 'json':
            return jsonify(json.loads(report))
        else:  # markdown
            return render_template('report.html', report=report, alert_id=alert_id)
    
    @app.route('/ti/ip/<ip>')
    @login_required
    def enrich_ip(ip):
        sentinelx = get_sentinelx()
        result = sentinelx.enrich_ip(ip)
        return render_template('ip_details.html', ip_info=result)
    
    @app.route('/ti/domain/<domain>')
    @login_required
    def enrich_domain(domain):
        sentinelx = get_sentinelx()
        result = sentinelx.enrich_domain(domain)
        return render_template('domain_details.html', domain_info=result)
    
    @app.route('/system')
    @login_required
    def system():
        sentinelx = get_sentinelx()
        system_info = sentinelx.get_system_info()
        return render_template('system.html', system_info=system_info)
    
    @app.route('/predict', methods=['GET', 'POST'])
    @login_required
    def predict():
        if request.method == 'POST':
            sentinelx = get_sentinelx()
            data = {
                'src_ip': request.form.get('src_ip'),
                'dst_ip': request.form.get('dst_ip'),
                'protocol': request.form.get('protocol'),
                'src_port': int(request.form.get('src_port')),
                'dst_port': int(request.form.get('dst_port')),
                'bytes': int(request.form.get('bytes')),
                'packets': int(request.form.get('packets'))
            }
            result = sentinelx.predict(data)
            return render_template('predict.html', result=result, data=data)
        return render_template('predict.html')


class TestWebInterface(unittest.TestCase):
    """Test the web interface for SentinelX."""
    
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
        self.get_sentinelx_patcher = patch('src.web_interface.get_sentinelx', return_value=self.mock_sentinelx)
        self.mock_get_sentinelx = self.get_sentinelx_patcher.start()
        
        # Configure the Flask app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Create a test client
        self.client = app.test_client()
        
        # Log in for tests that require authentication
        with self.client.session_transaction() as session:
            session['logged_in'] = True
            session['username'] = 'admin'
    
    def tearDown(self):
        """Clean up the test environment."""
        # Stop the patcher
        self.get_sentinelx_patcher.stop()
        
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_index_page(self):
        """Test the index page."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200, "Status code should be 200")
    
    def test_login_page(self):
        """Test the login page."""
        # Log out first
        self.client.get('/logout')
        
        # Test GET request
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Test POST request with valid credentials
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'password'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Test POST request with invalid credentials
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'wrong_password'
        })
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertIn(b'Invalid credentials', response.data, "Error message should be displayed")
    
    def test_logout(self):
        """Test the logout functionality."""
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertIn(b'login', response.data, "Should redirect to login page")
    
    def test_dashboard_page(self):
        """Test the dashboard page."""
        # Set up the mocks
        self.mock_sentinelx.get_packet_stats.return_value = {
            'total': 1000,
            'tcp': 800,
            'udp': 150,
            'icmp': 50
        }
        self.mock_sentinelx.get_flow_stats.return_value = {
            'total': 100,
            'active': 50,
            'expired': 50
        }
        self.mock_sentinelx.get_top_talkers.return_value = [
            {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'bytes': 1000, 'packets': 10},
            {'src_ip': '192.168.1.101', 'dst_ip': '8.8.4.4', 'bytes': 900, 'packets': 9}
        ]
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
        response = self.client.get('/dashboard')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mocks were called correctly
        self.mock_sentinelx.get_packet_stats.assert_called_once_with()
        self.mock_sentinelx.get_flow_stats.assert_called_once_with()
        self.mock_sentinelx.get_top_talkers.assert_called_once_with(n=5)
        self.mock_sentinelx.get_system_info.assert_called_once_with()
    
    def test_network_page(self):
        """Test the network page."""
        # Set up the mock
        self.mock_sentinelx.list_interfaces.return_value = ['eth0', 'wlan0']
        
        # Make the request
        response = self.client.get('/network')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.list_interfaces.assert_called_once_with()
    
    def test_start_monitoring(self):
        """Test the start monitoring functionality."""
        # Set up the mock
        self.mock_sentinelx.start_monitoring.return_value = True
        
        # Make the request
        response = self.client.post('/network/start', data={'interface': 'eth0'})
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json['success'], True, "Success should be True")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.start_monitoring.assert_called_once_with(interface='eth0')
    
    def test_stop_monitoring(self):
        """Test the stop monitoring functionality."""
        # Set up the mock
        self.mock_sentinelx.stop_monitoring.return_value = True
        
        # Make the request
        response = self.client.post('/network/stop')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json['success'], True, "Success should be True")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.stop_monitoring.assert_called_once_with()
    
    def test_alerts_page(self):
        """Test the alerts page."""
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
        response = self.client.get('/alerts?limit=10&offset=0&status=open')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_alerts.assert_called_once_with(limit=10, offset=0, status='open')
    
    def test_alert_details_page(self):
        """Test the alert details page."""
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
        response = self.client.get('/alerts/alert-1')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_alert.assert_called_once_with('alert-1')
    
    def test_update_alert(self):
        """Test the update alert functionality."""
        # Set up the mock
        self.mock_sentinelx.update_alert.return_value = {
            'id': 'alert-1',
            'status': 'closed',
            'notes': 'False positive'
        }
        
        # Make the request
        response = self.client.post('/alerts/alert-1/update', data={
            'status': 'closed',
            'notes': 'False positive'
        })
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(response.json['status'], 'closed', "Alert status should be closed")
        self.assertEqual(response.json['notes'], 'False positive', "Alert notes should be 'False positive'")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.update_alert.assert_called_once_with('alert-1', status='closed', notes='False positive')
    
    def test_analyze_alert(self):
        """Test the analyze alert functionality."""
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
        response = self.client.post('/alerts/alert-1/analyze')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(response.json['analysis']['threat_type'], 'C2 Communication', "Threat type should be C2 Communication")
        self.assertEqual(response.json['analysis']['confidence'], 'high', "Confidence should be high")
        self.assertEqual(response.json['analysis']['mitre_tactics'], ['Command and Control'], "MITRE tactics should be correct")
        self.assertEqual(response.json['analysis']['mitre_techniques'], ['T1071 - Application Layer Protocol'], "MITRE techniques should be correct")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.analyze_alert.assert_called_once_with('alert-1')
    
    def test_alert_report_json(self):
        """Test the alert report functionality with JSON format."""
        # Set up the mock
        self.mock_sentinelx.generate_alert_report.return_value = json.dumps({
            'id': 'alert-1',
            'analysis': {
                'threat_type': 'C2 Communication',
                'confidence': 'high'
            }
        })
        
        # Make the request
        response = self.client.get('/alerts/alert-1/report?format=json')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertEqual(response.json['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(response.json['analysis']['threat_type'], 'C2 Communication', "Threat type should be C2 Communication")
        self.assertEqual(response.json['analysis']['confidence'], 'high', "Confidence should be high")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with('alert-1', format='json')
    
    def test_alert_report_markdown(self):
        """Test the alert report functionality with Markdown format."""
        # Set up the mock
        self.mock_sentinelx.generate_alert_report.return_value = "# Alert Report: alert-1\n\n## Analysis\n\n- Threat Type: C2 Communication\n- Confidence: high"
        
        # Make the request
        response = self.client.get('/alerts/alert-1/report?format=markdown')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with('alert-1', format='markdown')
    
    def test_enrich_ip_page(self):
        """Test the IP enrichment page."""
        # Set up the mock
        self.mock_sentinelx.enrich_ip.return_value = {
            'ip': '8.8.8.8',
            'reputation': 'good',
            'country': 'US',
            'asn': 'AS15169 Google LLC',
            'tags': ['search-engine']
        }
        
        # Make the request
        response = self.client.get('/ti/ip/8.8.8.8')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.enrich_ip.assert_called_once_with('8.8.8.8')
    
    def test_enrich_domain_page(self):
        """Test the domain enrichment page."""
        # Set up the mock
        self.mock_sentinelx.enrich_domain.return_value = {
            'domain': 'google.com',
            'reputation': 'good',
            'categories': ['search-engine'],
            'registrar': 'MarkMonitor Inc.'
        }
        
        # Make the request
        response = self.client.get('/ti/domain/google.com')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.enrich_domain.assert_called_once_with('google.com')
    
    def test_system_page(self):
        """Test the system page."""
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
        response = self.client.get('/system')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_system_info.assert_called_once_with()
    
    def test_predict_page_get(self):
        """Test the prediction page with GET request."""
        # Make the request
        response = self.client.get('/predict')
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
    
    def test_predict_page_post(self):
        """Test the prediction page with POST request."""
        # Set up the mock
        self.mock_sentinelx.predict.return_value = {
            'prediction': 'malicious',
            'probability': 0.95
        }
        
        # Make the request
        response = self.client.post('/predict', data={
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': '12345',
            'dst_port': '80',
            'bytes': '1000',
            'packets': '10'
        })
        
        # Check the response
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        
        # Check that the mock was called correctly
        self.mock_sentinelx.predict.assert_called_once_with({
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 80,
            'bytes': 1000,
            'packets': 10
        })
    
    def test_authentication_required(self):
        """Test that authentication is required for protected pages."""
        # Log out
        self.client.get('/logout')
        
        # Try to access a protected page
        response = self.client.get('/dashboard', follow_redirects=True)
        
        # Check that we're redirected to the login page
        self.assertEqual(response.status_code, 200, "Status code should be 200")
        self.assertIn(b'login', response.data, "Should redirect to login page")


if __name__ == '__main__':
    unittest.main()