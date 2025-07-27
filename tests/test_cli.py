#!/usr/bin/env python
# SentinelX CLI Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import io

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scripts.sentinelx_cli import (
    SentinelXCLI, train_command, evaluate_command, monitor_command, 
    interfaces_command, stats_command, alerts_command, alert_details_command,
    alert_update_command, alert_analyze_command, alert_report_command,
    enrich_ip_command, enrich_domain_command
)


class TestSentinelXCLI(unittest.TestCase):
    """Test the SentinelX CLI."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for configuration and data
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, 'config.yaml')
        
        # Create a basic configuration file
        with open(self.config_path, 'w') as f:
            f.write('''
            data:
              dataset_path: data/nsl-kdd
              train_file: KDDTrain+.txt
              test_file: KDDTest+.txt
            model:
              type: random_forest
              params:
                n_estimators: 100
                max_depth: 10
              save_path: models/random_forest_model.joblib
            network:
              interface: eth0
              flow_timeout: 120
              max_flows: 10000
            threat_intel:
              abuseipdb:
                api_key: test_key
              otx:
                api_key: test_key
              virustotal:
                api_key: test_key
              cache_duration: 86400
            alert_management:
              storage_type: json
              json_path: data/alerts.json
            reasoning:
              llm_provider: openai
              openai_api_key: test_key
              mitre_data_path: data/mitre
              cve_data_path: data/cve
            logging:
              level: INFO
              file: logs/sentinelx.log
            api:
              host: 0.0.0.0
              port: 8000
              api_key: test_api_key
            ''')
        
        # Mock the SentinelX class
        self.sentinelx_patcher = patch('scripts.sentinelx_cli.SentinelX')
        self.mock_sentinelx_class = self.sentinelx_patcher.start()
        self.mock_sentinelx = MagicMock()
        self.mock_sentinelx_class.return_value = self.mock_sentinelx
        
        # Create the CLI instance
        self.cli = SentinelXCLI(config_path=self.config_path)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Stop the patchers
        self.sentinelx_patcher.stop()
        
        # Remove the temporary directory
        self.temp_dir.cleanup()
    
    def test_initialization(self):
        """Test the initialization of the CLI."""
        # Check that the SentinelX instance was created correctly
        self.mock_sentinelx_class.assert_called_once_with(config_path=self.config_path)
        
        # Check that the CLI instance has the correct attributes
        self.assertEqual(self.cli.sentinelx, self.mock_sentinelx)
    
    def test_train_command(self):
        """Test the train command."""
        # Set up the mocks
        self.mock_sentinelx.train_model.return_value = True
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.model_type = 'random_forest'
            args.config = self.config_path
            train_command(args)
            
            # Check that the output is correct
            self.assertIn('Training model: random_forest', mock_stdout.getvalue())
            self.assertIn('Model training completed successfully', mock_stdout.getvalue())
            
            # Check that the SentinelX.train_model method was called correctly
            self.mock_sentinelx.train_model.assert_called_once_with('random_forest')
    
    def test_evaluate_command(self):
        """Test the evaluate command."""
        # Set up the mocks
        self.mock_sentinelx.evaluate_model.return_value = {
            'accuracy': 0.95,
            'precision': 0.9,
            'recall': 0.85,
            'f1_score': 0.87
        }
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.model_type = 'random_forest'
            args.config = self.config_path
            evaluate_command(args)
            
            # Check that the output is correct
            self.assertIn('Evaluating model: random_forest', mock_stdout.getvalue())
            self.assertIn('Accuracy: 0.95', mock_stdout.getvalue())
            self.assertIn('Precision: 0.9', mock_stdout.getvalue())
            self.assertIn('Recall: 0.85', mock_stdout.getvalue())
            self.assertIn('F1 Score: 0.87', mock_stdout.getvalue())
            
            # Check that the SentinelX.evaluate_model method was called correctly
            self.mock_sentinelx.evaluate_model.assert_called_once_with('random_forest')
    
    def test_monitor_command_start(self):
        """Test the monitor command with start action."""
        # Set up the mocks
        self.mock_sentinelx.start_network_monitoring.return_value = True
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.action = 'start'
            args.interface = 'eth0'
            args.config = self.config_path
            monitor_command(args)
            
            # Check that the output is correct
            self.assertIn('Starting network monitoring on interface: eth0', mock_stdout.getvalue())
            self.assertIn('Network monitoring started successfully', mock_stdout.getvalue())
            
            # Check that the SentinelX.start_network_monitoring method was called correctly
            self.mock_sentinelx.start_network_monitoring.assert_called_once_with('eth0')
    
    def test_monitor_command_stop(self):
        """Test the monitor command with stop action."""
        # Set up the mocks
        self.mock_sentinelx.stop_network_monitoring.return_value = True
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.action = 'stop'
            args.config = self.config_path
            monitor_command(args)
            
            # Check that the output is correct
            self.assertIn('Stopping network monitoring', mock_stdout.getvalue())
            self.assertIn('Network monitoring stopped successfully', mock_stdout.getvalue())
            
            # Check that the SentinelX.stop_network_monitoring method was called correctly
            self.mock_sentinelx.stop_network_monitoring.assert_called_once()
    
    def test_interfaces_command(self):
        """Test the interfaces command."""
        # Set up the mocks
        self.mock_sentinelx.get_available_interfaces.return_value = ['eth0', 'lo']
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.config = self.config_path
            interfaces_command(args)
            
            # Check that the output is correct
            self.assertIn('Available network interfaces:', mock_stdout.getvalue())
            self.assertIn('eth0', mock_stdout.getvalue())
            self.assertIn('lo', mock_stdout.getvalue())
            
            # Check that the SentinelX.get_available_interfaces method was called correctly
            self.mock_sentinelx.get_available_interfaces.assert_called_once()
    
    def test_stats_command(self):
        """Test the stats command."""
        # Set up the mocks
        self.mock_sentinelx.get_packet_stats.return_value = {
            'total_packets': 100,
            'total_bytes': 10000,
            'protocol_stats': {'TCP': 80, 'UDP': 20},
            'port_stats': {80: 50, 443: 30}
        }
        
        self.mock_sentinelx.get_flow_stats.return_value = {
            'active_flows': 10,
            'total_flows': 20,
            'expired_flows': 10
        }
        
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
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.config = self.config_path
            stats_command(args)
            
            # Check that the output is correct
            self.assertIn('Network Statistics:', mock_stdout.getvalue())
            self.assertIn('Packet Statistics:', mock_stdout.getvalue())
            self.assertIn('Total Packets: 100', mock_stdout.getvalue())
            self.assertIn('Total Bytes: 10000', mock_stdout.getvalue())
            self.assertIn('Flow Statistics:', mock_stdout.getvalue())
            self.assertIn('Active Flows: 10', mock_stdout.getvalue())
            self.assertIn('Total Flows: 20', mock_stdout.getvalue())
            self.assertIn('Expired Flows: 10', mock_stdout.getvalue())
            self.assertIn('Top Talkers:', mock_stdout.getvalue())
            self.assertIn('192.168.1.1', mock_stdout.getvalue())
            self.assertIn('192.168.1.3', mock_stdout.getvalue())
            
            # Check that the SentinelX methods were called correctly
            self.mock_sentinelx.get_packet_stats.assert_called_once()
            self.mock_sentinelx.get_flow_stats.assert_called_once()
            self.mock_sentinelx.get_top_talkers.assert_called_once_with(10)
    
    def test_alerts_command(self):
        """Test the alerts command."""
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
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.config = self.config_path
            alerts_command(args)
            
            # Check that the output is correct
            self.assertIn('Alerts:', mock_stdout.getvalue())
            self.assertIn('12345', mock_stdout.getvalue())
            self.assertIn('port_scan', mock_stdout.getvalue())
            self.assertIn('192.168.1.1', mock_stdout.getvalue())
            self.assertIn('high', mock_stdout.getvalue())
            self.assertIn('new', mock_stdout.getvalue())
            self.assertIn('67890', mock_stdout.getvalue())
            self.assertIn('brute_force', mock_stdout.getvalue())
            self.assertIn('192.168.1.3', mock_stdout.getvalue())
            self.assertIn('medium', mock_stdout.getvalue())
            self.assertIn('acknowledged', mock_stdout.getvalue())
            
            # Check that the SentinelX.get_alerts method was called correctly
            self.mock_sentinelx.get_alerts.assert_called_once()
    
    def test_alert_details_command(self):
        """Test the alert details command."""
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
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.alert_id = '12345'
            args.config = self.config_path
            alert_details_command(args)
            
            # Check that the output is correct
            self.assertIn('Alert Details:', mock_stdout.getvalue())
            self.assertIn('ID: 12345', mock_stdout.getvalue())
            self.assertIn('Type: port_scan', mock_stdout.getvalue())
            self.assertIn('Source IP: 192.168.1.1', mock_stdout.getvalue())
            self.assertIn('Destination IP: 192.168.1.2', mock_stdout.getvalue())
            self.assertIn('Severity: high', mock_stdout.getvalue())
            self.assertIn('Status: new', mock_stdout.getvalue())
            self.assertIn('Raw Data:', mock_stdout.getvalue())
            self.assertIn('port_count: 20', mock_stdout.getvalue())
            
            # Check that the SentinelX.get_alert method was called correctly
            self.mock_sentinelx.get_alert.assert_called_once_with('12345')
    
    def test_alert_update_command(self):
        """Test the alert update command."""
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
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.alert_id = '12345'
            args.status = 'acknowledged'
            args.config = self.config_path
            alert_update_command(args)
            
            # Check that the output is correct
            self.assertIn('Updating alert 12345 status to acknowledged', mock_stdout.getvalue())
            self.assertIn('Alert updated successfully', mock_stdout.getvalue())
            
            # Check that the SentinelX.update_alert_status method was called correctly
            self.mock_sentinelx.update_alert_status.assert_called_once_with('12345', 'acknowledged')
    
    def test_alert_analyze_command(self):
        """Test the alert analyze command."""
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
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.alert_id = '12345'
            args.config = self.config_path
            alert_analyze_command(args)
            
            # Check that the output is correct
            self.assertIn('Analyzing alert 12345', mock_stdout.getvalue())
            self.assertIn('Analysis:', mock_stdout.getvalue())
            self.assertIn('Explanation: This is a port scan attack', mock_stdout.getvalue())
            self.assertIn('MITRE ATT&CK Techniques:', mock_stdout.getvalue())
            self.assertIn('T1046 - Network Service Scanning', mock_stdout.getvalue())
            self.assertIn('Remediation: Block the source IP address', mock_stdout.getvalue())
            
            # Check that the SentinelX.analyze_alert method was called correctly
            self.mock_sentinelx.analyze_alert.assert_called_once_with('12345')
    
    def test_alert_report_command(self):
        """Test the alert report command."""
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
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.alert_id = '12345'
            args.format = 'json'
            args.output = None
            args.config = self.config_path
            alert_report_command(args)
            
            # Check that the output is correct
            self.assertIn('Generating report for alert 12345', mock_stdout.getvalue())
            self.assertIn('"alert_id": "12345"', mock_stdout.getvalue())
            self.assertIn('"alert_type": "port_scan"', mock_stdout.getvalue())
            self.assertIn('"explanation": "This is a port scan attack"', mock_stdout.getvalue())
            
            # Check that the SentinelX.generate_alert_report method was called correctly
            self.mock_sentinelx.generate_alert_report.assert_called_once_with('12345')
    
    def test_enrich_ip_command(self):
        """Test the enrich IP command."""
        # Set up the mocks
        self.mock_sentinelx.enrich_ip.return_value = {
            'ip': '192.168.1.1',
            'reputation': 'malicious',
            'country': 'US',
            'asn': 12345,
            'threat_types': ['scanner']
        }
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.ip = '192.168.1.1'
            args.config = self.config_path
            enrich_ip_command(args)
            
            # Check that the output is correct
            self.assertIn('Enriching IP: 192.168.1.1', mock_stdout.getvalue())
            self.assertIn('IP: 192.168.1.1', mock_stdout.getvalue())
            self.assertIn('Reputation: malicious', mock_stdout.getvalue())
            self.assertIn('Country: US', mock_stdout.getvalue())
            self.assertIn('ASN: 12345', mock_stdout.getvalue())
            self.assertIn('Threat Types: ["scanner"]', mock_stdout.getvalue())
            
            # Check that the SentinelX.enrich_ip method was called correctly
            self.mock_sentinelx.enrich_ip.assert_called_once_with('192.168.1.1')
    
    def test_enrich_domain_command(self):
        """Test the enrich domain command."""
        # Set up the mocks
        self.mock_sentinelx.enrich_domain.return_value = {
            'domain': 'example.com',
            'reputation': 'malicious',
            'categories': ['malware', 'phishing']
        }
        
        # Create a mock for sys.stdout
        with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
            # Call the command
            args = MagicMock()
            args.domain = 'example.com'
            args.config = self.config_path
            enrich_domain_command(args)
            
            # Check that the output is correct
            self.assertIn('Enriching Domain: example.com', mock_stdout.getvalue())
            self.assertIn('Domain: example.com', mock_stdout.getvalue())
            self.assertIn('Reputation: malicious', mock_stdout.getvalue())
            self.assertIn('Categories: ["malware", "phishing"]', mock_stdout.getvalue())
            
            # Check that the SentinelX.enrich_domain method was called correctly
            self.mock_sentinelx.enrich_domain.assert_called_once_with('example.com')


if __name__ == '__main__':
    unittest.main()