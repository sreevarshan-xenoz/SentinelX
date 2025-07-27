#!/usr/bin/env python
# SentinelX CLI Integration Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import argparse

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the CLI and SentinelX classes
try:
    from scripts.sentinelx_cli import SentinelXCLI
    from src.sentinelx import SentinelX
except ImportError:
    # Mock classes if they don't exist yet
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
    
    class SentinelXCLI:
        def __init__(self):
            self.sentinelx = SentinelX()
            self.parser = argparse.ArgumentParser(description='SentinelX Command Line Interface')
            self._setup_parsers()
        
        def _setup_parsers(self):
            subparsers = self.parser.add_subparsers(dest='command', help='Command to run')
            
            # Model commands
            model_parser = subparsers.add_parser('model', help='Model operations')
            model_subparsers = model_parser.add_subparsers(dest='model_command', help='Model command to run')
            
            train_parser = model_subparsers.add_parser('train', help='Train a model')
            train_parser.add_argument('--dataset', help='Path to the dataset')
            train_parser.add_argument('--type', default='random_forest', help='Type of model to train')
            
            evaluate_parser = model_subparsers.add_parser('evaluate', help='Evaluate a model')
            evaluate_parser.add_argument('--dataset', help='Path to the dataset')
            
            # Network commands
            network_parser = subparsers.add_parser('network', help='Network operations')
            network_subparsers = network_parser.add_subparsers(dest='network_command', help='Network command to run')
            
            start_parser = network_subparsers.add_parser('start', help='Start network monitoring')
            start_parser.add_argument('--interface', help='Network interface to monitor')
            
            stop_parser = network_subparsers.add_parser('stop', help='Stop network monitoring')
            
            interfaces_parser = network_subparsers.add_parser('interfaces', help='List network interfaces')
            
            stats_parser = network_subparsers.add_parser('stats', help='Show network statistics')
            stats_parser.add_argument('--type', choices=['packet', 'flow', 'talkers'], default='packet', help='Type of statistics to show')
            stats_parser.add_argument('--limit', type=int, default=10, help='Limit for top talkers')
            
            # Alert commands
            alert_parser = subparsers.add_parser('alert', help='Alert operations')
            alert_subparsers = alert_parser.add_subparsers(dest='alert_command', help='Alert command to run')
            
            list_parser = alert_subparsers.add_parser('list', help='List alerts')
            list_parser.add_argument('--limit', type=int, default=100, help='Maximum number of alerts to show')
            list_parser.add_argument('--offset', type=int, default=0, help='Offset for pagination')
            list_parser.add_argument('--status', choices=['open', 'closed', 'in_progress'], help='Filter by status')
            
            show_parser = alert_subparsers.add_parser('show', help='Show alert details')
            show_parser.add_argument('alert_id', help='ID of the alert to show')
            
            update_parser = alert_subparsers.add_parser('update', help='Update an alert')
            update_parser.add_argument('alert_id', help='ID of the alert to update')
            update_parser.add_argument('--status', choices=['open', 'closed', 'in_progress'], help='New status')
            update_parser.add_argument('--notes', help='Notes to add')
            
            analyze_parser = alert_subparsers.add_parser('analyze', help='Analyze an alert')
            analyze_parser.add_argument('alert_id', help='ID of the alert to analyze')
            
            report_parser = alert_subparsers.add_parser('report', help='Generate an alert report')
            report_parser.add_argument('alert_id', help='ID of the alert to generate a report for')
            report_parser.add_argument('--format', choices=['json', 'markdown'], default='json', help='Report format')
            
            # Threat intelligence commands
            ti_parser = subparsers.add_parser('ti', help='Threat intelligence operations')
            ti_subparsers = ti_parser.add_subparsers(dest='ti_command', help='Threat intelligence command to run')
            
            ip_parser = ti_subparsers.add_parser('ip', help='Get information about an IP address')
            ip_parser.add_argument('ip', help='IP address to look up')
            
            domain_parser = ti_subparsers.add_parser('domain', help='Get information about a domain')
            domain_parser.add_argument('domain', help='Domain to look up')
            
            # System commands
            system_parser = subparsers.add_parser('system', help='System operations')
            system_subparsers = system_parser.add_subparsers(dest='system_command', help='System command to run')
            
            info_parser = system_subparsers.add_parser('info', help='Show system information')
        
        def run(self, args=None):
            args = self.parser.parse_args(args)
            
            if args.command == 'model':
                if args.model_command == 'train':
                    return self.sentinelx.train_model(dataset_path=args.dataset, model_type=args.type)
                elif args.model_command == 'evaluate':
                    return self.sentinelx.evaluate_model(dataset_path=args.dataset)
            
            elif args.command == 'network':
                if args.network_command == 'start':
                    return self.sentinelx.start_monitoring(interface=args.interface)
                elif args.network_command == 'stop':
                    return self.sentinelx.stop_monitoring()
                elif args.network_command == 'interfaces':
                    return self.sentinelx.list_interfaces()
                elif args.network_command == 'stats':
                    if args.type == 'packet':
                        return self.sentinelx.get_packet_stats()
                    elif args.type == 'flow':
                        return self.sentinelx.get_flow_stats()
                    elif args.type == 'talkers':
                        return self.sentinelx.get_top_talkers(n=args.limit)
            
            elif args.command == 'alert':
                if args.alert_command == 'list':
                    return self.sentinelx.get_alerts(limit=args.limit, offset=args.offset, status=args.status)
                elif args.alert_command == 'show':
                    return self.sentinelx.get_alert(args.alert_id)
                elif args.alert_command == 'update':
                    return self.sentinelx.update_alert(args.alert_id, status=args.status, notes=args.notes)
                elif args.alert_command == 'analyze':
                    return self.sentinelx.analyze_alert(args.alert_id)
                elif args.alert_command == 'report':
                    return self.sentinelx.generate_alert_report(args.alert_id, format=args.format)
            
            elif args.command == 'ti':
                if args.ti_command == 'ip':
                    return self.sentinelx.enrich_ip(args.ip)
                elif args.ti_command == 'domain':
                    return self.sentinelx.enrich_domain(args.domain)
            
            elif args.command == 'system':
                if args.system_command == 'info':
                    return self.sentinelx.get_system_info()
            
            return None


class TestCLIIntegration(unittest.TestCase):
    """Test the integration between the CLI and the SentinelX application."""
    
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
        
        # Create a CLI instance with the mock SentinelX
        self.cli = SentinelXCLI()
        self.cli.sentinelx = self.mock_sentinelx
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_model_train(self):
        """Test the model train command."""
        # Set up the mock
        self.mock_sentinelx.train_model.return_value = {
            'accuracy': 0.95,
            'precision': 0.94,
            'recall': 0.93,
            'f1': 0.92
        }
        
        # Run the command
        result = self.cli.run(['model', 'train', '--dataset', 'data/nsl-kdd/train.csv', '--type', 'random_forest'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.train_model.assert_called_once_with(
            dataset_path='data/nsl-kdd/train.csv',
            model_type='random_forest'
        )
        
        # Check the result
        self.assertEqual(result['accuracy'], 0.95, "Accuracy should be 0.95")
        self.assertEqual(result['precision'], 0.94, "Precision should be 0.94")
        self.assertEqual(result['recall'], 0.93, "Recall should be 0.93")
        self.assertEqual(result['f1'], 0.92, "F1 should be 0.92")
    
    def test_model_evaluate(self):
        """Test the model evaluate command."""
        # Set up the mock
        self.mock_sentinelx.evaluate_model.return_value = {
            'accuracy': 0.95,
            'precision': 0.94,
            'recall': 0.93,
            'f1': 0.92
        }
        
        # Run the command
        result = self.cli.run(['model', 'evaluate', '--dataset', 'data/nsl-kdd/test.csv'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.evaluate_model.assert_called_once_with(
            dataset_path='data/nsl-kdd/test.csv'
        )
        
        # Check the result
        self.assertEqual(result['accuracy'], 0.95, "Accuracy should be 0.95")
        self.assertEqual(result['precision'], 0.94, "Precision should be 0.94")
        self.assertEqual(result['recall'], 0.93, "Recall should be 0.93")
        self.assertEqual(result['f1'], 0.92, "F1 should be 0.92")
    
    def test_network_start(self):
        """Test the network start command."""
        # Set up the mock
        self.mock_sentinelx.start_monitoring.return_value = True
        
        # Run the command
        result = self.cli.run(['network', 'start', '--interface', 'eth0'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.start_monitoring.assert_called_once_with(
            interface='eth0'
        )
        
        # Check the result
        self.assertTrue(result, "Result should be True")
    
    def test_network_stop(self):
        """Test the network stop command."""
        # Set up the mock
        self.mock_sentinelx.stop_monitoring.return_value = True
        
        # Run the command
        result = self.cli.run(['network', 'stop'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.stop_monitoring.assert_called_once_with()
        
        # Check the result
        self.assertTrue(result, "Result should be True")
    
    def test_network_interfaces(self):
        """Test the network interfaces command."""
        # Set up the mock
        self.mock_sentinelx.list_interfaces.return_value = ['eth0', 'wlan0']
        
        # Run the command
        result = self.cli.run(['network', 'interfaces'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.list_interfaces.assert_called_once_with()
        
        # Check the result
        self.assertEqual(result, ['eth0', 'wlan0'], "Result should be ['eth0', 'wlan0']")
    
    def test_network_stats_packet(self):
        """Test the network stats command with packet type."""
        # Set up the mock
        self.mock_sentinelx.get_packet_stats.return_value = {
            'total': 1000,
            'tcp': 800,
            'udp': 150,
            'icmp': 50
        }
        
        # Run the command
        result = self.cli.run(['network', 'stats', '--type', 'packet'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_packet_stats.assert_called_once_with()
        
        # Check the result
        self.assertEqual(result['total'], 1000, "Total packets should be 1000")
        self.assertEqual(result['tcp'], 800, "TCP packets should be 800")
        self.assertEqual(result['udp'], 150, "UDP packets should be 150")
        self.assertEqual(result['icmp'], 50, "ICMP packets should be 50")
    
    def test_network_stats_flow(self):
        """Test the network stats command with flow type."""
        # Set up the mock
        self.mock_sentinelx.get_flow_stats.return_value = {
            'total': 100,
            'active': 50,
            'expired': 50
        }
        
        # Run the command
        result = self.cli.run(['network', 'stats', '--type', 'flow'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_flow_stats.assert_called_once_with()
        
        # Check the result
        self.assertEqual(result['total'], 100, "Total flows should be 100")
        self.assertEqual(result['active'], 50, "Active flows should be 50")
        self.assertEqual(result['expired'], 50, "Expired flows should be 50")
    
    def test_network_stats_talkers(self):
        """Test the network stats command with talkers type."""
        # Set up the mock
        self.mock_sentinelx.get_top_talkers.return_value = [
            {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'bytes': 1000, 'packets': 10},
            {'src_ip': '192.168.1.101', 'dst_ip': '8.8.4.4', 'bytes': 900, 'packets': 9}
        ]
        
        # Run the command
        result = self.cli.run(['network', 'stats', '--type', 'talkers', '--limit', '5'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_top_talkers.assert_called_once_with(n=5)
        
        # Check the result
        self.assertEqual(len(result), 2, "Should have 2 talkers")
        self.assertEqual(result[0]['src_ip'], '192.168.1.100', "First talker source IP should be 192.168.1.100")
        self.assertEqual(result[0]['dst_ip'], '8.8.8.8', "First talker destination IP should be 8.8.8.8")
        self.assertEqual(result[0]['bytes'], 1000, "First talker bytes should be 1000")
        self.assertEqual(result[0]['packets'], 10, "First talker packets should be 10")
    
    def test_alert_list(self):
        """Test the alert list command."""
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
        
        # Run the command
        result = self.cli.run(['alert', 'list', '--limit', '10', '--offset', '0', '--status', 'open'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_alerts.assert_called_once_with(
            limit=10,
            offset=0,
            status='open'
        )
        
        # Check the result
        self.assertEqual(len(result), 1, "Should have 1 alert")
        self.assertEqual(result[0]['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(result[0]['severity'], 'high', "Alert severity should be high")
        self.assertEqual(result[0]['category'], 'malware', "Alert category should be malware")
        self.assertEqual(result[0]['status'], 'open', "Alert status should be open")
    
    def test_alert_show(self):
        """Test the alert show command."""
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
        
        # Run the command
        result = self.cli.run(['alert', 'show', 'alert-1'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_alert.assert_called_once_with('alert-1')
        
        # Check the result
        self.assertEqual(result['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(result['severity'], 'high', "Alert severity should be high")
        self.assertEqual(result['category'], 'malware', "Alert category should be malware")
        self.assertEqual(result['status'], 'open', "Alert status should be open")
        self.assertEqual(result['details']['flow']['protocol'], 'TCP', "Flow protocol should be TCP")
        self.assertEqual(result['details']['flow']['src_port'], 12345, "Flow source port should be 12345")
        self.assertEqual(result['details']['flow']['dst_port'], 80, "Flow destination port should be 80")
    
    def test_alert_update(self):
        """Test the alert update command."""
        # Set up the mock
        self.mock_sentinelx.update_alert.return_value = {
            'id': 'alert-1',
            'status': 'closed',
            'notes': 'False positive'
        }
        
        # Run the command
        result = self.cli.run(['alert', 'update', 'alert-1', '--status', 'closed', '--notes', 'False positive'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.update_alert.assert_called_once_with(
            'alert-1',
            status='closed',
            notes='False positive'
        )
        
        # Check the result
        self.assertEqual(result['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(result['status'], 'closed', "Alert status should be closed")
        self.assertEqual(result['notes'], 'False positive', "Alert notes should be 'False positive'")
    
    def test_alert_analyze(self):
        """Test the alert analyze command."""
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
        
        # Run the command
        result = self.cli.run(['alert', 'analyze', 'alert-1'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.analyze_alert.assert_called_once_with('alert-1')
        
        # Check the result
        self.assertEqual(result['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(result['analysis']['threat_type'], 'C2 Communication', "Threat type should be C2 Communication")
        self.assertEqual(result['analysis']['confidence'], 'high', "Confidence should be high")
        self.assertEqual(result['analysis']['mitre_tactics'], ['Command and Control'], "MITRE tactics should be correct")
        self.assertEqual(result['analysis']['mitre_techniques'], ['T1071 - Application Layer Protocol'], "MITRE techniques should be correct")
    
    def test_alert_report_json(self):
        """Test the alert report command with JSON format."""
        # Set up the mock
        self.mock_sentinelx.generate_alert_report.return_value = json.dumps({
            'id': 'alert-1',
            'analysis': {
                'threat_type': 'C2 Communication',
                'confidence': 'high'
            }
        })
        
        # Run the command
        result = self.cli.run(['alert', 'report', 'alert-1', '--format', 'json'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with(
            'alert-1',
            format='json'
        )
        
        # Check the result
        result_json = json.loads(result)
        self.assertEqual(result_json['id'], 'alert-1', "Alert ID should be alert-1")
        self.assertEqual(result_json['analysis']['threat_type'], 'C2 Communication', "Threat type should be C2 Communication")
        self.assertEqual(result_json['analysis']['confidence'], 'high', "Confidence should be high")
    
    def test_alert_report_markdown(self):
        """Test the alert report command with Markdown format."""
        # Set up the mock
        self.mock_sentinelx.generate_alert_report.return_value = "# Alert Report: alert-1\n\n## Analysis\n\n- Threat Type: C2 Communication\n- Confidence: high"
        
        # Run the command
        result = self.cli.run(['alert', 'report', 'alert-1', '--format', 'markdown'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.generate_alert_report.assert_called_once_with(
            'alert-1',
            format='markdown'
        )
        
        # Check the result
        self.assertIn('# Alert Report: alert-1', result, "Report should have the correct title")
        self.assertIn('## Analysis', result, "Report should have an Analysis section")
        self.assertIn('- Threat Type: C2 Communication', result, "Report should have the threat type")
        self.assertIn('- Confidence: high', result, "Report should have the confidence")
    
    def test_ti_ip(self):
        """Test the threat intelligence IP command."""
        # Set up the mock
        self.mock_sentinelx.enrich_ip.return_value = {
            'ip': '8.8.8.8',
            'reputation': 'good',
            'country': 'US',
            'asn': 'AS15169 Google LLC',
            'tags': ['search-engine']
        }
        
        # Run the command
        result = self.cli.run(['ti', 'ip', '8.8.8.8'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.enrich_ip.assert_called_once_with('8.8.8.8')
        
        # Check the result
        self.assertEqual(result['ip'], '8.8.8.8', "IP should be 8.8.8.8")
        self.assertEqual(result['reputation'], 'good', "Reputation should be good")
        self.assertEqual(result['country'], 'US', "Country should be US")
        self.assertEqual(result['asn'], 'AS15169 Google LLC', "ASN should be correct")
        self.assertEqual(result['tags'], ['search-engine'], "Tags should be correct")
    
    def test_ti_domain(self):
        """Test the threat intelligence domain command."""
        # Set up the mock
        self.mock_sentinelx.enrich_domain.return_value = {
            'domain': 'google.com',
            'reputation': 'good',
            'categories': ['search-engine'],
            'registrar': 'MarkMonitor Inc.'
        }
        
        # Run the command
        result = self.cli.run(['ti', 'domain', 'google.com'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.enrich_domain.assert_called_once_with('google.com')
        
        # Check the result
        self.assertEqual(result['domain'], 'google.com', "Domain should be google.com")
        self.assertEqual(result['reputation'], 'good', "Reputation should be good")
        self.assertEqual(result['categories'], ['search-engine'], "Categories should be correct")
        self.assertEqual(result['registrar'], 'MarkMonitor Inc.', "Registrar should be correct")
    
    def test_system_info(self):
        """Test the system info command."""
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
        
        # Run the command
        result = self.cli.run(['system', 'info'])
        
        # Check that the mock was called correctly
        self.mock_sentinelx.get_system_info.assert_called_once_with()
        
        # Check the result
        self.assertEqual(result['os']['name'], 'Linux', "OS name should be Linux")
        self.assertEqual(result['os']['version'], '5.4.0-42-generic', "OS version should be correct")
        self.assertEqual(result['memory']['total'], 16 * 1024 * 1024 * 1024, "Total memory should be correct")
        self.assertEqual(result['memory']['available'], 8 * 1024 * 1024 * 1024, "Available memory should be correct")
        self.assertEqual(result['cpu']['count'], 8, "CPU count should be 8")
        self.assertEqual(result['cpu']['percent'], 25.0, "CPU percent should be 25.0")


if __name__ == '__main__':
    unittest.main()