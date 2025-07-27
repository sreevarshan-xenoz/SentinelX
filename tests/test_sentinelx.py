#!/usr/bin/env python
# SentinelX Core Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.sentinelx import SentinelX
from src.core.config_manager import ConfigManager
from src.core.logging_manager import LoggingManager
from src.data.dataset_loader import DatasetLoader
from src.data.preprocessing import PreprocessingPipeline
from src.model.model_factory import ModelFactory
from src.network.packet_capture import PacketCapture
from src.network.flow_analyzer import FlowAnalyzer
from src.threat_intel.threat_intelligence import ThreatIntelligence
from src.alert_management.alert_manager import AlertManager
from src.reasoning.threat_reasoning import ThreatReasoning
from src.reasoning.report_generator import ReportGenerator
from src.reasoning.llm_integration import LLMIntegration
from src.reasoning.mitre_context import MITREContext
from src.reasoning.cve_context import CVEContext


class TestSentinelX(unittest.TestCase):
    """Test the SentinelX class."""
    
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
        
        # Mock the ConfigManager
        self.config_manager_patcher = patch('src.core.config_manager.ConfigManager')
        self.mock_config_manager = self.config_manager_patcher.start()
        self.mock_config_manager.get_instance.return_value.get.return_value = {}
        
        # Mock the LoggingManager
        self.logging_manager_patcher = patch('src.core.logging_manager.LoggingManager')
        self.mock_logging_manager = self.logging_manager_patcher.start()
        
        # Create the SentinelX instance
        self.sentinelx = SentinelX(config_path=self.config_path)
        
        # Mock the components
        self.sentinelx.dataset_loader = MagicMock(spec=DatasetLoader)
        self.sentinelx.preprocessing_pipeline = MagicMock(spec=PreprocessingPipeline)
        self.sentinelx.model_factory = MagicMock(spec=ModelFactory)
        self.sentinelx.packet_capture = MagicMock(spec=PacketCapture)
        self.sentinelx.flow_analyzer = MagicMock(spec=FlowAnalyzer)
        self.sentinelx.threat_intelligence = MagicMock(spec=ThreatIntelligence)
        self.sentinelx.alert_manager = MagicMock(spec=AlertManager)
        self.sentinelx.threat_reasoning = MagicMock(spec=ThreatReasoning)
        self.sentinelx.report_generator = MagicMock(spec=ReportGenerator)
        self.sentinelx.llm_integration = MagicMock(spec=LLMIntegration)
        self.sentinelx.mitre_context = MagicMock(spec=MITREContext)
        self.sentinelx.cve_context = MagicMock(spec=CVEContext)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Stop the patchers
        self.config_manager_patcher.stop()
        self.logging_manager_patcher.stop()
        
        # Remove the temporary directory
        self.temp_dir.cleanup()
    
    def test_initialization(self):
        """Test the initialization of the SentinelX class."""
        # Create a new SentinelX instance with mocked components
        with patch('src.sentinelx.DatasetLoader') as mock_dataset_loader, \
             patch('src.sentinelx.PreprocessingPipeline') as mock_preprocessing_pipeline, \
             patch('src.sentinelx.ModelFactory') as mock_model_factory, \
             patch('src.sentinelx.PacketCapture') as mock_packet_capture, \
             patch('src.sentinelx.FlowAnalyzer') as mock_flow_analyzer, \
             patch('src.sentinelx.ThreatIntelligence') as mock_threat_intelligence, \
             patch('src.sentinelx.AlertManager') as mock_alert_manager, \
             patch('src.sentinelx.ThreatReasoning') as mock_threat_reasoning, \
             patch('src.sentinelx.ReportGenerator') as mock_report_generator, \
             patch('src.sentinelx.LLMIntegration') as mock_llm_integration, \
             patch('src.sentinelx.MITREContext') as mock_mitre_context, \
             patch('src.sentinelx.CVEContext') as mock_cve_context:
            
            # Create a new SentinelX instance
            sentinelx = SentinelX(config_path=self.config_path)
            
            # Check that the components were initialized correctly
            self.assertIsNotNone(sentinelx.config_manager)
            self.assertIsNotNone(sentinelx.logger)
            
            # Check that the setup methods were called
            mock_dataset_loader.assert_called_once()
            mock_preprocessing_pipeline.assert_called_once()
            mock_model_factory.assert_called_once()
            mock_packet_capture.assert_called_once()
            mock_flow_analyzer.assert_called_once()
            mock_threat_intelligence.assert_called_once()
            mock_alert_manager.assert_called_once()
            mock_threat_reasoning.assert_called_once()
            mock_report_generator.assert_called_once()
            mock_llm_integration.assert_called_once()
            mock_mitre_context.assert_called_once()
            mock_cve_context.assert_called_once()
    
    def test_train_model(self):
        """Test the train_model method."""
        # Set up the mocks
        self.sentinelx.dataset_loader.load_train_data.return_value = ({'X': [[1, 2, 3]], 'y': [0]}, {})
        self.sentinelx.preprocessing_pipeline.fit_transform.return_value = ([[1, 2, 3]], [0])
        self.sentinelx.model_factory.get_model.return_value.train.return_value = None
        
        # Call the method
        result = self.sentinelx.train_model('random_forest')
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the methods were called correctly
        self.sentinelx.dataset_loader.load_train_data.assert_called_once()
        self.sentinelx.preprocessing_pipeline.fit_transform.assert_called_once_with([[1, 2, 3]], [0])
        self.sentinelx.model_factory.get_model.assert_called_once_with('random_forest')
        self.sentinelx.model_factory.get_model.return_value.train.assert_called_once_with([[1, 2, 3]], [0])
    
    def test_evaluate_model(self):
        """Test the evaluate_model method."""
        # Set up the mocks
        self.sentinelx.dataset_loader.load_test_data.return_value = ({'X': [[1, 2, 3]], 'y': [0]}, {})
        self.sentinelx.preprocessing_pipeline.transform.return_value = ([[1, 2, 3]], [0])
        self.sentinelx.model_factory.get_model.return_value.evaluate.return_value = {
            'accuracy': 0.95,
            'precision': 0.9,
            'recall': 0.85,
            'f1_score': 0.87
        }
        
        # Call the method
        result = self.sentinelx.evaluate_model('random_forest')
        
        # Check that the result is correct
        self.assertEqual(result['accuracy'], 0.95)
        self.assertEqual(result['precision'], 0.9)
        self.assertEqual(result['recall'], 0.85)
        self.assertEqual(result['f1_score'], 0.87)
        
        # Check that the methods were called correctly
        self.sentinelx.dataset_loader.load_test_data.assert_called_once()
        self.sentinelx.preprocessing_pipeline.transform.assert_called_once_with([[1, 2, 3]], [0])
        self.sentinelx.model_factory.get_model.assert_called_once_with('random_forest')
        self.sentinelx.model_factory.get_model.return_value.evaluate.assert_called_once_with([[1, 2, 3]], [0])
    
    def test_predict(self):
        """Test the predict method."""
        # Set up the mocks
        self.sentinelx.preprocessing_pipeline.transform_single.return_value = [1, 2, 3]
        self.sentinelx.model_factory.get_model.return_value.predict.return_value = 1
        self.sentinelx.model_factory.get_model.return_value.predict_proba.return_value = [0.1, 0.9]
        
        # Call the method
        result = self.sentinelx.predict({'feature1': 1, 'feature2': 2}, 'random_forest')
        
        # Check that the result is correct
        self.assertEqual(result['prediction'], 1)
        self.assertEqual(result['probability'], 0.9)
        self.assertEqual(result['features'], {'feature1': 1, 'feature2': 2})
        
        # Check that the methods were called correctly
        self.sentinelx.preprocessing_pipeline.transform_single.assert_called_once_with({'feature1': 1, 'feature2': 2})
        self.sentinelx.model_factory.get_model.assert_called_once_with('random_forest')
        self.sentinelx.model_factory.get_model.return_value.predict.assert_called_once_with([1, 2, 3])
        self.sentinelx.model_factory.get_model.return_value.predict_proba.assert_called_once_with([1, 2, 3])
    
    def test_start_network_monitoring(self):
        """Test the start_network_monitoring method."""
        # Set up the mocks
        self.sentinelx.packet_capture.start_capture.return_value = True
        
        # Call the method
        result = self.sentinelx.start_network_monitoring('eth0')
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the methods were called correctly
        self.sentinelx.packet_capture.start_capture.assert_called_once_with('eth0')
    
    def test_stop_network_monitoring(self):
        """Test the stop_network_monitoring method."""
        # Set up the mocks
        self.sentinelx.packet_capture.stop_capture.return_value = True
        
        # Call the method
        result = self.sentinelx.stop_network_monitoring()
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the methods were called correctly
        self.sentinelx.packet_capture.stop_capture.assert_called_once()
    
    def test_get_available_interfaces(self):
        """Test the get_available_interfaces method."""
        # Set up the mocks
        self.sentinelx.packet_capture.get_available_interfaces.return_value = ['eth0', 'lo']
        
        # Call the method
        result = self.sentinelx.get_available_interfaces()
        
        # Check that the result is correct
        self.assertEqual(result, ['eth0', 'lo'])
        
        # Check that the methods were called correctly
        self.sentinelx.packet_capture.get_available_interfaces.assert_called_once()
    
    def test_get_packet_stats(self):
        """Test the get_packet_stats method."""
        # Set up the mocks
        self.sentinelx.packet_capture.get_stats.return_value = {
            'total_packets': 100,
            'total_bytes': 10000,
            'protocol_stats': {'TCP': 80, 'UDP': 20},
            'port_stats': {80: 50, 443: 30}
        }
        
        # Call the method
        result = self.sentinelx.get_packet_stats()
        
        # Check that the result is correct
        self.assertEqual(result['total_packets'], 100)
        self.assertEqual(result['total_bytes'], 10000)
        self.assertEqual(result['protocol_stats']['TCP'], 80)
        self.assertEqual(result['protocol_stats']['UDP'], 20)
        
        # Check that the methods were called correctly
        self.sentinelx.packet_capture.get_stats.assert_called_once()
    
    def test_get_flow_stats(self):
        """Test the get_flow_stats method."""
        # Set up the mocks
        self.sentinelx.flow_analyzer.get_stats.return_value = {
            'active_flows': 10,
            'total_flows': 20,
            'expired_flows': 10
        }
        
        # Call the method
        result = self.sentinelx.get_flow_stats()
        
        # Check that the result is correct
        self.assertEqual(result['active_flows'], 10)
        self.assertEqual(result['total_flows'], 20)
        self.assertEqual(result['expired_flows'], 10)
        
        # Check that the methods were called correctly
        self.sentinelx.flow_analyzer.get_stats.assert_called_once()
    
    def test_get_top_talkers(self):
        """Test the get_top_talkers method."""
        # Set up the mocks
        self.sentinelx.flow_analyzer.get_top_talkers.return_value = [
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
        
        # Call the method
        result = self.sentinelx.get_top_talkers(2)
        
        # Check that the result is correct
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['src_ip'], '192.168.1.1')
        self.assertEqual(result[1]['src_ip'], '192.168.1.3')
        
        # Check that the methods were called correctly
        self.sentinelx.flow_analyzer.get_top_talkers.assert_called_once_with(2)
    
    def test_enrich_ip(self):
        """Test the enrich_ip method."""
        # Set up the mocks
        self.sentinelx.threat_intelligence.enrich_ip.return_value = {
            'ip': '192.168.1.1',
            'reputation': 'malicious',
            'country': 'US',
            'asn': 12345
        }
        
        # Call the method
        result = self.sentinelx.enrich_ip('192.168.1.1')
        
        # Check that the result is correct
        self.assertEqual(result['ip'], '192.168.1.1')
        self.assertEqual(result['reputation'], 'malicious')
        self.assertEqual(result['country'], 'US')
        self.assertEqual(result['asn'], 12345)
        
        # Check that the methods were called correctly
        self.sentinelx.threat_intelligence.enrich_ip.assert_called_once_with('192.168.1.1')
    
    def test_enrich_domain(self):
        """Test the enrich_domain method."""
        # Set up the mocks
        self.sentinelx.threat_intelligence.enrich_domain.return_value = {
            'domain': 'example.com',
            'reputation': 'malicious',
            'categories': ['malware', 'phishing']
        }
        
        # Call the method
        result = self.sentinelx.enrich_domain('example.com')
        
        # Check that the result is correct
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['reputation'], 'malicious')
        self.assertEqual(result['categories'], ['malware', 'phishing'])
        
        # Check that the methods were called correctly
        self.sentinelx.threat_intelligence.enrich_domain.assert_called_once_with('example.com')
    
    def test_get_alerts(self):
        """Test the get_alerts method."""
        # Set up the mocks
        self.sentinelx.alert_manager.get_alerts.return_value = [
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
        
        # Call the method
        result = self.sentinelx.get_alerts()
        
        # Check that the result is correct
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['id'], '12345')
        self.assertEqual(result[1]['id'], '67890')
        
        # Check that the methods were called correctly
        self.sentinelx.alert_manager.get_alerts.assert_called_once()
    
    def test_get_alert(self):
        """Test the get_alert method."""
        # Set up the mocks
        self.sentinelx.alert_manager.get_alert.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20}
        }
        
        # Call the method
        result = self.sentinelx.get_alert('12345')
        
        # Check that the result is correct
        self.assertEqual(result['id'], '12345')
        self.assertEqual(result['alert_type'], 'port_scan')
        self.assertEqual(result['source_ip'], '192.168.1.1')
        
        # Check that the methods were called correctly
        self.sentinelx.alert_manager.get_alert.assert_called_once_with('12345')
    
    def test_update_alert_status(self):
        """Test the update_alert_status method."""
        # Set up the mocks
        self.sentinelx.alert_manager.update_alert.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'acknowledged'
        }
        
        # Call the method
        result = self.sentinelx.update_alert_status('12345', 'acknowledged')
        
        # Check that the result is correct
        self.assertEqual(result['id'], '12345')
        self.assertEqual(result['status'], 'acknowledged')
        
        # Check that the methods were called correctly
        self.sentinelx.alert_manager.update_alert.assert_called_once_with('12345', {'status': 'acknowledged'})
    
    def test_analyze_alert(self):
        """Test the analyze_alert method."""
        # Set up the mocks
        self.sentinelx.alert_manager.get_alert.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20}
        }
        
        self.sentinelx.threat_reasoning.analyze_alert.return_value = {
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
        
        # Call the method
        result = self.sentinelx.analyze_alert('12345')
        
        # Check that the result is correct
        self.assertEqual(result['explanation'], 'This is a port scan attack')
        self.assertEqual(result['mitre_techniques'][0]['technique_id'], 'T1046')
        
        # Check that the methods were called correctly
        self.sentinelx.alert_manager.get_alert.assert_called_once_with('12345')
        self.sentinelx.threat_reasoning.analyze_alert.assert_called_once_with({
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20}
        })
    
    def test_generate_alert_report(self):
        """Test the generate_alert_report method."""
        # Set up the mocks
        self.sentinelx.alert_manager.get_alert.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20},
            'analysis': {
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
        }
        
        self.sentinelx.report_generator.generate_report.return_value = {
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
        
        # Call the method
        result = self.sentinelx.generate_alert_report('12345')
        
        # Check that the result is correct
        self.assertEqual(result['alert_id'], '12345')
        self.assertEqual(result['explanation'], 'This is a port scan attack')
        
        # Check that the methods were called correctly
        self.sentinelx.alert_manager.get_alert.assert_called_once_with('12345')
        self.sentinelx.report_generator.generate_report.assert_called_once_with({
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20},
            'analysis': {
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
        })
    
    def test_get_system_info(self):
        """Test the get_system_info method."""
        # Mock the psutil module
        with patch('src.sentinelx.psutil') as mock_psutil, \
             patch('src.sentinelx.platform') as mock_platform, \
             patch('src.sentinelx.socket') as mock_socket:
            
            # Set up the mocks
            mock_platform.system.return_value = 'Linux'
            mock_platform.release.return_value = '5.10.0'
            mock_socket.gethostname.return_value = 'test-host'
            mock_psutil.cpu_percent.return_value = 10.5
            mock_psutil.virtual_memory.return_value.percent = 50.2
            mock_psutil.disk_usage.return_value.percent = 30.8
            
            # Call the method
            result = self.sentinelx.get_system_info()
            
            # Check that the result is correct
            self.assertEqual(result['hostname'], 'test-host')
            self.assertEqual(result['os'], 'Linux 5.10.0')
            self.assertEqual(result['cpu_usage'], 10.5)
            self.assertEqual(result['memory_usage'], 50.2)
            self.assertEqual(result['disk_usage'], 30.8)
    
    def test_main_function(self):
        """Test the main function."""
        # Mock the argparse module
        with patch('src.sentinelx.argparse') as mock_argparse, \
             patch('src.sentinelx.SentinelX') as mock_sentinelx_class, \
             patch('src.sentinelx.signal') as mock_signal:
            
            # Set up the mocks
            mock_parser = MagicMock()
            mock_argparse.ArgumentParser.return_value = mock_parser
            mock_args = MagicMock()
            mock_parser.parse_args.return_value = mock_args
            mock_sentinelx = MagicMock()
            mock_sentinelx_class.return_value = mock_sentinelx
            
            # Test the train command
            mock_args.command = 'train'
            mock_args.model_type = 'random_forest'
            
            # Call the main function
            from src.sentinelx import main
            main()
            
            # Check that the methods were called correctly
            mock_sentinelx.train_model.assert_called_once_with('random_forest')
            
            # Test the evaluate command
            mock_args.command = 'evaluate'
            mock_args.model_type = 'random_forest'
            
            # Call the main function
            main()
            
            # Check that the methods were called correctly
            mock_sentinelx.evaluate_model.assert_called_once_with('random_forest')
            
            # Test the monitor command
            mock_args.command = 'monitor'
            mock_args.interface = 'eth0'
            
            # Call the main function
            main()
            
            # Check that the methods were called correctly
            mock_sentinelx.start_network_monitoring.assert_called_once_with('eth0')
            
            # Check that the signal handlers were set up
            mock_signal.signal.assert_has_calls([
                call(mock_signal.SIGINT, mock_sentinelx.stop_network_monitoring),
                call(mock_signal.SIGTERM, mock_sentinelx.stop_network_monitoring)
            ])


if __name__ == '__main__':
    unittest.main()