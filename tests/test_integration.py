#!/usr/bin/env python
# SentinelX Integration Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import json
import time

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.sentinelx import SentinelX
from src.network.packet_capture import PacketCapture
from src.network.flow_analyzer import FlowAnalyzer
from src.threat_intel.threat_intelligence import ThreatIntelligence
from src.alert_management.alert_manager import AlertManager
from src.reasoning.threat_reasoning import ThreatReasoning


class TestIntegration(unittest.TestCase):
    """Test the integration of SentinelX components."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for configuration and data
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, 'config.yaml')
        self.alerts_path = os.path.join(self.temp_dir.name, 'alerts.json')
        
        # Create a basic configuration file
        with open(self.config_path, 'w') as f:
            f.write(f'''
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
              json_path: {self.alerts_path}
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
        
        # Create an empty alerts file
        with open(self.alerts_path, 'w') as f:
            f.write('[]')
        
        # Create the SentinelX instance with mocked components
        with patch('src.sentinelx.DatasetLoader'), \
             patch('src.sentinelx.PreprocessingPipeline'), \
             patch('src.sentinelx.ModelFactory'), \
             patch('src.sentinelx.PacketCapture'), \
             patch('src.sentinelx.FlowAnalyzer'), \
             patch('src.sentinelx.ThreatIntelligence'), \
             patch('src.sentinelx.AlertManager'), \
             patch('src.sentinelx.ThreatReasoning'), \
             patch('src.sentinelx.ReportGenerator'), \
             patch('src.sentinelx.LLMIntegration'), \
             patch('src.sentinelx.MITREContext'), \
             patch('src.sentinelx.CVEContext'):
            
            self.sentinelx = SentinelX(config_path=self.config_path)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory
        self.temp_dir.cleanup()
    
    def test_network_monitoring_to_alert_generation(self):
        """Test the flow from network monitoring to alert generation."""
        # Mock the packet capture and flow analyzer
        self.sentinelx.packet_capture = MagicMock(spec=PacketCapture)
        self.sentinelx.flow_analyzer = MagicMock(spec=FlowAnalyzer)
        self.sentinelx.alert_manager = MagicMock(spec=AlertManager)
        
        # Set up the packet capture mock to simulate packet processing
        def process_packet(packet):
            self.sentinelx.flow_analyzer.add_packet.assert_called_with(packet)
        
        self.sentinelx.packet_capture.start_capture.side_effect = lambda interface: True
        self.sentinelx.packet_capture.on_packet_received = process_packet
        
        # Set up the flow analyzer mock to simulate flow detection and alert generation
        self.sentinelx.flow_analyzer.detect_port_scan.return_value = {
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'port_count': 20,
            'start_time': time.time(),
            'end_time': time.time() + 10
        }
        
        # Start network monitoring
        self.sentinelx.start_network_monitoring('eth0')
        
        # Simulate packet processing
        test_packet = {'src': '192.168.1.1', 'dst': '192.168.1.2', 'proto': 'TCP'}
        self.sentinelx.packet_capture.on_packet_received(test_packet)
        
        # Simulate port scan detection
        self.sentinelx.flow_analyzer.detect_port_scan.assert_called_once()
        
        # Check that an alert was created
        self.sentinelx.alert_manager.create_alert.assert_called_with(
            alert_type='port_scan',
            source_ip='192.168.1.1',
            destination_ip='192.168.1.2',
            severity='high',
            raw_data={'port_count': 20, 'start_time': self.sentinelx.flow_analyzer.detect_port_scan.return_value['start_time'],
                     'end_time': self.sentinelx.flow_analyzer.detect_port_scan.return_value['end_time']}
        )
    
    def test_alert_enrichment_and_analysis(self):
        """Test the flow from alert creation to enrichment and analysis."""
        # Mock the threat intelligence and threat reasoning components
        self.sentinelx.threat_intelligence = MagicMock(spec=ThreatIntelligence)
        self.sentinelx.threat_reasoning = MagicMock(spec=ThreatReasoning)
        self.sentinelx.alert_manager = MagicMock(spec=AlertManager)
        
        # Set up the threat intelligence mock to return enrichment data
        self.sentinelx.threat_intelligence.enrich_ip.return_value = {
            'ip': '192.168.1.1',
            'reputation': 'malicious',
            'country': 'US',
            'asn': 12345,
            'threat_types': ['scanner']
        }
        
        # Set up the threat reasoning mock to return analysis data
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
        
        # Set up the alert manager mock to return an alert
        test_alert = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'severity': 'high',
            'timestamp': '2023-01-01T00:00:00',
            'status': 'new',
            'raw_data': {'port_count': 20}
        }
        self.sentinelx.alert_manager.get_alert.return_value = test_alert
        
        # Analyze the alert
        analysis_result = self.sentinelx.analyze_alert('12345')
        
        # Check that the threat intelligence was used to enrich the alert
        self.sentinelx.threat_intelligence.enrich_ip.assert_called_with('192.168.1.1')
        
        # Check that the threat reasoning was used to analyze the alert
        self.sentinelx.threat_reasoning.analyze_alert.assert_called_with(test_alert)
        
        # Check that the analysis result is correct
        self.assertEqual(analysis_result['explanation'], 'This is a port scan attack')
        self.assertEqual(analysis_result['mitre_techniques'][0]['technique_id'], 'T1046')
    
    def test_end_to_end_workflow(self):
        """Test the end-to-end workflow from packet capture to report generation."""
        # Create a real SentinelX instance with a temporary configuration
        with patch('src.sentinelx.PacketCapture') as mock_packet_capture, \
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
            
            # Set up the mocks
            mock_packet_capture.return_value.start_capture.return_value = True
            mock_packet_capture.return_value.get_available_interfaces.return_value = ['eth0', 'lo']
            
            mock_flow_analyzer.return_value.detect_port_scan.return_value = {
                'source_ip': '192.168.1.1',
                'destination_ip': '192.168.1.2',
                'port_count': 20,
                'start_time': time.time(),
                'end_time': time.time() + 10
            }
            
            mock_alert_manager.return_value.create_alert.return_value = {
                'id': '12345',
                'alert_type': 'port_scan',
                'source_ip': '192.168.1.1',
                'destination_ip': '192.168.1.2',
                'severity': 'high',
                'timestamp': '2023-01-01T00:00:00',
                'status': 'new',
                'raw_data': {'port_count': 20}
            }
            
            mock_alert_manager.return_value.get_alert.return_value = {
                'id': '12345',
                'alert_type': 'port_scan',
                'source_ip': '192.168.1.1',
                'destination_ip': '192.168.1.2',
                'severity': 'high',
                'timestamp': '2023-01-01T00:00:00',
                'status': 'new',
                'raw_data': {'port_count': 20}
            }
            
            mock_threat_intelligence.return_value.enrich_ip.return_value = {
                'ip': '192.168.1.1',
                'reputation': 'malicious',
                'country': 'US',
                'asn': 12345,
                'threat_types': ['scanner']
            }
            
            mock_threat_reasoning.return_value.analyze_alert.return_value = {
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
            
            mock_report_generator.return_value.generate_report.return_value = {
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
            
            # Step 1: Get available interfaces
            interfaces = sentinelx.get_available_interfaces()
            self.assertEqual(interfaces, ['eth0', 'lo'])
            
            # Step 2: Start network monitoring
            result = sentinelx.start_network_monitoring('eth0')
            self.assertTrue(result)
            
            # Step 3: Simulate packet processing and port scan detection
            # This would normally happen in the background, but we'll simulate it here
            sentinelx.flow_analyzer.detect_port_scan.return_value = {
                'source_ip': '192.168.1.1',
                'destination_ip': '192.168.1.2',
                'port_count': 20,
                'start_time': time.time(),
                'end_time': time.time() + 10
            }
            
            # Step 4: Get alerts
            mock_alert_manager.return_value.get_alerts.return_value = [
                {
                    'id': '12345',
                    'alert_type': 'port_scan',
                    'source_ip': '192.168.1.1',
                    'destination_ip': '192.168.1.2',
                    'severity': 'high',
                    'timestamp': '2023-01-01T00:00:00',
                    'status': 'new'
                }
            ]
            alerts = sentinelx.get_alerts()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]['id'], '12345')
            
            # Step 5: Get a specific alert
            alert = sentinelx.get_alert('12345')
            self.assertEqual(alert['id'], '12345')
            self.assertEqual(alert['alert_type'], 'port_scan')
            
            # Step 6: Analyze the alert
            analysis = sentinelx.analyze_alert('12345')
            self.assertEqual(analysis['explanation'], 'This is a port scan attack')
            self.assertEqual(analysis['mitre_techniques'][0]['technique_id'], 'T1046')
            
            # Step 7: Generate a report for the alert
            mock_alert_manager.return_value.get_alert.return_value = {
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
            report = sentinelx.generate_alert_report('12345')
            self.assertEqual(report['alert_id'], '12345')
            self.assertEqual(report['explanation'], 'This is a port scan attack')
            
            # Step 8: Update the alert status
            mock_alert_manager.return_value.update_alert.return_value = {
                'id': '12345',
                'alert_type': 'port_scan',
                'source_ip': '192.168.1.1',
                'destination_ip': '192.168.1.2',
                'severity': 'high',
                'timestamp': '2023-01-01T00:00:00',
                'status': 'acknowledged'
            }
            updated_alert = sentinelx.update_alert_status('12345', 'acknowledged')
            self.assertEqual(updated_alert['status'], 'acknowledged')
            
            # Step 9: Stop network monitoring
            mock_packet_capture.return_value.stop_capture.return_value = True
            result = sentinelx.stop_network_monitoring()
            self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()