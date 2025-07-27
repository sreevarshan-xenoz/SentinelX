#!/usr/bin/env python
# SentinelX Reasoning Layer Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
from datetime import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.reasoning.threat_reasoning import ThreatReasoning
from src.reasoning.report_generator import ReportGenerator
from src.reasoning.llm_integration import LLMIntegration, AsyncLLMProcessor
from src.reasoning.mitre_context import MITREContext
from src.reasoning.cve_context import CVEContext
from src.alert.alert_manager import Alert


class TestThreatReasoning(unittest.TestCase):
    """Test the ThreatReasoning class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for data files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock configuration
        self.config = {
            'llm': {
                'provider': 'mock',
                'api_key': 'test_api_key',
                'model': 'test-model'
            },
            'mitre_data_path': os.path.join(self.temp_dir, 'mitre_data.json'),
            'cve_data_path': os.path.join(self.temp_dir, 'cve_data.json')
        }
        
        # Create mock MITRE and CVE data files
        with open(self.config['mitre_data_path'], 'w') as f:
            json.dump({
                'techniques': [
                    {
                        'technique_id': 'T1046',
                        'name': 'Network Service Scanning',
                        'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                        'tactics': ['discovery'],
                        'mitigation': 'Minimize the number of services exposed to the network.'
                    }
                ]
            }, f)
        
        with open(self.config['cve_data_path'], 'w') as f:
            json.dump({
                'cves': [
                    {
                        'id': 'CVE-2021-1234',
                        'description': 'A vulnerability in the web server allows remote code execution.',
                        'severity': 'high',
                        'cvss_score': 8.5,
                        'affected_products': ['Web Server 1.0'],
                        'remediation': 'Update to the latest version.'
                    }
                ]
            }, f)
        
        # Create a ThreatReasoning object with mocked dependencies
        with patch('src.reasoning.threat_reasoning.ConfigManager') as mock_config_manager, \
             patch('src.reasoning.threat_reasoning.LLMIntegration') as mock_llm_integration, \
             patch('src.reasoning.threat_reasoning.MITREContext') as mock_mitre_context, \
             patch('src.reasoning.threat_reasoning.CVEContext') as mock_cve_context:
            
            mock_config_manager.get_instance.return_value.get.return_value = self.config
            self.mock_llm = MagicMock()
            mock_llm_integration.return_value = self.mock_llm
            self.mock_mitre = MagicMock()
            mock_mitre_context.return_value = self.mock_mitre
            self.mock_cve = MagicMock()
            mock_cve_context.return_value = self.mock_cve
            
            self.threat_reasoning = ThreatReasoning()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    def test_analyze_alert(self):
        """Test analyzing an alert."""
        # Create a mock alert
        alert = MagicMock(spec=Alert)
        alert.id = '12345'
        alert.alert_type = 'port_scan'
        alert.source_ip = '192.168.1.1'
        alert.destination_ip = '192.168.1.2'
        alert.to_dict.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'raw_data': {'port_count': 20}
        }
        
        # Mock the LLM response
        self.mock_llm.generate_response.return_value = json.dumps({
            'explanation': 'This is a port scan attack',
            'mitre_techniques': ['T1046'],
            'cve_ids': ['CVE-2021-1234'],
            'remediation': 'Block the source IP address'
        })
        
        # Mock the MITRE and CVE context
        self.mock_mitre.get_technique_details.return_value = {
            'technique_id': 'T1046',
            'name': 'Network Service Scanning',
            'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
            'tactics': ['discovery'],
            'mitigation': 'Minimize the number of services exposed to the network.'
        }
        
        self.mock_cve.get_cve_details.return_value = {
            'id': 'CVE-2021-1234',
            'description': 'A vulnerability in the web server allows remote code execution.',
            'severity': 'high',
            'cvss_score': 8.5,
            'affected_products': ['Web Server 1.0'],
            'remediation': 'Update to the latest version.'
        }
        
        # Analyze the alert
        result = self.threat_reasoning.analyze_alert(alert)
        
        # Check that the result is correct
        self.assertEqual(result['explanation'], 'This is a port scan attack')
        self.assertEqual(result['mitre_techniques'][0]['technique_id'], 'T1046')
        self.assertEqual(result['cve_ids'][0]['id'], 'CVE-2021-1234')
        self.assertEqual(result['remediation'], 'Block the source IP address')
        
        # Check that the LLM was called correctly
        self.mock_llm.generate_response.assert_called_once()
    
    def test_analyze_alerts_batch(self):
        """Test analyzing a batch of alerts."""
        # Create mock alerts
        alert1 = MagicMock(spec=Alert)
        alert1.id = '12345'
        alert1.alert_type = 'port_scan'
        alert1.source_ip = '192.168.1.1'
        alert1.destination_ip = '192.168.1.2'
        alert1.to_dict.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'raw_data': {'port_count': 20}
        }
        
        alert2 = MagicMock(spec=Alert)
        alert2.id = '67890'
        alert2.alert_type = 'brute_force'
        alert2.source_ip = '192.168.1.3'
        alert2.destination_ip = '192.168.1.4'
        alert2.to_dict.return_value = {
            'id': '67890',
            'alert_type': 'brute_force',
            'source_ip': '192.168.1.3',
            'destination_ip': '192.168.1.4',
            'raw_data': {'login_attempts': 10}
        }
        
        # Mock the LLM response
        self.mock_llm.generate_response.side_effect = [
            json.dumps({
                'explanation': 'This is a port scan attack',
                'mitre_techniques': ['T1046'],
                'cve_ids': ['CVE-2021-1234'],
                'remediation': 'Block the source IP address'
            }),
            json.dumps({
                'explanation': 'This is a brute force attack',
                'mitre_techniques': ['T1110'],
                'cve_ids': [],
                'remediation': 'Implement account lockout policies'
            })
        ]
        
        # Mock the MITRE and CVE context
        self.mock_mitre.get_technique_details.side_effect = [
            {
                'technique_id': 'T1046',
                'name': 'Network Service Scanning',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                'tactics': ['discovery'],
                'mitigation': 'Minimize the number of services exposed to the network.'
            },
            {
                'technique_id': 'T1110',
                'name': 'Brute Force',
                'description': 'Adversaries may use brute force techniques to gain access to accounts.',
                'tactics': ['credential-access'],
                'mitigation': 'Implement account lockout policies.'
            }
        ]
        
        self.mock_cve.get_cve_details.return_value = {
            'id': 'CVE-2021-1234',
            'description': 'A vulnerability in the web server allows remote code execution.',
            'severity': 'high',
            'cvss_score': 8.5,
            'affected_products': ['Web Server 1.0'],
            'remediation': 'Update to the latest version.'
        }
        
        # Analyze the alerts
        results = self.threat_reasoning.analyze_alerts_batch([alert1, alert2])
        
        # Check that the results are correct
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['explanation'], 'This is a port scan attack')
        self.assertEqual(results[1]['explanation'], 'This is a brute force attack')
        
        # Check that the LLM was called correctly
        self.assertEqual(self.mock_llm.generate_response.call_count, 2)
    
    def test_download_mitre_data(self):
        """Test downloading MITRE ATT&CK data."""
        # Mock the MITREContext.download_latest_data method
        self.mock_mitre.download_latest_data.return_value = True
        
        # Download MITRE data
        result = self.threat_reasoning.download_mitre_data()
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the MITREContext.download_latest_data method was called correctly
        self.mock_mitre.download_latest_data.assert_called_once()
    
    def test_download_cve_data(self):
        """Test downloading CVE data."""
        # Mock the CVEContext.download_recent_cves method
        self.mock_cve.download_recent_cves.return_value = True
        
        # Download CVE data
        result = self.threat_reasoning.download_cve_data()
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the CVEContext.download_recent_cves method was called correctly
        self.mock_cve.download_recent_cves.assert_called_once()


class TestReportGenerator(unittest.TestCase):
    """Test the ReportGenerator class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for report files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock configuration
        self.config = {
            'report_output_dir': self.temp_dir
        }
        
        # Create a ReportGenerator object with mocked dependencies
        with patch('src.reasoning.report_generator.ConfigManager') as mock_config_manager:
            mock_config_manager.get_instance.return_value.get.return_value = self.config
            self.report_generator = ReportGenerator()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    def test_generate_alert_report(self):
        """Test generating a report for a single alert."""
        # Create a mock alert
        alert = MagicMock(spec=Alert)
        alert.id = '12345'
        alert.alert_type = 'port_scan'
        alert.source_ip = '192.168.1.1'
        alert.destination_ip = '192.168.1.2'
        alert.timestamp = datetime.now().isoformat()
        alert.severity = 'high'
        alert.description = 'Port scan detected'
        alert.to_dict.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'timestamp': datetime.now().isoformat(),
            'severity': 'high',
            'description': 'Port scan detected'
        }
        
        # Create mock analysis data
        analysis = {
            'explanation': 'This is a port scan attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1046',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                    'tactics': ['discovery'],
                    'mitigation': 'Minimize the number of services exposed to the network.'
                }
            ],
            'cve_ids': [
                {
                    'id': 'CVE-2021-1234',
                    'description': 'A vulnerability in the web server allows remote code execution.',
                    'severity': 'high',
                    'cvss_score': 8.5,
                    'affected_products': ['Web Server 1.0'],
                    'remediation': 'Update to the latest version.'
                }
            ],
            'remediation': 'Block the source IP address'
        }
        
        # Generate a report
        report = self.report_generator.generate_alert_report(alert, analysis)
        
        # Check that the report is correct
        self.assertEqual(report['alert_id'], '12345')
        self.assertEqual(report['alert_type'], 'port_scan')
        self.assertEqual(report['explanation'], 'This is a port scan attack')
        self.assertEqual(report['mitre_techniques'][0]['technique_id'], 'T1046')
        self.assertEqual(report['cve_ids'][0]['id'], 'CVE-2021-1234')
        self.assertEqual(report['remediation'], 'Block the source IP address')
    
    def test_generate_summary_report(self):
        """Test generating a summary report for multiple alerts."""
        # Create mock alerts
        alert1 = MagicMock(spec=Alert)
        alert1.id = '12345'
        alert1.alert_type = 'port_scan'
        alert1.source_ip = '192.168.1.1'
        alert1.destination_ip = '192.168.1.2'
        alert1.timestamp = datetime.now().isoformat()
        alert1.severity = 'high'
        alert1.description = 'Port scan detected'
        alert1.to_dict.return_value = {
            'id': '12345',
            'alert_type': 'port_scan',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'timestamp': datetime.now().isoformat(),
            'severity': 'high',
            'description': 'Port scan detected'
        }
        
        alert2 = MagicMock(spec=Alert)
        alert2.id = '67890'
        alert2.alert_type = 'brute_force'
        alert2.source_ip = '192.168.1.3'
        alert2.destination_ip = '192.168.1.4'
        alert2.timestamp = datetime.now().isoformat()
        alert2.severity = 'medium'
        alert2.description = 'Brute force attack detected'
        alert2.to_dict.return_value = {
            'id': '67890',
            'alert_type': 'brute_force',
            'source_ip': '192.168.1.3',
            'destination_ip': '192.168.1.4',
            'timestamp': datetime.now().isoformat(),
            'severity': 'medium',
            'description': 'Brute force attack detected'
        }
        
        # Create mock analyses
        analysis1 = {
            'explanation': 'This is a port scan attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1046',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                    'tactics': ['discovery'],
                    'mitigation': 'Minimize the number of services exposed to the network.'
                }
            ],
            'cve_ids': [
                {
                    'id': 'CVE-2021-1234',
                    'description': 'A vulnerability in the web server allows remote code execution.',
                    'severity': 'high',
                    'cvss_score': 8.5,
                    'affected_products': ['Web Server 1.0'],
                    'remediation': 'Update to the latest version.'
                }
            ],
            'remediation': 'Block the source IP address'
        }
        
        analysis2 = {
            'explanation': 'This is a brute force attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1110',
                    'name': 'Brute Force',
                    'description': 'Adversaries may use brute force techniques to gain access to accounts.',
                    'tactics': ['credential-access'],
                    'mitigation': 'Implement account lockout policies.'
                }
            ],
            'cve_ids': [],
            'remediation': 'Implement account lockout policies'
        }
        
        # Generate a summary report
        report = self.report_generator.generate_summary_report(
            [alert1, alert2],
            [analysis1, analysis2]
        )
        
        # Check that the report is correct
        self.assertEqual(len(report['alerts']), 2)
        self.assertEqual(report['alerts'][0]['alert_id'], '12345')
        self.assertEqual(report['alerts'][1]['alert_id'], '67890')
        self.assertEqual(len(report['top_mitre_techniques']), 2)
        self.assertEqual(report['top_mitre_techniques'][0]['technique_id'], 'T1046')
        self.assertEqual(report['top_mitre_techniques'][1]['technique_id'], 'T1110')
        self.assertEqual(len(report['top_cve_ids']), 1)
        self.assertEqual(report['top_cve_ids'][0]['id'], 'CVE-2021-1234')
        self.assertEqual(len(report['common_remediation_steps']), 2)
    
    def test_save_report_json(self):
        """Test saving a report in JSON format."""
        # Create a report
        report = {
            'alert_id': '12345',
            'alert_type': 'port_scan',
            'explanation': 'This is a port scan attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1046',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                    'tactics': ['discovery'],
                    'mitigation': 'Minimize the number of services exposed to the network.'
                }
            ],
            'cve_ids': [
                {
                    'id': 'CVE-2021-1234',
                    'description': 'A vulnerability in the web server allows remote code execution.',
                    'severity': 'high',
                    'cvss_score': 8.5,
                    'affected_products': ['Web Server 1.0'],
                    'remediation': 'Update to the latest version.'
                }
            ],
            'remediation': 'Block the source IP address'
        }
        
        # Save the report
        file_path = self.report_generator.save_report_json(report, '12345')
        
        # Check that the file was created
        self.assertTrue(os.path.exists(file_path))
        
        # Check that the report was saved correctly
        with open(file_path, 'r') as f:
            saved_report = json.load(f)
        
        self.assertEqual(saved_report['alert_id'], '12345')
        self.assertEqual(saved_report['alert_type'], 'port_scan')
        self.assertEqual(saved_report['explanation'], 'This is a port scan attack')
    
    def test_save_report_markdown(self):
        """Test saving a report in Markdown format."""
        # Create a report
        report = {
            'alert_id': '12345',
            'alert_type': 'port_scan',
            'explanation': 'This is a port scan attack',
            'mitre_techniques': [
                {
                    'technique_id': 'T1046',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                    'tactics': ['discovery'],
                    'mitigation': 'Minimize the number of services exposed to the network.'
                }
            ],
            'cve_ids': [
                {
                    'id': 'CVE-2021-1234',
                    'description': 'A vulnerability in the web server allows remote code execution.',
                    'severity': 'high',
                    'cvss_score': 8.5,
                    'affected_products': ['Web Server 1.0'],
                    'remediation': 'Update to the latest version.'
                }
            ],
            'remediation': 'Block the source IP address'
        }
        
        # Save the report
        file_path = self.report_generator.save_report_markdown(report, '12345')
        
        # Check that the file was created
        self.assertTrue(os.path.exists(file_path))
        
        # Check that the report was saved correctly
        with open(file_path, 'r') as f:
            content = f.read()
        
        self.assertIn('# Alert Report: 12345', content)
        self.assertIn('## Alert Details', content)
        self.assertIn('## Explanation', content)
        self.assertIn('This is a port scan attack', content)
        self.assertIn('## MITRE ATT&CK Techniques', content)
        self.assertIn('T1046', content)
        self.assertIn('## CVEs', content)
        self.assertIn('CVE-2021-1234', content)
        self.assertIn('## Remediation Steps', content)
        self.assertIn('Block the source IP address', content)


class TestLLMIntegration(unittest.TestCase):
    """Test the LLMIntegration class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a mock configuration
        self.config = {
            'provider': 'mock',
            'api_key': 'test_api_key',
            'model': 'test-model',
            'temperature': 0.7,
            'max_tokens': 1000
        }
        
        # Create an LLMIntegration object
        self.llm_integration = LLMIntegration(self.config)
    
    @patch('src.reasoning.llm_integration.openai.ChatCompletion.create')
    def test_initialize_openai(self, mock_create):
        """Test initializing OpenAI."""
        # Set the provider to OpenAI
        self.llm_integration.config['provider'] = 'openai'
        
        # Mock the OpenAI response
        mock_create.return_value = {
            'choices': [
                {
                    'message': {
                        'content': 'This is a test response'
                    }
                }
            ]
        }
        
        # Initialize OpenAI
        self.llm_integration._initialize_openai()
        
        # Generate a response
        response = self.llm_integration.generate_response('This is a test prompt')
        
        # Check that the response is correct
        self.assertEqual(response, 'This is a test response')
        
        # Check that the OpenAI API was called correctly
        mock_create.assert_called_once()
    
    def test_initialize_langchain(self):
        """Test initializing Langchain."""
        # Set the provider to Langchain
        self.llm_integration.config['provider'] = 'langchain'
        
        # Mock the Langchain initialization
        with patch('src.reasoning.llm_integration.ChatOpenAI') as mock_chat_openai:
            mock_llm = MagicMock()
            mock_chat_openai.return_value = mock_llm
            mock_llm.invoke.return_value.content = 'This is a test response'
            
            # Initialize Langchain
            self.llm_integration._initialize_langchain()
            
            # Generate a response
            response = self.llm_integration.generate_response('This is a test prompt')
            
            # Check that the response is correct
            self.assertEqual(response, 'This is a test response')
            
            # Check that the Langchain API was called correctly
            mock_llm.invoke.assert_called_once()
    
    def test_initialize_local(self):
        """Test initializing a local model."""
        # Set the provider to local
        self.llm_integration.config['provider'] = 'local'
        
        # Mock the local model initialization
        with patch('src.reasoning.llm_integration.Llama') as mock_llama:
            mock_model = MagicMock()
            mock_llama.return_value = mock_model
            mock_model.create_completion.return_value = {
                'choices': [
                    {
                        'text': 'This is a test response'
                    }
                ]
            }
            
            # Initialize the local model
            self.llm_integration._initialize_local()
            
            # Generate a response
            response = self.llm_integration.generate_response('This is a test prompt')
            
            # Check that the response is correct
            self.assertEqual(response, 'This is a test response')
            
            # Check that the local model API was called correctly
            mock_model.create_completion.assert_called_once()
    
    def test_get_prompt_template(self):
        """Test getting a prompt template."""
        # Get the alert analysis prompt template
        template = self.llm_integration.get_prompt_template('alert_analysis')
        
        # Check that the template is correct
        self.assertIn('analyze the following security alert', template.lower())
        
        # Get a non-existent prompt template
        template = self.llm_integration.get_prompt_template('non_existent')
        
        # Check that the template is None
        self.assertIsNone(template)


class TestAsyncLLMProcessor(unittest.TestCase):
    """Test the AsyncLLMProcessor class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a mock LLMIntegration object
        self.mock_llm = MagicMock(spec=LLMIntegration)
        self.mock_llm.generate_response.return_value = 'This is a test response'
        
        # Create an AsyncLLMProcessor object
        self.processor = AsyncLLMProcessor(self.mock_llm, num_workers=2)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Stop the processor
        self.processor.stop()
    
    def test_submit_request(self):
        """Test submitting a request."""
        # Submit a request
        future = self.processor.submit_request('This is a test prompt')
        
        # Wait for the result
        result = future.result(timeout=5)
        
        # Check that the result is correct
        self.assertEqual(result, 'This is a test response')
        
        # Check that the LLM was called correctly
        self.mock_llm.generate_response.assert_called_once_with('This is a test prompt')
    
    def test_submit_batch(self):
        """Test submitting a batch of requests."""
        # Submit a batch of requests
        prompts = ['Prompt 1', 'Prompt 2', 'Prompt 3']
        futures = self.processor.submit_batch(prompts)
        
        # Wait for the results
        results = [future.result(timeout=5) for future in futures]
        
        # Check that the results are correct
        self.assertEqual(results, ['This is a test response'] * 3)
        
        # Check that the LLM was called correctly
        self.assertEqual(self.mock_llm.generate_response.call_count, 3)
    
    def test_stop(self):
        """Test stopping the processor."""
        # Stop the processor
        self.processor.stop()
        
        # Check that the processor is stopped
        self.assertTrue(self.processor.executor._shutdown)
        
        # Try to submit a request after stopping
        with self.assertRaises(RuntimeError):
            self.processor.submit_request('This is a test prompt')


class TestMITREContext(unittest.TestCase):
    """Test the MITREContext class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for data files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock MITRE data file
        self.mitre_data_path = os.path.join(self.temp_dir, 'mitre_data.json')
        with open(self.mitre_data_path, 'w') as f:
            json.dump({
                'techniques': [
                    {
                        'technique_id': 'T1046',
                        'name': 'Network Service Scanning',
                        'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                        'tactics': ['discovery'],
                        'mitigation': 'Minimize the number of services exposed to the network.'
                    },
                    {
                        'technique_id': 'T1110',
                        'name': 'Brute Force',
                        'description': 'Adversaries may use brute force techniques to gain access to accounts.',
                        'tactics': ['credential-access'],
                        'mitigation': 'Implement account lockout policies.'
                    }
                ]
            }, f)
        
        # Create a MITREContext object
        self.mitre_context = MITREContext(self.mitre_data_path)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    def test_load_mitre_data(self):
        """Test loading MITRE ATT&CK data."""
        # Check that the data was loaded correctly
        self.assertEqual(len(self.mitre_context.techniques), 2)
        self.assertEqual(self.mitre_context.techniques['T1046']['name'], 'Network Service Scanning')
        self.assertEqual(self.mitre_context.techniques['T1110']['name'], 'Brute Force')
    
    def test_get_technique_details(self):
        """Test getting technique details."""
        # Get technique details
        details = self.mitre_context.get_technique_details('T1046')
        
        # Check that the details are correct
        self.assertEqual(details['technique_id'], 'T1046')
        self.assertEqual(details['name'], 'Network Service Scanning')
        self.assertEqual(details['description'], 'Adversaries may attempt to get a listing of services running on remote hosts.')
        self.assertEqual(details['tactics'], ['discovery'])
        self.assertEqual(details['mitigation'], 'Minimize the number of services exposed to the network.')
        
        # Get details for a non-existent technique
        details = self.mitre_context.get_technique_details('T9999')
        
        # Check that the details are None
        self.assertIsNone(details)
    
    def test_map_alert_to_techniques(self):
        """Test mapping an alert to techniques."""
        # Create a mock alert
        alert = MagicMock(spec=Alert)
        alert.alert_type = 'port_scan'
        alert.raw_data = {'port_count': 20}
        
        # Create a mock mapping
        self.mitre_context.alert_type_mappings = {
            'port_scan': ['T1046']
        }
        
        # Map the alert to techniques
        techniques = self.mitre_context.map_alert_to_techniques(alert)
        
        # Check that the techniques are correct
        self.assertEqual(len(techniques), 1)
        self.assertEqual(techniques[0]['technique_id'], 'T1046')
        self.assertEqual(techniques[0]['name'], 'Network Service Scanning')
    
    def test_search_techniques_by_keyword(self):
        """Test searching techniques by keyword."""
        # Search for techniques by keyword
        techniques = self.mitre_context.search_techniques_by_keyword('scanning')
        
        # Check that the techniques are correct
        self.assertEqual(len(techniques), 1)
        self.assertEqual(techniques[0]['technique_id'], 'T1046')
        self.assertEqual(techniques[0]['name'], 'Network Service Scanning')
        
        # Search for techniques by another keyword
        techniques = self.mitre_context.search_techniques_by_keyword('brute force')
        
        # Check that the techniques are correct
        self.assertEqual(len(techniques), 1)
        self.assertEqual(techniques[0]['technique_id'], 'T1110')
        self.assertEqual(techniques[0]['name'], 'Brute Force')
        
        # Search for techniques by a non-existent keyword
        techniques = self.mitre_context.search_techniques_by_keyword('non-existent')
        
        # Check that no techniques were found
        self.assertEqual(len(techniques), 0)
    
    @patch('requests.get')
    def test_download_latest_data(self, mock_get):
        """Test downloading the latest MITRE ATT&CK data."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475',
                    'name': 'Network Service Scanning',
                    'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
                    'external_references': [
                        {
                            'source_name': 'mitre-attack',
                            'external_id': 'T1046'
                        }
                    ],
                    'kill_chain_phases': [
                        {
                            'kill_chain_name': 'mitre-attack',
                            'phase_name': 'discovery'
                        }
                    ]
                }
            ]
        }
        mock_get.return_value = mock_response
        
        # Download the latest data
        result = self.mitre_context.download_latest_data()
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the API was called correctly
        mock_get.assert_called_once()
        
        # Check that the data was saved correctly
        with open(self.mitre_data_path, 'r') as f:
            saved_data = json.load(f)
        
        self.assertEqual(len(saved_data['techniques']), 1)
        self.assertEqual(saved_data['techniques'][0]['technique_id'], 'T1046')
        self.assertEqual(saved_data['techniques'][0]['name'], 'Network Service Scanning')


class TestCVEContext(unittest.TestCase):
    """Test the CVEContext class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for data files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock CVE data file
        self.cve_data_path = os.path.join(self.temp_dir, 'cve_data.json')
        with open(self.cve_data_path, 'w') as f:
            json.dump({
                'cves': [
                    {
                        'id': 'CVE-2021-1234',
                        'description': 'A vulnerability in the web server allows remote code execution.',
                        'severity': 'high',
                        'cvss_score': 8.5,
                        'affected_products': ['Web Server 1.0'],
                        'remediation': 'Update to the latest version.'
                    },
                    {
                        'id': 'CVE-2021-5678',
                        'description': 'A vulnerability in the database server allows SQL injection.',
                        'severity': 'critical',
                        'cvss_score': 9.5,
                        'affected_products': ['Database Server 2.0'],
                        'remediation': 'Apply the security patch.'
                    }
                ]
            }, f)
        
        # Create a CVEContext object
        self.cve_context = CVEContext(self.cve_data_path)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    def test_load_cve_data(self):
        """Test loading CVE data."""
        # Check that the data was loaded correctly
        self.assertEqual(len(self.cve_context.cves), 2)
        self.assertEqual(self.cve_context.cves['CVE-2021-1234']['description'], 'A vulnerability in the web server allows remote code execution.')
        self.assertEqual(self.cve_context.cves['CVE-2021-5678']['description'], 'A vulnerability in the database server allows SQL injection.')
    
    def test_get_cve_details(self):
        """Test getting CVE details."""
        # Get CVE details
        details = self.cve_context.get_cve_details('CVE-2021-1234')
        
        # Check that the details are correct
        self.assertEqual(details['id'], 'CVE-2021-1234')
        self.assertEqual(details['description'], 'A vulnerability in the web server allows remote code execution.')
        self.assertEqual(details['severity'], 'high')
        self.assertEqual(details['cvss_score'], 8.5)
        self.assertEqual(details['affected_products'], ['Web Server 1.0'])
        self.assertEqual(details['remediation'], 'Update to the latest version.')
        
        # Get details for a non-existent CVE
        details = self.cve_context.get_cve_details('CVE-9999-9999')
        
        # Check that the details are None
        self.assertIsNone(details)
    
    def test_find_cves_for_alert(self):
        """Test finding CVEs for an alert."""
        # Create a mock alert with explicit CVE IDs
        alert1 = MagicMock(spec=Alert)
        alert1.raw_data = {'cve_ids': ['CVE-2021-1234']}
        
        # Find CVEs for the alert
        cves = self.cve_context.find_cves_for_alert(alert1)
        
        # Check that the CVEs are correct
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]['id'], 'CVE-2021-1234')
        self.assertEqual(cves[0]['description'], 'A vulnerability in the web server allows remote code execution.')
        
        # Create a mock alert with product information
        alert2 = MagicMock(spec=Alert)
        alert2.raw_data = {'product': 'Web Server', 'version': '1.0'}
        
        # Mock the search_cves_by_product method
        self.cve_context.search_cves_by_product = MagicMock(return_value=[
            self.cve_context.cves['CVE-2021-1234']
        ])
        
        # Find CVEs for the alert
        cves = self.cve_context.find_cves_for_alert(alert2)
        
        # Check that the CVEs are correct
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]['id'], 'CVE-2021-1234')
        
        # Check that the search_cves_by_product method was called correctly
        self.cve_context.search_cves_by_product.assert_called_once_with('Web Server', '1.0')
    
    def test_search_cves_by_keyword(self):
        """Test searching CVEs by keyword."""
        # Search for CVEs by keyword
        cves = self.cve_context.search_cves_by_keyword('web server')
        
        # Check that the CVEs are correct
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]['id'], 'CVE-2021-1234')
        self.assertEqual(cves[0]['description'], 'A vulnerability in the web server allows remote code execution.')
        
        # Search for CVEs by another keyword
        cves = self.cve_context.search_cves_by_keyword('database')
        
        # Check that the CVEs are correct
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]['id'], 'CVE-2021-5678')
        self.assertEqual(cves[0]['description'], 'A vulnerability in the database server allows SQL injection.')
        
        # Search for CVEs by a non-existent keyword
        cves = self.cve_context.search_cves_by_keyword('non-existent')
        
        # Check that no CVEs were found
        self.assertEqual(len(cves), 0)
    
    @patch('requests.get')
    def test_download_recent_cves(self, mock_get):
        """Test downloading recent CVEs."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'CVE_Items': [
                {
                    'cve': {
                        'CVE_data_meta': {
                            'ID': 'CVE-2021-1234'
                        },
                        'description': {
                            'description_data': [
                                {
                                    'value': 'A vulnerability in the web server allows remote code execution.'
                                }
                            ]
                        }
                    },
                    'impact': {
                        'baseMetricV3': {
                            'cvssV3': {
                                'baseScore': 8.5,
                                'baseSeverity': 'HIGH'
                            }
                        }
                    },
                    'configurations': {
                        'nodes': [
                            {
                                'cpe_match': [
                                    {
                                        'cpe23Uri': 'cpe:2.3:a:vendor:web_server:1.0:*:*:*:*:*:*:*'
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        mock_get.return_value = mock_response
        
        # Download recent CVEs
        result = self.cve_context.download_recent_cves()
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Check that the API was called correctly
        mock_get.assert_called_once()
        
        # Check that the data was saved correctly
        with open(self.cve_data_path, 'r') as f:
            saved_data = json.load(f)
        
        self.assertEqual(len(saved_data['cves']), 1)
        self.assertEqual(saved_data['cves'][0]['id'], 'CVE-2021-1234')
        self.assertEqual(saved_data['cves'][0]['description'], 'A vulnerability in the web server allows remote code execution.')


if __name__ == '__main__':
    unittest.main()