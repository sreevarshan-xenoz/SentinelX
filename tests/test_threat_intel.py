#!/usr/bin/env python
# SentinelX Threat Intelligence Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.threat_intel.threat_intelligence import ThreatIntelligence
from src.threat_intel.abuseipdb_client import AbuseIPDBClient
from src.threat_intel.otx_client import OTXClient
from src.threat_intel.virustotal_client import VirusTotalClient


class TestThreatIntelligence(unittest.TestCase):
    """Test the ThreatIntelligence class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for cache files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock configuration
        self.config = {
            'abuseipdb': {'api_key': 'test_abuseipdb_key'},
            'otx': {'api_key': 'test_otx_key'},
            'virustotal': {'api_key': 'test_vt_key'},
            'cache_dir': self.temp_dir,
            'cache_duration': 3600  # 1 hour
        }
        
        # Create a ThreatIntelligence object
        with patch('src.threat_intel.threat_intelligence.ConfigManager') as mock_config_manager:
            mock_config_manager.get_instance.return_value.get.return_value = self.config
            self.threat_intel = ThreatIntelligence()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    @patch('src.threat_intel.abuseipdb_client.AbuseIPDBClient.check_ip')
    @patch('src.threat_intel.otx_client.OTXClient.get_ip_reputation')
    @patch('src.threat_intel.virustotal_client.VirusTotalClient.get_ip_report')
    def test_enrich_ip(self, mock_vt_check, mock_otx_check, mock_abuse_check):
        """Test enriching an IP address."""
        # Mock the API responses
        mock_abuse_check.return_value = {
            'abuseConfidenceScore': 90,
            'countryCode': 'US',
            'domain': 'example.com',
            'isp': 'Example ISP',
            'usageType': 'Data Center',
            'reports': 10
        }
        
        mock_otx_check.return_value = {
            'reputation': 'malicious',
            'pulses': 5,
            'malware_samples': 2,
            'url_samples': 3
        }
        
        mock_vt_check.return_value = {
            'detected_urls': 8,
            'detected_communicating_samples': 4,
            'detected_downloaded_samples': 2,
            'asn': 12345,
            'as_owner': 'Example AS'
        }
        
        # Enrich an IP address
        result = self.threat_intel.enrich_ip('192.168.1.1')
        
        # Check that the result contains data from all sources
        self.assertIn('abuseipdb', result)
        self.assertIn('otx', result)
        self.assertIn('virustotal', result)
        
        # Check specific values
        self.assertEqual(result['abuseipdb']['confidence_score'], 90)
        self.assertEqual(result['otx']['reputation'], 'malicious')
        self.assertEqual(result['virustotal']['detected_urls'], 8)
        
        # Check that the result was cached
        cache_file = os.path.join(self.temp_dir, 'ip_192.168.1.1.json')
        self.assertTrue(os.path.exists(cache_file))
    
    @patch('src.threat_intel.otx_client.OTXClient.get_domain_reputation')
    @patch('src.threat_intel.virustotal_client.VirusTotalClient.get_domain_report')
    def test_enrich_domain(self, mock_vt_check, mock_otx_check):
        """Test enriching a domain."""
        # Mock the API responses
        mock_otx_check.return_value = {
            'reputation': 'malicious',
            'pulses': 5,
            'malware_samples': 2,
            'url_samples': 3
        }
        
        mock_vt_check.return_value = {
            'detected_urls': 8,
            'detected_communicating_samples': 4,
            'detected_downloaded_samples': 2,
            'categories': ['malware', 'phishing']
        }
        
        # Enrich a domain
        result = self.threat_intel.enrich_domain('example.com')
        
        # Check that the result contains data from all sources
        self.assertIn('otx', result)
        self.assertIn('virustotal', result)
        
        # Check specific values
        self.assertEqual(result['otx']['reputation'], 'malicious')
        self.assertEqual(result['virustotal']['detected_urls'], 8)
        
        # Check that the result was cached
        cache_file = os.path.join(self.temp_dir, 'domain_example.com.json')
        self.assertTrue(os.path.exists(cache_file))
    
    def test_is_malicious_ip(self):
        """Test checking if an IP is malicious."""
        # Create a mock enrichment result
        enrichment = {
            'abuseipdb': {'confidence_score': 90},
            'otx': {'reputation': 'malicious'},
            'virustotal': {'detected_urls': 8}
        }
        
        # Mock the enrich_ip method
        self.threat_intel.enrich_ip = MagicMock(return_value=enrichment)
        
        # Check if the IP is malicious
        result = self.threat_intel.is_malicious_ip('192.168.1.1')
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Test with a non-malicious IP
        enrichment = {
            'abuseipdb': {'confidence_score': 0},
            'otx': {'reputation': 'good'},
            'virustotal': {'detected_urls': 0}
        }
        self.threat_intel.enrich_ip = MagicMock(return_value=enrichment)
        result = self.threat_intel.is_malicious_ip('192.168.1.2')
        self.assertFalse(result)
    
    def test_is_malicious_domain(self):
        """Test checking if a domain is malicious."""
        # Create a mock enrichment result
        enrichment = {
            'otx': {'reputation': 'malicious'},
            'virustotal': {'detected_urls': 8}
        }
        
        # Mock the enrich_domain method
        self.threat_intel.enrich_domain = MagicMock(return_value=enrichment)
        
        # Check if the domain is malicious
        result = self.threat_intel.is_malicious_domain('example.com')
        
        # Check that the result is correct
        self.assertTrue(result)
        
        # Test with a non-malicious domain
        enrichment = {
            'otx': {'reputation': 'good'},
            'virustotal': {'detected_urls': 0}
        }
        self.threat_intel.enrich_domain = MagicMock(return_value=enrichment)
        result = self.threat_intel.is_malicious_domain('example.org')
        self.assertFalse(result)
    
    def test_get_cached_data(self):
        """Test getting cached data."""
        # Create a cache file
        cache_data = {'test': 'data'}
        cache_file = os.path.join(self.temp_dir, 'ip_192.168.1.1.json')
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
        
        # Get cached data
        result = self.threat_intel._get_cached_data('ip', '192.168.1.1')
        
        # Check that the result is correct
        self.assertEqual(result, cache_data)
    
    def test_save_to_cache(self):
        """Test saving data to cache."""
        # Save data to cache
        cache_data = {'test': 'data'}
        self.threat_intel._save_to_cache('ip', '192.168.1.1', cache_data)
        
        # Check that the data was saved correctly
        cache_file = os.path.join(self.temp_dir, 'ip_192.168.1.1.json')
        with open(cache_file, 'r') as f:
            result = json.load(f)
        
        self.assertEqual(result, cache_data)


class TestAbuseIPDBClient(unittest.TestCase):
    """Test the AbuseIPDBClient class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create an AbuseIPDBClient object
        self.client = AbuseIPDBClient('test_api_key')
    
    @patch('requests.get')
    def test_check_ip(self, mock_get):
        """Test checking an IP address."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'abuseConfidenceScore': 90,
                'countryCode': 'US',
                'domain': 'example.com',
                'isp': 'Example ISP',
                'usageType': 'Data Center',
                'totalReports': 10
            }
        }
        mock_get.return_value = mock_response
        
        # Check an IP address
        result = self.client.check_ip('192.168.1.1')
        
        # Check that the result is correct
        self.assertEqual(result['abuseConfidenceScore'], 90)
        self.assertEqual(result['countryCode'], 'US')
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['isp'], 'Example ISP')
        self.assertEqual(result['usageType'], 'Data Center')
        self.assertEqual(result['reports'], 10)
    
    @patch('requests.get')
    def test_check_ip_error(self, mock_get):
        """Test checking an IP address with an error."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        # Check an IP address
        result = self.client.check_ip('192.168.1.1')
        
        # Check that the result is an empty dictionary
        self.assertEqual(result, {})


class TestOTXClient(unittest.TestCase):
    """Test the OTXClient class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create an OTXClient object
        with patch('src.threat_intel.otx_client.OTXv2'):
            self.client = OTXClient('test_api_key')
    
    @patch('src.threat_intel.otx_client.OTXv2.get_indicator_details_by_section')
    def test_get_ip_reputation(self, mock_get_details):
        """Test getting IP reputation."""
        # Mock the API response
        mock_get_details.side_effect = [
            {'reputation': {'reputation': 'malicious'}},
            {'pulse_info': {'count': 5}},
            {'malware': {'samples': [{'hash': 'hash1'}, {'hash': 'hash2'}]}},
            {'url_list': {'url_list': [{'url': 'url1'}, {'url': 'url2'}, {'url': 'url3'}]}}
        ]
        
        # Get IP reputation
        result = self.client.get_ip_reputation('192.168.1.1')
        
        # Check that the result is correct
        self.assertEqual(result['reputation'], 'malicious')
        self.assertEqual(result['pulses'], 5)
        self.assertEqual(result['malware_samples'], 2)
        self.assertEqual(result['url_samples'], 3)
    
    @patch('src.threat_intel.otx_client.OTXv2.get_indicator_details_by_section')
    def test_get_domain_reputation(self, mock_get_details):
        """Test getting domain reputation."""
        # Mock the API response
        mock_get_details.side_effect = [
            {'reputation': {'reputation': 'malicious'}},
            {'pulse_info': {'count': 5}},
            {'malware': {'samples': [{'hash': 'hash1'}, {'hash': 'hash2'}]}},
            {'url_list': {'url_list': [{'url': 'url1'}, {'url': 'url2'}, {'url': 'url3'}]}}
        ]
        
        # Get domain reputation
        result = self.client.get_domain_reputation('example.com')
        
        # Check that the result is correct
        self.assertEqual(result['reputation'], 'malicious')
        self.assertEqual(result['pulses'], 5)
        self.assertEqual(result['malware_samples'], 2)
        self.assertEqual(result['url_samples'], 3)


class TestVirusTotalClient(unittest.TestCase):
    """Test the VirusTotalClient class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a VirusTotalClient object
        with patch('src.threat_intel.virustotal_client.vt'):
            self.client = VirusTotalClient('test_api_key')
    
    @patch('src.threat_intel.virustotal_client.vt.Client.get_object')
    def test_get_ip_report(self, mock_get_object):
        """Test getting an IP report."""
        # Mock the API response
        mock_ip_obj = MagicMock()
        mock_ip_obj.last_analysis_stats = {'malicious': 8, 'suspicious': 2}
        mock_ip_obj.last_analysis_results = {'engine1': {'category': 'malicious'}, 'engine2': {'category': 'clean'}}
        mock_ip_obj.asn = 12345
        mock_ip_obj.as_owner = 'Example AS'
        mock_ip_obj.country = 'US'
        mock_ip_obj.network = '192.168.0.0/16'
        
        mock_get_object.return_value = mock_ip_obj
        
        # Get IP report
        result = self.client.get_ip_report('192.168.1.1')
        
        # Check that the result is correct
        self.assertEqual(result['detected_urls'], 8)
        self.assertEqual(result['asn'], 12345)
        self.assertEqual(result['as_owner'], 'Example AS')
        self.assertEqual(result['country'], 'US')
        self.assertEqual(result['network'], '192.168.0.0/16')
    
    @patch('src.threat_intel.virustotal_client.vt.Client.get_object')
    def test_get_domain_report(self, mock_get_object):
        """Test getting a domain report."""
        # Mock the API response
        mock_domain_obj = MagicMock()
        mock_domain_obj.last_analysis_stats = {'malicious': 8, 'suspicious': 2}
        mock_domain_obj.last_analysis_results = {'engine1': {'category': 'malicious'}, 'engine2': {'category': 'clean'}}
        mock_domain_obj.categories = {'engine1': 'malware', 'engine2': 'phishing'}
        mock_domain_obj.creation_date = 1609459200  # 2021-01-01
        mock_domain_obj.last_dns_records = [{'type': 'A', 'value': '192.168.1.1'}]
        
        mock_get_object.return_value = mock_domain_obj
        
        # Get domain report
        result = self.client.get_domain_report('example.com')
        
        # Check that the result is correct
        self.assertEqual(result['detected_urls'], 8)
        self.assertEqual(result['categories'], ['malware', 'phishing'])
        self.assertEqual(result['creation_date'], 1609459200)
        self.assertEqual(result['dns_records'], [{'type': 'A', 'value': '192.168.1.1'}])


if __name__ == '__main__':
    unittest.main()