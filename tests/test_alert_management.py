#!/usr/bin/env python
# SentinelX Alert Management Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
from datetime import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.alert.alert_manager import AlertManager, Alert
from src.alert.alert_storage import AlertStorage, JSONAlertStorage, SQLiteAlertStorage


class TestAlert(unittest.TestCase):
    """Test the Alert class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create an Alert object
        self.alert_data = {
            'id': '12345',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'alert_type': 'port_scan',
            'severity': 'high',
            'description': 'Port scan detected',
            'raw_data': {'packet_count': 100, 'port_count': 20},
            'status': 'new'
        }
        self.alert = Alert(**self.alert_data)
    
    def test_alert_creation(self):
        """Test creating an Alert object."""
        # Check that the Alert object was created correctly
        self.assertEqual(self.alert.id, '12345')
        self.assertEqual(self.alert.source_ip, '192.168.1.1')
        self.assertEqual(self.alert.destination_ip, '192.168.1.2')
        self.assertEqual(self.alert.source_port, 12345)
        self.assertEqual(self.alert.destination_port, 80)
        self.assertEqual(self.alert.protocol, 'TCP')
        self.assertEqual(self.alert.alert_type, 'port_scan')
        self.assertEqual(self.alert.severity, 'high')
        self.assertEqual(self.alert.description, 'Port scan detected')
        self.assertEqual(self.alert.raw_data, {'packet_count': 100, 'port_count': 20})
        self.assertEqual(self.alert.status, 'new')
    
    def test_to_dict(self):
        """Test converting an Alert object to a dictionary."""
        # Convert the Alert object to a dictionary
        alert_dict = self.alert.to_dict()
        
        # Check that the dictionary is correct
        self.assertEqual(alert_dict['id'], '12345')
        self.assertEqual(alert_dict['source_ip'], '192.168.1.1')
        self.assertEqual(alert_dict['destination_ip'], '192.168.1.2')
        self.assertEqual(alert_dict['source_port'], 12345)
        self.assertEqual(alert_dict['destination_port'], 80)
        self.assertEqual(alert_dict['protocol'], 'TCP')
        self.assertEqual(alert_dict['alert_type'], 'port_scan')
        self.assertEqual(alert_dict['severity'], 'high')
        self.assertEqual(alert_dict['description'], 'Port scan detected')
        self.assertEqual(alert_dict['raw_data'], {'packet_count': 100, 'port_count': 20})
        self.assertEqual(alert_dict['status'], 'new')
    
    def test_from_dict(self):
        """Test creating an Alert object from a dictionary."""
        # Create an Alert object from a dictionary
        alert = Alert.from_dict(self.alert_data)
        
        # Check that the Alert object was created correctly
        self.assertEqual(alert.id, '12345')
        self.assertEqual(alert.source_ip, '192.168.1.1')
        self.assertEqual(alert.destination_ip, '192.168.1.2')
        self.assertEqual(alert.source_port, 12345)
        self.assertEqual(alert.destination_port, 80)
        self.assertEqual(alert.protocol, 'TCP')
        self.assertEqual(alert.alert_type, 'port_scan')
        self.assertEqual(alert.severity, 'high')
        self.assertEqual(alert.description, 'Port scan detected')
        self.assertEqual(alert.raw_data, {'packet_count': 100, 'port_count': 20})
        self.assertEqual(alert.status, 'new')
    
    def test_update_status(self):
        """Test updating the status of an Alert object."""
        # Update the status
        self.alert.update_status('acknowledged')
        
        # Check that the status was updated correctly
        self.assertEqual(self.alert.status, 'acknowledged')
    
    def test_add_enrichment(self):
        """Test adding enrichment data to an Alert object."""
        # Add enrichment data
        enrichment_data = {
            'ip_reputation': 'malicious',
            'country': 'US',
            'asn': 12345
        }
        self.alert.add_enrichment(enrichment_data)
        
        # Check that the enrichment data was added correctly
        self.assertEqual(self.alert.enrichment, enrichment_data)
    
    def test_add_analysis(self):
        """Test adding analysis data to an Alert object."""
        # Add analysis data
        analysis_data = {
            'mitre_techniques': ['T1046'],
            'cve_ids': ['CVE-2021-1234'],
            'explanation': 'This is a port scan attack'
        }
        self.alert.add_analysis(analysis_data)
        
        # Check that the analysis data was added correctly
        self.assertEqual(self.alert.analysis, analysis_data)


class TestJSONAlertStorage(unittest.TestCase):
    """Test the JSONAlertStorage class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for alert files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a JSONAlertStorage object
        self.storage = JSONAlertStorage(self.temp_dir)
        
        # Create an Alert object
        self.alert_data = {
            'id': '12345',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'alert_type': 'port_scan',
            'severity': 'high',
            'description': 'Port scan detected',
            'raw_data': {'packet_count': 100, 'port_count': 20},
            'status': 'new'
        }
        self.alert = Alert(**self.alert_data)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    def test_save_alert(self):
        """Test saving an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Check that the alert file was created
        alert_file = os.path.join(self.temp_dir, f'{self.alert.id}.json')
        self.assertTrue(os.path.exists(alert_file))
        
        # Check that the alert was saved correctly
        with open(alert_file, 'r') as f:
            saved_alert = json.load(f)
        
        self.assertEqual(saved_alert['id'], '12345')
        self.assertEqual(saved_alert['source_ip'], '192.168.1.1')
        self.assertEqual(saved_alert['alert_type'], 'port_scan')
    
    def test_get_alert(self):
        """Test getting an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Get the alert
        alert = self.storage.get_alert('12345')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(alert.id, '12345')
        self.assertEqual(alert.source_ip, '192.168.1.1')
        self.assertEqual(alert.alert_type, 'port_scan')
    
    def test_get_all_alerts(self):
        """Test getting all alerts."""
        # Save multiple alerts
        self.storage.save_alert(self.alert)
        
        # Create and save another alert
        alert_data2 = self.alert_data.copy()
        alert_data2['id'] = '67890'
        alert_data2['source_ip'] = '192.168.1.3'
        alert2 = Alert(**alert_data2)
        self.storage.save_alert(alert2)
        
        # Get all alerts
        alerts = self.storage.get_all_alerts()
        
        # Check that all alerts were retrieved correctly
        self.assertEqual(len(alerts), 2)
        self.assertTrue(any(a.id == '12345' for a in alerts))
        self.assertTrue(any(a.id == '67890' for a in alerts))
    
    def test_update_alert(self):
        """Test updating an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Update the alert
        self.alert.update_status('acknowledged')
        self.storage.update_alert(self.alert)
        
        # Get the updated alert
        updated_alert = self.storage.get_alert('12345')
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert.status, 'acknowledged')
    
    def test_delete_alert(self):
        """Test deleting an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Delete the alert
        self.storage.delete_alert('12345')
        
        # Check that the alert file was deleted
        alert_file = os.path.join(self.temp_dir, '12345.json')
        self.assertFalse(os.path.exists(alert_file))
        
        # Check that the alert cannot be retrieved
        alert = self.storage.get_alert('12345')
        self.assertIsNone(alert)


class TestSQLiteAlertStorage(unittest.TestCase):
    """Test the SQLiteAlertStorage class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for the database file
        self.temp_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.temp_dir, 'alerts.db')
        
        # Create a SQLiteAlertStorage object
        self.storage = SQLiteAlertStorage(self.db_file)
        
        # Create an Alert object
        self.alert_data = {
            'id': '12345',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'alert_type': 'port_scan',
            'severity': 'high',
            'description': 'Port scan detected',
            'raw_data': {'packet_count': 100, 'port_count': 20},
            'status': 'new'
        }
        self.alert = Alert(**self.alert_data)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Close the database connection
        self.storage.conn.close()
        
        # Remove the database file
        os.unlink(self.db_file)
        os.rmdir(self.temp_dir)
    
    def test_save_alert(self):
        """Test saving an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Check that the alert was saved correctly
        cursor = self.storage.conn.cursor()
        cursor.execute('SELECT * FROM alerts WHERE id = ?', (self.alert.id,))
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[0], '12345')  # id
        self.assertEqual(row[2], '192.168.1.1')  # source_ip
        self.assertEqual(row[7], 'port_scan')  # alert_type
    
    def test_get_alert(self):
        """Test getting an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Get the alert
        alert = self.storage.get_alert('12345')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(alert.id, '12345')
        self.assertEqual(alert.source_ip, '192.168.1.1')
        self.assertEqual(alert.alert_type, 'port_scan')
    
    def test_get_all_alerts(self):
        """Test getting all alerts."""
        # Save multiple alerts
        self.storage.save_alert(self.alert)
        
        # Create and save another alert
        alert_data2 = self.alert_data.copy()
        alert_data2['id'] = '67890'
        alert_data2['source_ip'] = '192.168.1.3'
        alert2 = Alert(**alert_data2)
        self.storage.save_alert(alert2)
        
        # Get all alerts
        alerts = self.storage.get_all_alerts()
        
        # Check that all alerts were retrieved correctly
        self.assertEqual(len(alerts), 2)
        self.assertTrue(any(a.id == '12345' for a in alerts))
        self.assertTrue(any(a.id == '67890' for a in alerts))
    
    def test_update_alert(self):
        """Test updating an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Update the alert
        self.alert.update_status('acknowledged')
        self.storage.update_alert(self.alert)
        
        # Get the updated alert
        updated_alert = self.storage.get_alert('12345')
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert.status, 'acknowledged')
    
    def test_delete_alert(self):
        """Test deleting an alert."""
        # Save the alert
        self.storage.save_alert(self.alert)
        
        # Delete the alert
        self.storage.delete_alert('12345')
        
        # Check that the alert cannot be retrieved
        alert = self.storage.get_alert('12345')
        self.assertIsNone(alert)


class TestAlertManager(unittest.TestCase):
    """Test the AlertManager class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a mock AlertStorage object
        self.mock_storage = MagicMock(spec=AlertStorage)
        
        # Create an AlertManager object
        self.alert_manager = AlertManager(self.mock_storage)
        
        # Create an Alert object
        self.alert_data = {
            'id': '12345',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.2',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 'TCP',
            'alert_type': 'port_scan',
            'severity': 'high',
            'description': 'Port scan detected',
            'raw_data': {'packet_count': 100, 'port_count': 20},
            'status': 'new'
        }
        self.alert = Alert(**self.alert_data)
    
    def test_create_alert(self):
        """Test creating an alert."""
        # Create an alert
        alert = self.alert_manager.create_alert(
            source_ip='192.168.1.1',
            destination_ip='192.168.1.2',
            source_port=12345,
            destination_port=80,
            protocol='TCP',
            alert_type='port_scan',
            severity='high',
            description='Port scan detected',
            raw_data={'packet_count': 100, 'port_count': 20}
        )
        
        # Check that the alert was created correctly
        self.assertEqual(alert.source_ip, '192.168.1.1')
        self.assertEqual(alert.destination_ip, '192.168.1.2')
        self.assertEqual(alert.source_port, 12345)
        self.assertEqual(alert.destination_port, 80)
        self.assertEqual(alert.protocol, 'TCP')
        self.assertEqual(alert.alert_type, 'port_scan')
        self.assertEqual(alert.severity, 'high')
        self.assertEqual(alert.description, 'Port scan detected')
        self.assertEqual(alert.raw_data, {'packet_count': 100, 'port_count': 20})
        self.assertEqual(alert.status, 'new')
        
        # Check that the alert was saved
        self.mock_storage.save_alert.assert_called_once()
    
    def test_get_alert(self):
        """Test getting an alert."""
        # Mock the storage.get_alert method
        self.mock_storage.get_alert.return_value = self.alert
        
        # Get the alert
        alert = self.alert_manager.get_alert('12345')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(alert.id, '12345')
        self.assertEqual(alert.source_ip, '192.168.1.1')
        self.assertEqual(alert.alert_type, 'port_scan')
        
        # Check that the storage.get_alert method was called correctly
        self.mock_storage.get_alert.assert_called_once_with('12345')
    
    def test_get_all_alerts(self):
        """Test getting all alerts."""
        # Mock the storage.get_all_alerts method
        self.mock_storage.get_all_alerts.return_value = [self.alert]
        
        # Get all alerts
        alerts = self.alert_manager.get_all_alerts()
        
        # Check that the alerts were retrieved correctly
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].id, '12345')
        
        # Check that the storage.get_all_alerts method was called correctly
        self.mock_storage.get_all_alerts.assert_called_once()
    
    def test_update_alert_status(self):
        """Test updating an alert status."""
        # Mock the storage.get_alert and storage.update_alert methods
        self.mock_storage.get_alert.return_value = self.alert
        
        # Update the alert status
        updated_alert = self.alert_manager.update_alert_status('12345', 'acknowledged')
        
        # Check that the alert status was updated correctly
        self.assertEqual(updated_alert.status, 'acknowledged')
        
        # Check that the storage methods were called correctly
        self.mock_storage.get_alert.assert_called_once_with('12345')
        self.mock_storage.update_alert.assert_called_once()
    
    def test_add_enrichment(self):
        """Test adding enrichment data to an alert."""
        # Mock the storage.get_alert and storage.update_alert methods
        self.mock_storage.get_alert.return_value = self.alert
        
        # Add enrichment data
        enrichment_data = {
            'ip_reputation': 'malicious',
            'country': 'US',
            'asn': 12345
        }
        updated_alert = self.alert_manager.add_enrichment('12345', enrichment_data)
        
        # Check that the enrichment data was added correctly
        self.assertEqual(updated_alert.enrichment, enrichment_data)
        
        # Check that the storage methods were called correctly
        self.mock_storage.get_alert.assert_called_once_with('12345')
        self.mock_storage.update_alert.assert_called_once()
    
    def test_add_analysis(self):
        """Test adding analysis data to an alert."""
        # Mock the storage.get_alert and storage.update_alert methods
        self.mock_storage.get_alert.return_value = self.alert
        
        # Add analysis data
        analysis_data = {
            'mitre_techniques': ['T1046'],
            'cve_ids': ['CVE-2021-1234'],
            'explanation': 'This is a port scan attack'
        }
        updated_alert = self.alert_manager.add_analysis('12345', analysis_data)
        
        # Check that the analysis data was added correctly
        self.assertEqual(updated_alert.analysis, analysis_data)
        
        # Check that the storage methods were called correctly
        self.mock_storage.get_alert.assert_called_once_with('12345')
        self.mock_storage.update_alert.assert_called_once()
    
    def test_delete_alert(self):
        """Test deleting an alert."""
        # Delete the alert
        self.alert_manager.delete_alert('12345')
        
        # Check that the storage.delete_alert method was called correctly
        self.mock_storage.delete_alert.assert_called_once_with('12345')


if __name__ == '__main__':
    unittest.main()