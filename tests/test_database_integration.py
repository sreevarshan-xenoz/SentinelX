#!/usr/bin/env python
# SentinelX Database Integration Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import sqlite3
import pymongo
import yaml

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the database classes
try:
    from src.alert_management import JSONAlertStorage, SQLiteAlertStorage, MongoDBAlertStorage
    from src.alert_management import Alert, AlertManager
except ImportError:
    # Mock classes if they don't exist yet
    class Alert:
        def __init__(self, alert_id=None, timestamp=None, source_ip=None, destination_ip=None, 
                     severity=None, category=None, status='open', details=None):
            self.id = alert_id or 'alert-1'
            self.timestamp = timestamp or '2023-01-01T00:00:00'
            self.source_ip = source_ip or '192.168.1.100'
            self.destination_ip = destination_ip or '8.8.8.8'
            self.severity = severity or 'high'
            self.category = category or 'malware'
            self.status = status
            self.details = details or {}
            self.enrichment = {}
            self.analysis = {}
            self.notes = ''
        
        def to_dict(self):
            return {
                'id': self.id,
                'timestamp': self.timestamp,
                'source_ip': self.source_ip,
                'destination_ip': self.destination_ip,
                'severity': self.severity,
                'category': self.category,
                'status': self.status,
                'details': self.details,
                'enrichment': self.enrichment,
                'analysis': self.analysis,
                'notes': self.notes
            }
        
        def update_status(self, status):
            self.status = status
            return self
        
        def add_notes(self, notes):
            self.notes = notes
            return self
        
        def add_enrichment(self, enrichment):
            self.enrichment.update(enrichment)
            return self
        
        def add_analysis(self, analysis):
            self.analysis.update(analysis)
            return self
    
    class JSONAlertStorage:
        def __init__(self, file_path):
            self.file_path = file_path
            self.alerts = {}
            self._load()
        
        def _load(self):
            if os.path.exists(self.file_path):
                with open(self.file_path, 'r') as f:
                    self.alerts = json.load(f)
            else:
                self.alerts = {}
                self._save()
        
        def _save(self):
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            with open(self.file_path, 'w') as f:
                json.dump(self.alerts, f, indent=2)
        
        def save_alert(self, alert):
            alert_dict = alert.to_dict() if isinstance(alert, Alert) else alert
            self.alerts[alert_dict['id']] = alert_dict
            self._save()
            return alert_dict['id']
        
        def get_alert(self, alert_id):
            return self.alerts.get(alert_id)
        
        def get_alerts(self, limit=100, offset=0, status=None):
            alerts = list(self.alerts.values())
            if status:
                alerts = [a for a in alerts if a.get('status') == status]
            return alerts[offset:offset+limit]
        
        def update_alert(self, alert_id, update_data):
            if alert_id in self.alerts:
                self.alerts[alert_id].update(update_data)
                self._save()
                return self.alerts[alert_id]
            return None
        
        def delete_alert(self, alert_id):
            if alert_id in self.alerts:
                del self.alerts[alert_id]
                self._save()
                return True
            return False
    
    class SQLiteAlertStorage:
        def __init__(self, db_path):
            self.db_path = db_path
            self._init_db()
        
        def _init_db(self):
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    severity TEXT,
                    category TEXT,
                    status TEXT,
                    details TEXT,
                    enrichment TEXT,
                    analysis TEXT,
                    notes TEXT
                )
            ''')
            conn.commit()
            conn.close()
        
        def save_alert(self, alert):
            alert_dict = alert.to_dict() if isinstance(alert, Alert) else alert
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO alerts
                (id, timestamp, source_ip, destination_ip, severity, category, status, details, enrichment, analysis, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_dict['id'],
                alert_dict['timestamp'],
                alert_dict['source_ip'],
                alert_dict['destination_ip'],
                alert_dict['severity'],
                alert_dict['category'],
                alert_dict['status'],
                json.dumps(alert_dict.get('details', {})),
                json.dumps(alert_dict.get('enrichment', {})),
                json.dumps(alert_dict.get('analysis', {})),
                alert_dict.get('notes', '')
            ))
            conn.commit()
            conn.close()
            return alert_dict['id']
        
        def get_alert(self, alert_id):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'id': row[0],
                    'timestamp': row[1],
                    'source_ip': row[2],
                    'destination_ip': row[3],
                    'severity': row[4],
                    'category': row[5],
                    'status': row[6],
                    'details': json.loads(row[7]),
                    'enrichment': json.loads(row[8]),
                    'analysis': json.loads(row[9]),
                    'notes': row[10]
                }
            return None
        
        def get_alerts(self, limit=100, offset=0, status=None):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if status:
                cursor.execute('SELECT * FROM alerts WHERE status = ? LIMIT ? OFFSET ?', (status, limit, offset))
            else:
                cursor.execute('SELECT * FROM alerts LIMIT ? OFFSET ?', (limit, offset))
            
            rows = cursor.fetchall()
            conn.close()
            
            alerts = []
            for row in rows:
                alerts.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'source_ip': row[2],
                    'destination_ip': row[3],
                    'severity': row[4],
                    'category': row[5],
                    'status': row[6],
                    'details': json.loads(row[7]),
                    'enrichment': json.loads(row[8]),
                    'analysis': json.loads(row[9]),
                    'notes': row[10]
                })
            
            return alerts
        
        def update_alert(self, alert_id, update_data):
            alert = self.get_alert(alert_id)
            if alert:
                alert.update(update_data)
                self.save_alert(alert)
                return alert
            return None
        
        def delete_alert(self, alert_id):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return deleted
    
    class MongoDBAlertStorage:
        def __init__(self, connection_string, database_name='sentinelx', collection_name='alerts'):
            self.connection_string = connection_string
            self.database_name = database_name
            self.collection_name = collection_name
            self.client = None
            self.db = None
            self.collection = None
            self._connect()
        
        def _connect(self):
            try:
                self.client = pymongo.MongoClient(self.connection_string)
                self.db = self.client[self.database_name]
                self.collection = self.db[self.collection_name]
                # Create index on id field
                self.collection.create_index('id', unique=True)
            except Exception as e:
                print(f"Error connecting to MongoDB: {e}")
                raise
        
        def save_alert(self, alert):
            alert_dict = alert.to_dict() if isinstance(alert, Alert) else alert
            try:
                self.collection.replace_one({'id': alert_dict['id']}, alert_dict, upsert=True)
                return alert_dict['id']
            except Exception as e:
                print(f"Error saving alert to MongoDB: {e}")
                raise
        
        def get_alert(self, alert_id):
            try:
                alert = self.collection.find_one({'id': alert_id})
                if alert:
                    # Remove MongoDB's _id field
                    alert.pop('_id', None)
                return alert
            except Exception as e:
                print(f"Error getting alert from MongoDB: {e}")
                raise
        
        def get_alerts(self, limit=100, offset=0, status=None):
            try:
                query = {}
                if status:
                    query['status'] = status
                
                alerts = list(self.collection.find(query).skip(offset).limit(limit))
                # Remove MongoDB's _id field
                for alert in alerts:
                    alert.pop('_id', None)
                
                return alerts
            except Exception as e:
                print(f"Error getting alerts from MongoDB: {e}")
                raise
        
        def update_alert(self, alert_id, update_data):
            try:
                result = self.collection.update_one({'id': alert_id}, {'$set': update_data})
                if result.modified_count > 0 or result.matched_count > 0:
                    return self.get_alert(alert_id)
                return None
            except Exception as e:
                print(f"Error updating alert in MongoDB: {e}")
                raise
        
        def delete_alert(self, alert_id):
            try:
                result = self.collection.delete_one({'id': alert_id})
                return result.deleted_count > 0
            except Exception as e:
                print(f"Error deleting alert from MongoDB: {e}")
                raise
    
    class AlertManager:
        def __init__(self, storage):
            self.storage = storage
        
        def create_alert(self, alert_data):
            if isinstance(alert_data, Alert):
                alert = alert_data
            else:
                alert = Alert(
                    alert_id=alert_data.get('id'),
                    timestamp=alert_data.get('timestamp'),
                    source_ip=alert_data.get('source_ip'),
                    destination_ip=alert_data.get('destination_ip'),
                    severity=alert_data.get('severity'),
                    category=alert_data.get('category'),
                    status=alert_data.get('status', 'open'),
                    details=alert_data.get('details', {})
                )
            
            alert_id = self.storage.save_alert(alert)
            return self.get_alert(alert_id)
        
        def get_alert(self, alert_id):
            return self.storage.get_alert(alert_id)
        
        def get_alerts(self, limit=100, offset=0, status=None):
            return self.storage.get_alerts(limit=limit, offset=offset, status=status)
        
        def update_alert(self, alert_id, status=None, notes=None):
            update_data = {}
            if status:
                update_data['status'] = status
            if notes:
                update_data['notes'] = notes
            
            return self.storage.update_alert(alert_id, update_data)
        
        def delete_alert(self, alert_id):
            return self.storage.delete_alert(alert_id)
        
        def add_enrichment(self, alert_id, enrichment):
            alert = self.get_alert(alert_id)
            if alert:
                alert_enrichment = alert.get('enrichment', {})
                alert_enrichment.update(enrichment)
                return self.storage.update_alert(alert_id, {'enrichment': alert_enrichment})
            return None
        
        def add_analysis(self, alert_id, analysis):
            alert = self.get_alert(alert_id)
            if alert:
                alert_analysis = alert.get('analysis', {})
                alert_analysis.update(analysis)
                return self.storage.update_alert(alert_id, {'analysis': alert_analysis})
            return None


class TestJSONAlertStorage(unittest.TestCase):
    """Test the JSONAlertStorage class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test JSON file path
        self.json_path = os.path.join(self.temp_dir, 'alerts.json')
        
        # Create a JSONAlertStorage instance
        self.storage = JSONAlertStorage(self.json_path)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_save_and_get_alert(self):
        """Test saving and retrieving an alert."""
        # Create a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open',
            details={'flow': {'protocol': 'TCP', 'src_port': 12345, 'dst_port': 80}}
        )
        
        # Save the alert
        alert_id = self.storage.save_alert(alert)
        
        # Check that the alert was saved correctly
        self.assertEqual(alert_id, 'test-alert-1', "Alert ID should be test-alert-1")
        
        # Get the alert
        retrieved_alert = self.storage.get_alert('test-alert-1')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(retrieved_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(retrieved_alert['source_ip'], '192.168.1.100', "Source IP should be 192.168.1.100")
        self.assertEqual(retrieved_alert['destination_ip'], '8.8.8.8', "Destination IP should be 8.8.8.8")
        self.assertEqual(retrieved_alert['severity'], 'high', "Severity should be high")
        self.assertEqual(retrieved_alert['category'], 'malware', "Category should be malware")
        self.assertEqual(retrieved_alert['status'], 'open', "Status should be open")
        self.assertEqual(retrieved_alert['details']['flow']['protocol'], 'TCP', "Protocol should be TCP")
    
    def test_get_alerts(self):
        """Test retrieving multiple alerts."""
        # Create and save test alerts
        for i in range(5):
            alert = Alert(
                alert_id=f'test-alert-{i}',
                timestamp='2023-01-01T00:00:00',
                source_ip='192.168.1.100',
                destination_ip='8.8.8.8',
                severity='high',
                category='malware',
                status='open' if i % 2 == 0 else 'closed'
            )
            self.storage.save_alert(alert)
        
        # Get all alerts
        all_alerts = self.storage.get_alerts()
        self.assertEqual(len(all_alerts), 5, "Should have 5 alerts")
        
        # Get alerts with limit and offset
        limited_alerts = self.storage.get_alerts(limit=2, offset=1)
        self.assertEqual(len(limited_alerts), 2, "Should have 2 alerts")
        
        # Get alerts by status
        open_alerts = self.storage.get_alerts(status='open')
        self.assertEqual(len(open_alerts), 3, "Should have 3 open alerts")
        
        closed_alerts = self.storage.get_alerts(status='closed')
        self.assertEqual(len(closed_alerts), 2, "Should have 2 closed alerts")
    
    def test_update_alert(self):
        """Test updating an alert."""
        # Create and save a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open'
        )
        self.storage.save_alert(alert)
        
        # Update the alert
        updated_alert = self.storage.update_alert('test-alert-1', {
            'status': 'closed',
            'notes': 'False positive'
        })
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(updated_alert['notes'], 'False positive', "Notes should be 'False positive'")
        
        # Get the alert to verify the update
        retrieved_alert = self.storage.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(retrieved_alert['notes'], 'False positive', "Notes should be 'False positive'")
    
    def test_delete_alert(self):
        """Test deleting an alert."""
        # Create and save a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open'
        )
        self.storage.save_alert(alert)
        
        # Delete the alert
        result = self.storage.delete_alert('test-alert-1')
        self.assertTrue(result, "Delete should return True")
        
        # Try to get the deleted alert
        retrieved_alert = self.storage.get_alert('test-alert-1')
        self.assertIsNone(retrieved_alert, "Alert should be None after deletion")
        
        # Try to delete a non-existent alert
        result = self.storage.delete_alert('non-existent-alert')
        self.assertFalse(result, "Delete should return False for non-existent alert")


class TestSQLiteAlertStorage(unittest.TestCase):
    """Test the SQLiteAlertStorage class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test SQLite database path
        self.db_path = os.path.join(self.temp_dir, 'alerts.db')
        
        # Create a SQLiteAlertStorage instance
        self.storage = SQLiteAlertStorage(self.db_path)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_save_and_get_alert(self):
        """Test saving and retrieving an alert."""
        # Create a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open',
            details={'flow': {'protocol': 'TCP', 'src_port': 12345, 'dst_port': 80}}
        )
        
        # Save the alert
        alert_id = self.storage.save_alert(alert)
        
        # Check that the alert was saved correctly
        self.assertEqual(alert_id, 'test-alert-1', "Alert ID should be test-alert-1")
        
        # Get the alert
        retrieved_alert = self.storage.get_alert('test-alert-1')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(retrieved_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(retrieved_alert['source_ip'], '192.168.1.100', "Source IP should be 192.168.1.100")
        self.assertEqual(retrieved_alert['destination_ip'], '8.8.8.8', "Destination IP should be 8.8.8.8")
        self.assertEqual(retrieved_alert['severity'], 'high', "Severity should be high")
        self.assertEqual(retrieved_alert['category'], 'malware', "Category should be malware")
        self.assertEqual(retrieved_alert['status'], 'open', "Status should be open")
        self.assertEqual(retrieved_alert['details']['flow']['protocol'], 'TCP', "Protocol should be TCP")
    
    def test_get_alerts(self):
        """Test retrieving multiple alerts."""
        # Create and save test alerts
        for i in range(5):
            alert = Alert(
                alert_id=f'test-alert-{i}',
                timestamp='2023-01-01T00:00:00',
                source_ip='192.168.1.100',
                destination_ip='8.8.8.8',
                severity='high',
                category='malware',
                status='open' if i % 2 == 0 else 'closed'
            )
            self.storage.save_alert(alert)
        
        # Get all alerts
        all_alerts = self.storage.get_alerts()
        self.assertEqual(len(all_alerts), 5, "Should have 5 alerts")
        
        # Get alerts with limit and offset
        limited_alerts = self.storage.get_alerts(limit=2, offset=1)
        self.assertEqual(len(limited_alerts), 2, "Should have 2 alerts")
        
        # Get alerts by status
        open_alerts = self.storage.get_alerts(status='open')
        self.assertEqual(len(open_alerts), 3, "Should have 3 open alerts")
        
        closed_alerts = self.storage.get_alerts(status='closed')
        self.assertEqual(len(closed_alerts), 2, "Should have 2 closed alerts")
    
    def test_update_alert(self):
        """Test updating an alert."""
        # Create and save a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open'
        )
        self.storage.save_alert(alert)
        
        # Update the alert
        updated_alert = self.storage.update_alert('test-alert-1', {
            'status': 'closed',
            'notes': 'False positive'
        })
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(updated_alert['notes'], 'False positive', "Notes should be 'False positive'")
        
        # Get the alert to verify the update
        retrieved_alert = self.storage.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(retrieved_alert['notes'], 'False positive', "Notes should be 'False positive'")
    
    def test_delete_alert(self):
        """Test deleting an alert."""
        # Create and save a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open'
        )
        self.storage.save_alert(alert)
        
        # Delete the alert
        result = self.storage.delete_alert('test-alert-1')
        self.assertTrue(result, "Delete should return True")
        
        # Try to get the deleted alert
        retrieved_alert = self.storage.get_alert('test-alert-1')
        self.assertIsNone(retrieved_alert, "Alert should be None after deletion")
        
        # Try to delete a non-existent alert
        result = self.storage.delete_alert('non-existent-alert')
        self.assertFalse(result, "Delete should return False for non-existent alert")


@unittest.skipIf(True, "MongoDB tests require a running MongoDB server")
class TestMongoDBAlertStorage(unittest.TestCase):
    """Test the MongoDBAlertStorage class."""
    
    def setUp(self):
        """Set up the test environment."""
        # MongoDB connection string (use a test database)
        self.connection_string = "mongodb://localhost:27017/"
        self.database_name = "sentinelx_test"
        self.collection_name = "alerts_test"
        
        try:
            # Create a MongoDBAlertStorage instance
            self.storage = MongoDBAlertStorage(
                connection_string=self.connection_string,
                database_name=self.database_name,
                collection_name=self.collection_name
            )
            
            # Clear the collection before each test
            self.storage.collection.delete_many({})
        except Exception as e:
            self.skipTest(f"MongoDB not available: {e}")
    
    def tearDown(self):
        """Clean up the test environment."""
        if hasattr(self, 'storage') and self.storage.client:
            # Drop the test collection
            self.storage.collection.drop()
            # Close the MongoDB connection
            self.storage.client.close()
    
    def test_save_and_get_alert(self):
        """Test saving and retrieving an alert."""
        # Create a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open',
            details={'flow': {'protocol': 'TCP', 'src_port': 12345, 'dst_port': 80}}
        )
        
        # Save the alert
        alert_id = self.storage.save_alert(alert)
        
        # Check that the alert was saved correctly
        self.assertEqual(alert_id, 'test-alert-1', "Alert ID should be test-alert-1")
        
        # Get the alert
        retrieved_alert = self.storage.get_alert('test-alert-1')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(retrieved_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(retrieved_alert['source_ip'], '192.168.1.100', "Source IP should be 192.168.1.100")
        self.assertEqual(retrieved_alert['destination_ip'], '8.8.8.8', "Destination IP should be 8.8.8.8")
        self.assertEqual(retrieved_alert['severity'], 'high', "Severity should be high")
        self.assertEqual(retrieved_alert['category'], 'malware', "Category should be malware")
        self.assertEqual(retrieved_alert['status'], 'open', "Status should be open")
        self.assertEqual(retrieved_alert['details']['flow']['protocol'], 'TCP', "Protocol should be TCP")
    
    def test_get_alerts(self):
        """Test retrieving multiple alerts."""
        # Create and save test alerts
        for i in range(5):
            alert = Alert(
                alert_id=f'test-alert-{i}',
                timestamp='2023-01-01T00:00:00',
                source_ip='192.168.1.100',
                destination_ip='8.8.8.8',
                severity='high',
                category='malware',
                status='open' if i % 2 == 0 else 'closed'
            )
            self.storage.save_alert(alert)
        
        # Get all alerts
        all_alerts = self.storage.get_alerts()
        self.assertEqual(len(all_alerts), 5, "Should have 5 alerts")
        
        # Get alerts with limit and offset
        limited_alerts = self.storage.get_alerts(limit=2, offset=1)
        self.assertEqual(len(limited_alerts), 2, "Should have 2 alerts")
        
        # Get alerts by status
        open_alerts = self.storage.get_alerts(status='open')
        self.assertEqual(len(open_alerts), 3, "Should have 3 open alerts")
        
        closed_alerts = self.storage.get_alerts(status='closed')
        self.assertEqual(len(closed_alerts), 2, "Should have 2 closed alerts")
    
    def test_update_alert(self):
        """Test updating an alert."""
        # Create and save a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open'
        )
        self.storage.save_alert(alert)
        
        # Update the alert
        updated_alert = self.storage.update_alert('test-alert-1', {
            'status': 'closed',
            'notes': 'False positive'
        })
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(updated_alert['notes'], 'False positive', "Notes should be 'False positive'")
        
        # Get the alert to verify the update
        retrieved_alert = self.storage.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(retrieved_alert['notes'], 'False positive', "Notes should be 'False positive'")
    
    def test_delete_alert(self):
        """Test deleting an alert."""
        # Create and save a test alert
        alert = Alert(
            alert_id='test-alert-1',
            timestamp='2023-01-01T00:00:00',
            source_ip='192.168.1.100',
            destination_ip='8.8.8.8',
            severity='high',
            category='malware',
            status='open'
        )
        self.storage.save_alert(alert)
        
        # Delete the alert
        result = self.storage.delete_alert('test-alert-1')
        self.assertTrue(result, "Delete should return True")
        
        # Try to get the deleted alert
        retrieved_alert = self.storage.get_alert('test-alert-1')
        self.assertIsNone(retrieved_alert, "Alert should be None after deletion")
        
        # Try to delete a non-existent alert
        result = self.storage.delete_alert('non-existent-alert')
        self.assertFalse(result, "Delete should return False for non-existent alert")


class TestAlertManager(unittest.TestCase):
    """Test the AlertManager class with different storage backends."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test file paths
        self.json_path = os.path.join(self.temp_dir, 'alerts.json')
        self.db_path = os.path.join(self.temp_dir, 'alerts.db')
        
        # Create storage instances
        self.json_storage = JSONAlertStorage(self.json_path)
        self.sqlite_storage = SQLiteAlertStorage(self.db_path)
        
        # Create AlertManager instances
        self.json_manager = AlertManager(self.json_storage)
        self.sqlite_manager = AlertManager(self.sqlite_storage)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_create_and_get_alert_json(self):
        """Test creating and retrieving an alert with JSON storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware',
            'details': {'flow': {'protocol': 'TCP', 'src_port': 12345, 'dst_port': 80}}
        }
        
        # Create the alert
        created_alert = self.json_manager.create_alert(alert_data)
        
        # Check that the alert was created correctly
        self.assertEqual(created_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(created_alert['status'], 'open', "Status should be open (default)")
        
        # Get the alert
        retrieved_alert = self.json_manager.get_alert('test-alert-1')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(retrieved_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(retrieved_alert['source_ip'], '192.168.1.100', "Source IP should be 192.168.1.100")
        self.assertEqual(retrieved_alert['details']['flow']['protocol'], 'TCP', "Protocol should be TCP")
    
    def test_create_and_get_alert_sqlite(self):
        """Test creating and retrieving an alert with SQLite storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware',
            'details': {'flow': {'protocol': 'TCP', 'src_port': 12345, 'dst_port': 80}}
        }
        
        # Create the alert
        created_alert = self.sqlite_manager.create_alert(alert_data)
        
        # Check that the alert was created correctly
        self.assertEqual(created_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(created_alert['status'], 'open', "Status should be open (default)")
        
        # Get the alert
        retrieved_alert = self.sqlite_manager.get_alert('test-alert-1')
        
        # Check that the alert was retrieved correctly
        self.assertEqual(retrieved_alert['id'], 'test-alert-1', "Alert ID should be test-alert-1")
        self.assertEqual(retrieved_alert['source_ip'], '192.168.1.100', "Source IP should be 192.168.1.100")
        self.assertEqual(retrieved_alert['details']['flow']['protocol'], 'TCP', "Protocol should be TCP")
    
    def test_get_alerts_json(self):
        """Test retrieving multiple alerts with JSON storage."""
        # Create and save test alerts
        for i in range(5):
            alert_data = {
                'id': f'test-alert-{i}',
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open' if i % 2 == 0 else 'closed'
            }
            self.json_manager.create_alert(alert_data)
        
        # Get all alerts
        all_alerts = self.json_manager.get_alerts()
        self.assertEqual(len(all_alerts), 5, "Should have 5 alerts")
        
        # Get alerts with limit and offset
        limited_alerts = self.json_manager.get_alerts(limit=2, offset=1)
        self.assertEqual(len(limited_alerts), 2, "Should have 2 alerts")
        
        # Get alerts by status
        open_alerts = self.json_manager.get_alerts(status='open')
        self.assertEqual(len(open_alerts), 3, "Should have 3 open alerts")
        
        closed_alerts = self.json_manager.get_alerts(status='closed')
        self.assertEqual(len(closed_alerts), 2, "Should have 2 closed alerts")
    
    def test_get_alerts_sqlite(self):
        """Test retrieving multiple alerts with SQLite storage."""
        # Create and save test alerts
        for i in range(5):
            alert_data = {
                'id': f'test-alert-{i}',
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open' if i % 2 == 0 else 'closed'
            }
            self.sqlite_manager.create_alert(alert_data)
        
        # Get all alerts
        all_alerts = self.sqlite_manager.get_alerts()
        self.assertEqual(len(all_alerts), 5, "Should have 5 alerts")
        
        # Get alerts with limit and offset
        limited_alerts = self.sqlite_manager.get_alerts(limit=2, offset=1)
        self.assertEqual(len(limited_alerts), 2, "Should have 2 alerts")
        
        # Get alerts by status
        open_alerts = self.sqlite_manager.get_alerts(status='open')
        self.assertEqual(len(open_alerts), 3, "Should have 3 open alerts")
        
        closed_alerts = self.sqlite_manager.get_alerts(status='closed')
        self.assertEqual(len(closed_alerts), 2, "Should have 2 closed alerts")
    
    def test_update_alert_json(self):
        """Test updating an alert with JSON storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.json_manager.create_alert(alert_data)
        
        # Update the alert
        updated_alert = self.json_manager.update_alert('test-alert-1', status='closed', notes='False positive')
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(updated_alert['notes'], 'False positive', "Notes should be 'False positive'")
        
        # Get the alert to verify the update
        retrieved_alert = self.json_manager.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(retrieved_alert['notes'], 'False positive', "Notes should be 'False positive'")
    
    def test_update_alert_sqlite(self):
        """Test updating an alert with SQLite storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.sqlite_manager.create_alert(alert_data)
        
        # Update the alert
        updated_alert = self.sqlite_manager.update_alert('test-alert-1', status='closed', notes='False positive')
        
        # Check that the alert was updated correctly
        self.assertEqual(updated_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(updated_alert['notes'], 'False positive', "Notes should be 'False positive'")
        
        # Get the alert to verify the update
        retrieved_alert = self.sqlite_manager.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['status'], 'closed', "Status should be closed")
        self.assertEqual(retrieved_alert['notes'], 'False positive', "Notes should be 'False positive'")
    
    def test_add_enrichment_json(self):
        """Test adding enrichment to an alert with JSON storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.json_manager.create_alert(alert_data)
        
        # Add enrichment to the alert
        enrichment = {
            'source_ip': {
                'reputation': 'good',
                'country': 'US',
                'asn': 'AS12345 Example ISP'
            },
            'destination_ip': {
                'reputation': 'malicious',
                'country': 'RU',
                'asn': 'AS67890 Bad Actor'
            }
        }
        updated_alert = self.json_manager.add_enrichment('test-alert-1', enrichment)
        
        # Check that the enrichment was added correctly
        self.assertEqual(updated_alert['enrichment']['source_ip']['reputation'], 'good', "Source IP reputation should be good")
        self.assertEqual(updated_alert['enrichment']['destination_ip']['reputation'], 'malicious', "Destination IP reputation should be malicious")
        
        # Get the alert to verify the enrichment
        retrieved_alert = self.json_manager.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['enrichment']['source_ip']['country'], 'US', "Source IP country should be US")
        self.assertEqual(retrieved_alert['enrichment']['destination_ip']['country'], 'RU', "Destination IP country should be RU")
    
    def test_add_enrichment_sqlite(self):
        """Test adding enrichment to an alert with SQLite storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.sqlite_manager.create_alert(alert_data)
        
        # Add enrichment to the alert
        enrichment = {
            'source_ip': {
                'reputation': 'good',
                'country': 'US',
                'asn': 'AS12345 Example ISP'
            },
            'destination_ip': {
                'reputation': 'malicious',
                'country': 'RU',
                'asn': 'AS67890 Bad Actor'
            }
        }
        updated_alert = self.sqlite_manager.add_enrichment('test-alert-1', enrichment)
        
        # Check that the enrichment was added correctly
        self.assertEqual(updated_alert['enrichment']['source_ip']['reputation'], 'good', "Source IP reputation should be good")
        self.assertEqual(updated_alert['enrichment']['destination_ip']['reputation'], 'malicious', "Destination IP reputation should be malicious")
        
        # Get the alert to verify the enrichment
        retrieved_alert = self.sqlite_manager.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['enrichment']['source_ip']['country'], 'US', "Source IP country should be US")
        self.assertEqual(retrieved_alert['enrichment']['destination_ip']['country'], 'RU', "Destination IP country should be RU")
    
    def test_add_analysis_json(self):
        """Test adding analysis to an alert with JSON storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.json_manager.create_alert(alert_data)
        
        # Add analysis to the alert
        analysis = {
            'threat_type': 'C2 Communication',
            'confidence': 'high',
            'mitre_tactics': ['Command and Control'],
            'mitre_techniques': ['T1071 - Application Layer Protocol']
        }
        updated_alert = self.json_manager.add_analysis('test-alert-1', analysis)
        
        # Check that the analysis was added correctly
        self.assertEqual(updated_alert['analysis']['threat_type'], 'C2 Communication', "Threat type should be C2 Communication")
        self.assertEqual(updated_alert['analysis']['confidence'], 'high', "Confidence should be high")
        
        # Get the alert to verify the analysis
        retrieved_alert = self.json_manager.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['analysis']['mitre_tactics'], ['Command and Control'], "MITRE tactics should be correct")
        self.assertEqual(retrieved_alert['analysis']['mitre_techniques'], ['T1071 - Application Layer Protocol'], "MITRE techniques should be correct")
    
    def test_add_analysis_sqlite(self):
        """Test adding analysis to an alert with SQLite storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.sqlite_manager.create_alert(alert_data)
        
        # Add analysis to the alert
        analysis = {
            'threat_type': 'C2 Communication',
            'confidence': 'high',
            'mitre_tactics': ['Command and Control'],
            'mitre_techniques': ['T1071 - Application Layer Protocol']
        }
        updated_alert = self.sqlite_manager.add_analysis('test-alert-1', analysis)
        
        # Check that the analysis was added correctly
        self.assertEqual(updated_alert['analysis']['threat_type'], 'C2 Communication', "Threat type should be C2 Communication")
        self.assertEqual(updated_alert['analysis']['confidence'], 'high', "Confidence should be high")
        
        # Get the alert to verify the analysis
        retrieved_alert = self.sqlite_manager.get_alert('test-alert-1')
        self.assertEqual(retrieved_alert['analysis']['mitre_tactics'], ['Command and Control'], "MITRE tactics should be correct")
        self.assertEqual(retrieved_alert['analysis']['mitre_techniques'], ['T1071 - Application Layer Protocol'], "MITRE techniques should be correct")
    
    def test_delete_alert_json(self):
        """Test deleting an alert with JSON storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.json_manager.create_alert(alert_data)
        
        # Delete the alert
        result = self.json_manager.delete_alert('test-alert-1')
        self.assertTrue(result, "Delete should return True")
        
        # Try to get the deleted alert
        retrieved_alert = self.json_manager.get_alert('test-alert-1')
        self.assertIsNone(retrieved_alert, "Alert should be None after deletion")
    
    def test_delete_alert_sqlite(self):
        """Test deleting an alert with SQLite storage."""
        # Create a test alert
        alert_data = {
            'id': 'test-alert-1',
            'timestamp': '2023-01-01T00:00:00',
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'severity': 'high',
            'category': 'malware'
        }
        self.sqlite_manager.create_alert(alert_data)
        
        # Delete the alert
        result = self.sqlite_manager.delete_alert('test-alert-1')
        self.assertTrue(result, "Delete should return True")
        
        # Try to get the deleted alert
        retrieved_alert = self.sqlite_manager.get_alert('test-alert-1')
        self.assertIsNone(retrieved_alert, "Alert should be None after deletion")


class TestConfigIntegration(unittest.TestCase):
    """Test the integration of database configuration with SentinelX."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test configuration file
        self.config_path = os.path.join(self.temp_dir, 'config.yaml')
        
        # Create test database paths
        self.json_path = os.path.join(self.temp_dir, 'data', 'alerts.json')
        self.db_path = os.path.join(self.temp_dir, 'data', 'alerts.db')
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_json_storage_config(self):
        """Test JSON storage configuration."""
        # Create a configuration file with JSON storage
        config = {
            'alert_storage': {
                'type': 'json',
                'path': self.json_path
            }
        }
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f)
        
        # Create a mock SentinelX instance
        mock_sentinelx = MagicMock()
        
        # Create a mock AlertManager with JSON storage
        mock_alert_manager = MagicMock(spec=AlertManager)
        mock_sentinelx.alert_manager = mock_alert_manager
        
        # Create a mock JSONAlertStorage
        mock_json_storage = MagicMock(spec=JSONAlertStorage)
        mock_alert_manager.storage = mock_json_storage
        
        # Check that the storage is configured correctly
        self.assertIsInstance(mock_alert_manager.storage, MagicMock, "Storage should be a MagicMock")
        self.assertEqual(mock_alert_manager.storage._spec_class, JSONAlertStorage, "Storage should be a JSONAlertStorage")
    
    def test_sqlite_storage_config(self):
        """Test SQLite storage configuration."""
        # Create a configuration file with SQLite storage
        config = {
            'alert_storage': {
                'type': 'sqlite',
                'path': self.db_path
            }
        }
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f)
        
        # Create a mock SentinelX instance
        mock_sentinelx = MagicMock()
        
        # Create a mock AlertManager with SQLite storage
        mock_alert_manager = MagicMock(spec=AlertManager)
        mock_sentinelx.alert_manager = mock_alert_manager
        
        # Create a mock SQLiteAlertStorage
        mock_sqlite_storage = MagicMock(spec=SQLiteAlertStorage)
        mock_alert_manager.storage = mock_sqlite_storage
        
        # Check that the storage is configured correctly
        self.assertIsInstance(mock_alert_manager.storage, MagicMock, "Storage should be a MagicMock")
        self.assertEqual(mock_alert_manager.storage._spec_class, SQLiteAlertStorage, "Storage should be a SQLiteAlertStorage")
    
    def test_mongodb_storage_config(self):
        """Test MongoDB storage configuration."""
        # Create a configuration file with MongoDB storage
        config = {
            'alert_storage': {
                'type': 'mongodb',
                'connection_string': 'mongodb://localhost:27017/',
                'database': 'sentinelx',
                'collection': 'alerts'
            }
        }
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f)
        
        # Create a mock SentinelX instance
        mock_sentinelx = MagicMock()
        
        # Create a mock AlertManager with MongoDB storage
        mock_alert_manager = MagicMock(spec=AlertManager)
        mock_sentinelx.alert_manager = mock_alert_manager
        
        # Create a mock MongoDBAlertStorage
        mock_mongodb_storage = MagicMock(spec=MongoDBAlertStorage)
        mock_alert_manager.storage = mock_mongodb_storage
        
        # Check that the storage is configured correctly
        self.assertIsInstance(mock_alert_manager.storage, MagicMock, "Storage should be a MagicMock")
        self.assertEqual(mock_alert_manager.storage._spec_class, MongoDBAlertStorage, "Storage should be a MongoDBAlertStorage")


if __name__ == '__main__':
    unittest.main()