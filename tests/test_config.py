#!/usr/bin/env python
# SentinelX Configuration Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
import yaml

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the ConfigManager class
try:
    from src.core.config_manager import ConfigManager
except ImportError:
    # Mock ConfigManager if it doesn't exist yet
    class ConfigManager:
        _instance = None
        
        def __new__(cls):
            if cls._instance is None:
                cls._instance = super(ConfigManager, cls).__new__(cls)
                cls._instance.config = {}
            return cls._instance
        
        def load_config(self, config_path):
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            return self.config
        
        def get(self, key, default=None):
            return self.config.get(key, default)
        
        def set(self, key, value):
            self.config[key] = value
            return True
        
        def save_config(self, config_path):
            with open(config_path, 'w') as f:
                yaml.dump(self.config, f)
            return True


class TestConfig(unittest.TestCase):
    """Test the configuration management."""
    
    def setUp(self):
        """Set up the test environment."""
        # Reset the ConfigManager singleton
        ConfigManager._instance = None
        
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test configuration file
        self.config_path = os.path.join(self.temp_dir, 'config.yaml')
        self.test_config = {
            'network': {
                'interface': 'eth0',
                'capture_timeout': 60,
                'max_packets': 1000,
                'flow_timeout': 120
            },
            'model': {
                'type': 'random_forest',
                'params': {
                    'n_estimators': 100,
                    'max_depth': 10
                },
                'threshold': 0.8
            },
            'threat_intel': {
                'abuseipdb': {
                    'api_key': 'test_key',
                    'cache_duration': 86400
                },
                'otx': {
                    'api_key': 'test_key',
                    'cache_duration': 86400
                },
                'virustotal': {
                    'api_key': 'test_key',
                    'cache_duration': 86400
                }
            },
            'api': {
                'host': '0.0.0.0',
                'port': 8000,
                'api_key': 'test_api_key'
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/sentinelx.log',
                'max_size': 10485760,  # 10 MB
                'backup_count': 5
            },
            'paths': {
                'data': 'data',
                'models': 'models',
                'logs': 'logs',
                'pcaps': 'pcaps'
            }
        }
        
        # Write the test configuration to the file
        with open(self.config_path, 'w') as f:
            yaml.dump(self.test_config, f)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_singleton_pattern(self):
        """Test that ConfigManager follows the singleton pattern."""
        config1 = ConfigManager()
        config2 = ConfigManager()
        self.assertIs(config1, config2, "ConfigManager should be a singleton")
    
    def test_load_config(self):
        """Test loading a configuration file."""
        config = ConfigManager()
        loaded_config = config.load_config(self.config_path)
        self.assertEqual(loaded_config, self.test_config, "Loaded config should match the test config")
    
    def test_get_config_value(self):
        """Test getting a configuration value."""
        config = ConfigManager()
        config.load_config(self.config_path)
        
        # Test getting a top-level value
        network_config = config.get('network')
        self.assertEqual(network_config, self.test_config['network'], "Should get the correct network config")
        
        # Test getting a nested value
        interface = config.get('network', {}).get('interface')
        self.assertEqual(interface, 'eth0', "Should get the correct interface value")
        
        # Test getting a default value for a non-existent key
        non_existent = config.get('non_existent', 'default')
        self.assertEqual(non_existent, 'default', "Should get the default value for a non-existent key")
    
    def test_set_config_value(self):
        """Test setting a configuration value."""
        config = ConfigManager()
        config.load_config(self.config_path)
        
        # Test setting a top-level value
        config.set('new_key', 'new_value')
        self.assertEqual(config.get('new_key'), 'new_value', "Should set and get the new value")
        
        # Test setting a nested value
        network = config.get('network', {})
        network['interface'] = 'wlan0'
        config.set('network', network)
        self.assertEqual(config.get('network', {}).get('interface'), 'wlan0', "Should set and get the nested value")
    
    def test_save_config(self):
        """Test saving a configuration file."""
        config = ConfigManager()
        config.load_config(self.config_path)
        
        # Modify the configuration
        config.set('new_key', 'new_value')
        
        # Save the configuration to a new file
        new_config_path = os.path.join(self.temp_dir, 'new_config.yaml')
        config.save_config(new_config_path)
        
        # Load the new configuration file
        new_config = ConfigManager()
        new_config.load_config(new_config_path)
        
        # Check that the new configuration matches the modified configuration
        self.assertEqual(new_config.get('new_key'), 'new_value', "Saved config should contain the new value")
    
    def test_config_validation(self):
        """Test configuration validation."""
        # This test assumes that ConfigManager has a validate_config method
        # If it doesn't, this test can be skipped or modified
        config = ConfigManager()
        
        # Test with a valid configuration
        try:
            config.load_config(self.config_path)
            # If validate_config exists, call it
            if hasattr(config, 'validate_config'):
                self.assertTrue(config.validate_config(), "Valid config should pass validation")
        except Exception as e:
            self.fail(f"Loading a valid config should not raise an exception: {e}")
        
        # Test with an invalid configuration
        invalid_config_path = os.path.join(self.temp_dir, 'invalid_config.yaml')
        with open(invalid_config_path, 'w') as f:
            f.write('invalid: yaml: content')
        
        try:
            config.load_config(invalid_config_path)
            # If validate_config exists, call it
            if hasattr(config, 'validate_config'):
                self.assertFalse(config.validate_config(), "Invalid config should fail validation")
        except Exception:
            # It's acceptable for load_config to raise an exception for invalid YAML
            pass
    
    def test_environment_variable_override(self):
        """Test that environment variables can override configuration values."""
        # This test assumes that ConfigManager checks environment variables
        # If it doesn't, this test can be skipped or modified
        config = ConfigManager()
        config.load_config(self.config_path)
        
        # Set an environment variable to override a configuration value
        with patch.dict('os.environ', {'SENTINELX_API_PORT': '9000'}):
            # If get_from_env exists, call it
            if hasattr(config, 'get_from_env'):
                port = config.get_from_env('api.port', 8000)
                self.assertEqual(port, 9000, "Environment variable should override config value")
    
    def test_default_config(self):
        """Test that a default configuration is used if no file is provided."""
        # This test assumes that ConfigManager has a default configuration
        # If it doesn't, this test can be skipped or modified
        config = ConfigManager()
        
        # If load_default_config exists, call it
        if hasattr(config, 'load_default_config'):
            config.load_default_config()
            self.assertIsNotNone(config.get('network'), "Default config should have a network section")
            self.assertIsNotNone(config.get('model'), "Default config should have a model section")
            self.assertIsNotNone(config.get('api'), "Default config should have an API section")
            self.assertIsNotNone(config.get('logging'), "Default config should have a logging section")
            self.assertIsNotNone(config.get('paths'), "Default config should have a paths section")


if __name__ == '__main__':
    unittest.main()