#!/usr/bin/env python
# SentinelX Core Tests

import os
import sys
import unittest
import tempfile
import yaml

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.config_manager import ConfigManager
from src.core.logging_manager import LoggingManager


class TestConfigManager(unittest.TestCase):
    """Test the ConfigManager class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
        
        # Write test configuration
        test_config = {
            'general': {
                'project_name': 'SentinelX-Test',
                'version': '0.1.0'
            },
            'paths': {
                'data_dir': '/tmp/sentinelx/data',
                'logs_dir': '/tmp/sentinelx/logs'
            },
            'logging': {
                'level': 'DEBUG',
                'console': True,
                'file': True,
                'file_level': 'INFO'
            }
        }
        
        yaml.dump(test_config, self.temp_config)
        self.temp_config.close()
        
        # Reset ConfigManager singleton
        ConfigManager._instance = None
    
    def tearDown(self):
        """Clean up the test environment."""
        os.unlink(self.temp_config.name)
    
    def test_singleton(self):
        """Test that ConfigManager is a singleton."""
        config1 = ConfigManager()
        config2 = ConfigManager()
        self.assertIs(config1, config2)
    
    def test_load_config(self):
        """Test loading configuration from a file."""
        config = ConfigManager()
        config.load_config(self.temp_config.name)
        
        # Check that the configuration was loaded correctly
        self.assertEqual(config.get('general', 'project_name'), 'SentinelX-Test')
        self.assertEqual(config.get('paths', 'data_dir'), '/tmp/sentinelx/data')
        self.assertEqual(config.get('logging', 'level'), 'DEBUG')
    
    def test_get_default(self):
        """Test getting a configuration value with a default."""
        config = ConfigManager()
        config.load_config(self.temp_config.name)
        
        # Get an existing value
        self.assertEqual(config.get('general', 'version', 'unknown'), '0.1.0')
        
        # Get a non-existing value with a default
        self.assertEqual(config.get('general', 'non_existent', 'default_value'), 'default_value')
    
    def test_set_value(self):
        """Test setting a configuration value."""
        config = ConfigManager()
        config.load_config(self.temp_config.name)
        
        # Set a new value
        config.set('general', 'new_key', 'new_value')
        self.assertEqual(config.get('general', 'new_key'), 'new_value')
        
        # Update an existing value
        config.set('general', 'version', '0.2.0')
        self.assertEqual(config.get('general', 'version'), '0.2.0')


class TestLoggingManager(unittest.TestCase):
    """Test the LoggingManager class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
        
        # Create a temporary log directory
        self.temp_log_dir = tempfile.mkdtemp()
        
        # Write test configuration
        test_config = {
            'general': {
                'project_name': 'SentinelX-Test',
                'version': '0.1.0'
            },
            'paths': {
                'data_dir': '/tmp/sentinelx/data',
                'logs_dir': self.temp_log_dir
            },
            'logging': {
                'level': 'DEBUG',
                'console': True,
                'file': True,
                'file_level': 'INFO',
                'max_size_mb': 10,
                'backup_count': 3
            }
        }
        
        yaml.dump(test_config, self.temp_config)
        self.temp_config.close()
        
        # Reset ConfigManager singleton
        ConfigManager._instance = None
        
        # Load the test configuration
        self.config = ConfigManager()
        self.config.load_config(self.temp_config.name)
        
        # Reset LoggingManager singleton
        LoggingManager._instance = None
    
    def tearDown(self):
        """Clean up the test environment."""
        os.unlink(self.temp_config.name)
        
        # Remove temporary log files
        for root, dirs, files in os.walk(self.temp_log_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_log_dir)
    
    def test_singleton(self):
        """Test that LoggingManager is a singleton."""
        logger1 = LoggingManager()
        logger2 = LoggingManager()
        self.assertIs(logger1, logger2)
    
    def test_get_logger(self):
        """Test getting a logger."""
        logging_manager = LoggingManager()
        logging_manager.configure()
        
        # Get a logger
        logger = logging_manager.get_logger('test')
        self.assertIsNotNone(logger)
        
        # Test that the logger has the correct name
        self.assertEqual(logger.name, 'sentinelx.test')
        
        # Test that the logger has the correct level
        self.assertEqual(logger.level, 10)  # DEBUG = 10


if __name__ == '__main__':
    unittest.main()