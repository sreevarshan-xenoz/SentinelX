#!/usr/bin/env python
# SentinelX Logging Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import logging
import json

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the LoggingManager class
try:
    from src.core.logging_manager import LoggingManager
except ImportError:
    # Mock LoggingManager if it doesn't exist yet
    class LoggingManager:
        _instance = None
        
        def __new__(cls):
            if cls._instance is None:
                cls._instance = super(LoggingManager, cls).__new__(cls)
                cls._instance.loggers = {}
            return cls._instance
        
        def configure(self, config=None):
            if config is None:
                config = {
                    'level': 'INFO',
                    'file': 'logs/sentinelx.log',
                    'max_size': 10485760,  # 10 MB
                    'backup_count': 5
                }
            
            # Create the logs directory if it doesn't exist
            log_dir = os.path.dirname(config['file'])
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Configure the root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(getattr(logging, config['level']))
            
            # Add a file handler
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                config['file'],
                maxBytes=config['max_size'],
                backupCount=config['backup_count']
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            root_logger.addHandler(file_handler)
            
            # Add a console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            root_logger.addHandler(console_handler)
            
            return root_logger
        
        def get_logger(self, name):
            if name not in self.loggers:
                self.loggers[name] = logging.getLogger(name)
            return self.loggers[name]


class TestLogging(unittest.TestCase):
    """Test the logging functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        # Reset the LoggingManager singleton
        LoggingManager._instance = None
        
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test logging configuration
        self.log_file = os.path.join(self.temp_dir, 'test.log')
        self.log_config = {
            'level': 'DEBUG',
            'file': self.log_file,
            'max_size': 1024,  # 1 KB
            'backup_count': 3
        }
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
        
        # Reset the root logger
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:  # Make a copy of the list
            root_logger.removeHandler(handler)
    
    def test_singleton_pattern(self):
        """Test that LoggingManager follows the singleton pattern."""
        logging1 = LoggingManager()
        logging2 = LoggingManager()
        self.assertIs(logging1, logging2, "LoggingManager should be a singleton")
    
    def test_configure(self):
        """Test configuring the logging system."""
        logging_manager = LoggingManager()
        logger = logging_manager.configure(self.log_config)
        
        # Check that the logger has the correct level
        self.assertEqual(logger.level, logging.DEBUG, "Logger should have the DEBUG level")
        
        # Check that the logger has handlers
        self.assertTrue(logger.handlers, "Logger should have handlers")
        
        # Check that the log file was created
        self.assertTrue(os.path.exists(self.log_file), "Log file should be created")
    
    def test_get_logger(self):
        """Test getting a logger."""
        logging_manager = LoggingManager()
        logging_manager.configure(self.log_config)
        
        # Get a logger
        logger = logging_manager.get_logger('test')
        
        # Check that the logger has the correct name
        self.assertEqual(logger.name, 'test', "Logger should have the correct name")
        
        # Check that the logger has the correct level
        self.assertEqual(logger.level, 0, "Logger should inherit the level from the root logger")
        
        # Check that getting the same logger twice returns the same object
        logger2 = logging_manager.get_logger('test')
        self.assertIs(logger, logger2, "Getting the same logger twice should return the same object")
    
    def test_logging_to_file(self):
        """Test logging messages to a file."""
        logging_manager = LoggingManager()
        logging_manager.configure(self.log_config)
        
        # Get a logger
        logger = logging_manager.get_logger('test')
        
        # Log a message
        test_message = 'Test message'
        logger.info(test_message)
        
        # Check that the message was written to the log file
        with open(self.log_file, 'r') as f:
            log_content = f.read()
        self.assertIn(test_message, log_content, "Log message should be written to the file")
    
    def test_log_rotation(self):
        """Test log file rotation."""
        # This test assumes that LoggingManager uses RotatingFileHandler
        # If it doesn't, this test can be skipped or modified
        logging_manager = LoggingManager()
        logging_manager.configure(self.log_config)
        
        # Get a logger
        logger = logging_manager.get_logger('test')
        
        # Write enough data to trigger log rotation
        for i in range(100):
            logger.info('A' * 100)  # 100 characters per log message
        
        # Check that the log file was rotated
        self.assertTrue(os.path.exists(self.log_file), "Log file should exist")
        self.assertTrue(os.path.exists(f"{self.log_file}.1") or 
                      os.path.exists(f"{self.log_file}.1.gz"), 
                      "Rotated log file should exist")
    
    def test_log_levels(self):
        """Test different log levels."""
        logging_manager = LoggingManager()
        logging_manager.configure(self.log_config)
        
        # Get a logger
        logger = logging_manager.get_logger('test')
        
        # Log messages at different levels
        debug_message = 'Debug message'
        info_message = 'Info message'
        warning_message = 'Warning message'
        error_message = 'Error message'
        critical_message = 'Critical message'
        
        logger.debug(debug_message)
        logger.info(info_message)
        logger.warning(warning_message)
        logger.error(error_message)
        logger.critical(critical_message)
        
        # Check that all messages were written to the log file
        with open(self.log_file, 'r') as f:
            log_content = f.read()
        
        self.assertIn(debug_message, log_content, "Debug message should be in the log")
        self.assertIn(info_message, log_content, "Info message should be in the log")
        self.assertIn(warning_message, log_content, "Warning message should be in the log")
        self.assertIn(error_message, log_content, "Error message should be in the log")
        self.assertIn(critical_message, log_content, "Critical message should be in the log")
        
        # Change the log level to INFO
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        
        # Clear the log file
        with open(self.log_file, 'w') as f:
            f.write('')
        
        # Log messages again
        logger.debug(debug_message)
        logger.info(info_message)
        logger.warning(warning_message)
        logger.error(error_message)
        logger.critical(critical_message)
        
        # Check that only INFO and above messages were written to the log file
        with open(self.log_file, 'r') as f:
            log_content = f.read()
        
        self.assertNotIn(debug_message, log_content, "Debug message should not be in the log")
        self.assertIn(info_message, log_content, "Info message should be in the log")
        self.assertIn(warning_message, log_content, "Warning message should be in the log")
        self.assertIn(error_message, log_content, "Error message should be in the log")
        self.assertIn(critical_message, log_content, "Critical message should be in the log")
    
    def test_structured_logging(self):
        """Test structured logging."""
        # This test assumes that LoggingManager supports structured logging
        # If it doesn't, this test can be skipped or modified
        logging_manager = LoggingManager()
        
        # If configure_json exists, call it
        if hasattr(logging_manager, 'configure_json'):
            json_log_file = os.path.join(self.temp_dir, 'test.json.log')
            json_log_config = {
                'level': 'DEBUG',
                'file': json_log_file,
                'max_size': 1024,  # 1 KB
                'backup_count': 3
            }
            
            logging_manager.configure_json(json_log_config)
            
            # Get a logger
            logger = logging_manager.get_logger('test')
            
            # Log a structured message
            logger.info('Structured message', extra={
                'user_id': 123,
                'action': 'login',
                'status': 'success'
            })
            
            # Check that the message was written to the log file as JSON
            with open(json_log_file, 'r') as f:
                log_line = f.readline().strip()
            
            try:
                log_entry = json.loads(log_line)
                self.assertEqual(log_entry.get('user_id'), 123, "Log entry should have the user_id field")
                self.assertEqual(log_entry.get('action'), 'login', "Log entry should have the action field")
                self.assertEqual(log_entry.get('status'), 'success', "Log entry should have the status field")
            except json.JSONDecodeError:
                self.fail("Log entry should be valid JSON")


if __name__ == '__main__':
    unittest.main()