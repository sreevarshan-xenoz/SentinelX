# SentinelX Logging Manager

import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from typing import Optional

from .config_manager import ConfigManager

class LoggingManager:
    """Logging manager for SentinelX.
    
    This class is responsible for setting up and configuring the logging system
    based on the application configuration.
    """
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern implementation to ensure only one logging manager instance exists."""
        if cls._instance is None:
            cls._instance = super(LoggingManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the logging manager."""
        if self._initialized:
            return
            
        self.config = ConfigManager()
        self.setup_logging()
        self._initialized = True
    
    def setup_logging(self) -> None:
        """Set up the logging configuration based on the application config."""
        # Get logging configuration
        log_level_str = self.config.get('logging', 'level', 'INFO')
        log_format = self.config.get('logging', 'format', 
                                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file = self.config.get('logging', 'file', 'sentinelx.log')
        max_size_mb = self.config.get('logging', 'max_size_mb', 10)
        backup_count = self.config.get('logging', 'backup_count', 5)
        
        # Convert log level string to logging level
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        
        # Create logs directory if it doesn't exist
        logs_dir = self.config.get('paths', 'logs_dir', '../logs')
        
        # Get the directory of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to the logs directory
        logs_dir = os.path.abspath(os.path.join(current_dir, '..', '..', logs_dir))
        
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
        
        log_file_path = os.path.join(logs_dir, log_file)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Remove existing handlers to avoid duplicates
        for handler in root_logger.handlers[:]:  
            root_logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(log_format)
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # Create file handler
        file_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=max_size_mb * 1024 * 1024,  # Convert MB to bytes
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Log initial message
        root_logger.info(f"Logging initialized at level {log_level_str}")
        root_logger.info(f"Log file: {log_file_path}")
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with the specified name.
        
        Args:
            name: The name of the logger, typically the module name
            
        Returns:
            A configured logger instance
        """
        return logging.getLogger(name)