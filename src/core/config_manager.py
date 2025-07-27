# SentinelX Configuration Manager

import os
import yaml
from typing import Dict, Any, Optional
import logging

class ConfigManager:
    """Configuration manager for SentinelX.
    
    This class is responsible for loading and providing access to the configuration
    settings defined in the YAML configuration file.
    """
    
    _instance = None
    
    def __new__(cls, config_path: Optional[str] = None):
        """Singleton pattern implementation to ensure only one config instance exists."""
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, uses default path.
        """
        if self._initialized:
            return
            
        self.logger = logging.getLogger(__name__)
        
        # Default config path is in the config directory
        if config_path is None:
            # Get the directory of the current file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Navigate to the config directory
            config_dir = os.path.abspath(os.path.join(current_dir, '..', '..', 'config'))
            config_path = os.path.join(config_dir, 'config.yaml')
        
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.load_config()
        self._initialized = True
    
    def load_config(self) -> None:
        """Load configuration from the YAML file."""
        try:
            with open(self.config_path, 'r') as config_file:
                self.config = yaml.safe_load(config_file)
            self.logger.info(f"Configuration loaded from {self.config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            # Set default configuration
            self.config = self._get_default_config()
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            section: The configuration section
            key: The specific key within the section. If None, returns the entire section.
            default: Default value to return if the key is not found
            
        Returns:
            The configuration value or default if not found
        """
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value.
        
        Args:
            section: The configuration section
            key: The specific key within the section
            value: The value to set
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
    
    def save(self) -> bool:
        """Save the current configuration to the YAML file.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(self.config_path, 'w') as config_file:
                yaml.dump(self.config, config_file, default_flow_style=False)
            self.logger.info(f"Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            return False
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration when config file cannot be loaded.
        
        Returns:
            Dict containing default configuration values
        """
        return {
            "general": {
                "project_name": "SentinelX",
                "version": "0.1.0",
                "debug_mode": True
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "sentinelx.log"
            },
            "paths": {
                "data_dir": "../data",
                "models_dir": "../models",
                "logs_dir": "../logs"
            }
        }