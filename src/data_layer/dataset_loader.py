# SentinelX Dataset Loader

import os
import pandas as pd
import numpy as np
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional
import logging

from ..core.config_manager import ConfigManager

class DatasetLoader(ABC):
    """Abstract base class for dataset loaders.
    
    This class defines the interface that all dataset loaders must implement.
    """
    
    def __init__(self):
        """Initialize the dataset loader."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get data directory from config
        data_dir = self.config.get('paths', 'data_dir', '../data')
        
        # Get the directory of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to the data directory
        self.data_dir = os.path.abspath(os.path.join(current_dir, '..', '..', data_dir))
        
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            self.logger.info(f"Created data directory: {self.data_dir}")
    
    @abstractmethod
    def load_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load the dataset.
        
        Returns:
            Tuple containing training and testing DataFrames
        """
        pass
    
    @abstractmethod
    def download_dataset(self) -> bool:
        """Download the dataset if not already available.
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_feature_info(self) -> Dict[str, Any]:
        """Get information about the dataset features.
        
        Returns:
            Dictionary containing feature information
        """
        pass


class NSLKDDDatasetLoader(DatasetLoader):
    """Loader for the NSL-KDD dataset.
    
    The NSL-KDD dataset is an improved version of the KDD Cup 1999 dataset,
    which is widely used for intrusion detection system evaluation.
    """
    
    def __init__(self):
        """Initialize the NSL-KDD dataset loader."""
        super().__init__()
        self.train_file = os.path.join(self.data_dir, 'NSL-KDD', 'KDDTrain+.txt')
        self.test_file = os.path.join(self.data_dir, 'NSL-KDD', 'KDDTest+.txt')
        self.column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'class', 'difficulty_level'
        ]
        
        # Attack class mapping
        self.attack_mapping = {
            'normal': 'normal',
            'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos',
            'smurf': 'dos', 'teardrop': 'dos', 'mailbomb': 'dos',
            'apache2': 'dos', 'processtable': 'dos', 'udpstorm': 'dos',
            'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe',
            'satan': 'probe', 'mscan': 'probe', 'saint': 'probe',
            'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l',
            'multihop': 'r2l', 'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l',
            'warezmaster': 'r2l', 'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l',
            'snmpguess': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l', 'worm': 'r2l',
            'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r',
            'rootkit': 'u2r', 'httptunnel': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r',
            'xterm': 'u2r'
        }
    
    def download_dataset(self) -> bool:
        """Download the NSL-KDD dataset.
        
        Returns:
            True if successful, False otherwise
        """
        import requests
        import zipfile
        import io
        
        # Create NSL-KDD directory if it doesn't exist
        nsl_kdd_dir = os.path.join(self.data_dir, 'NSL-KDD')
        if not os.path.exists(nsl_kdd_dir):
            os.makedirs(nsl_kdd_dir)
        
        # Check if files already exist
        if os.path.exists(self.train_file) and os.path.exists(self.test_file):
            self.logger.info("NSL-KDD dataset files already exist.")
            return True
        
        try:
            # URLs for the NSL-KDD dataset
            train_url = "https://iscxdownloads.cs.unb.ca/iscxdownloads/NSL-KDD/KDDTrain+.txt"
            test_url = "https://iscxdownloads.cs.unb.ca/iscxdownloads/NSL-KDD/KDDTest+.txt"
            
            # Download training data
            self.logger.info("Downloading NSL-KDD training data...")
            train_response = requests.get(train_url)
            if train_response.status_code == 200:
                with open(self.train_file, 'wb') as f:
                    f.write(train_response.content)
                self.logger.info(f"Training data saved to {self.train_file}")
            else:
                self.logger.error(f"Failed to download training data: {train_response.status_code}")
                return False
            
            # Download testing data
            self.logger.info("Downloading NSL-KDD testing data...")
            test_response = requests.get(test_url)
            if test_response.status_code == 200:
                with open(self.test_file, 'wb') as f:
                    f.write(test_response.content)
                self.logger.info(f"Testing data saved to {self.test_file}")
            else:
                self.logger.error(f"Failed to download testing data: {test_response.status_code}")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"Error downloading NSL-KDD dataset: {str(e)}")
            return False
    
    def load_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load the NSL-KDD dataset.
        
        Returns:
            Tuple containing training and testing DataFrames
        """
        # Check if dataset exists, download if not
        if not os.path.exists(self.train_file) or not os.path.exists(self.test_file):
            success = self.download_dataset()
            if not success:
                self.logger.error("Failed to download dataset. Cannot proceed.")
                raise FileNotFoundError("NSL-KDD dataset files not found and could not be downloaded.")
        
        try:
            # Load training data
            self.logger.info(f"Loading training data from {self.train_file}")
            train_df = pd.read_csv(self.train_file, header=None, names=self.column_names)
            
            # Load testing data
            self.logger.info(f"Loading testing data from {self.test_file}")
            test_df = pd.read_csv(self.test_file, header=None, names=self.column_names)
            
            # Add attack category column
            train_df['attack_category'] = train_df['class'].apply(
                lambda x: self.attack_mapping.get(x.lower(), 'unknown')
            )
            test_df['attack_category'] = test_df['class'].apply(
                lambda x: self.attack_mapping.get(x.lower(), 'unknown')
            )
            
            self.logger.info(f"Loaded {len(train_df)} training samples and {len(test_df)} testing samples")
            
            return train_df, test_df
        except Exception as e:
            self.logger.error(f"Error loading NSL-KDD dataset: {str(e)}")
            raise
    
    def get_feature_info(self) -> Dict[str, Any]:
        """Get information about the NSL-KDD dataset features.
        
        Returns:
            Dictionary containing feature information
        """
        # Define feature types
        categorical_features = ['protocol_type', 'service', 'flag']
        binary_features = ['land', 'logged_in', 'root_shell', 'su_attempted', 
                          'is_host_login', 'is_guest_login']
        numeric_features = [col for col in self.column_names 
                           if col not in categorical_features + binary_features + 
                           ['class', 'difficulty_level', 'attack_category']]
        
        return {
            'categorical_features': categorical_features,
            'binary_features': binary_features,
            'numeric_features': numeric_features,
            'target_column': 'class',
            'attack_category_column': 'attack_category',
            'attack_categories': ['normal', 'dos', 'probe', 'r2l', 'u2r'],
            'total_features': len(self.column_names) - 2  # Excluding class and difficulty_level
        }