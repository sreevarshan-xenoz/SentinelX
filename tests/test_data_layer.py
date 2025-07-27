#!/usr/bin/env python
# SentinelX Data Layer Tests

import os
import sys
import unittest
import tempfile
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_layer.dataset_loader import DatasetLoader, NSLKDDDatasetLoader
from src.data_layer.preprocessing_pipeline import PreprocessingPipeline
from src.data_layer.feature_extractor import FeatureExtractor


class TestDatasetLoader(unittest.TestCase):
    """Test the DatasetLoader class."""
    
    def test_abstract_methods(self):
        """Test that abstract methods raise NotImplementedError."""
        loader = DatasetLoader()
        
        with self.assertRaises(NotImplementedError):
            loader.load_data()
        
        with self.assertRaises(NotImplementedError):
            loader.download_dataset()
        
        with self.assertRaises(NotImplementedError):
            loader.get_feature_info()


class TestNSLKDDDatasetLoader(unittest.TestCase):
    """Test the NSLKDDDatasetLoader class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary data directory
        self.temp_data_dir = tempfile.mkdtemp()
        
        # Create a mock NSL-KDD dataset
        self.train_data = pd.DataFrame({
            'duration': [0, 0, 0],
            'protocol_type': ['tcp', 'udp', 'icmp'],
            'service': ['http', 'private', 'domain_u'],
            'flag': ['SF', 'SF', 'SF'],
            'src_bytes': [181, 239, 235],
            'dst_bytes': [5450, 486, 1337],
            'land': [0, 0, 0],
            'wrong_fragment': [0, 0, 0],
            'urgent': [0, 0, 0],
            'hot': [0, 0, 0],
            'num_failed_logins': [0, 0, 0],
            'logged_in': [1, 1, 1],
            'num_compromised': [0, 0, 0],
            'root_shell': [0, 0, 0],
            'su_attempted': [0, 0, 0],
            'num_root': [0, 0, 0],
            'num_file_creations': [0, 0, 0],
            'num_shells': [0, 0, 0],
            'num_access_files': [0, 0, 0],
            'num_outbound_cmds': [0, 0, 0],
            'is_host_login': [0, 0, 0],
            'is_guest_login': [0, 0, 0],
            'count': [1, 2, 1],
            'srv_count': [1, 2, 1],
            'serror_rate': [0, 0, 0],
            'srv_serror_rate': [0, 0, 0],
            'rerror_rate': [0, 0, 0],
            'srv_rerror_rate': [0, 0, 0],
            'same_srv_rate': [1, 1, 1],
            'diff_srv_rate': [0, 0, 0],
            'srv_diff_host_rate': [0, 0, 0],
            'dst_host_count': [9, 9, 10],
            'dst_host_srv_count': [9, 9, 10],
            'dst_host_same_srv_rate': [1, 1, 1],
            'dst_host_diff_srv_rate': [0, 0, 0],
            'dst_host_same_src_port_rate': [0.11, 0.11, 0.1],
            'dst_host_srv_diff_host_rate': [0, 0, 0],
            'dst_host_serror_rate': [0, 0, 0],
            'dst_host_srv_serror_rate': [0, 0, 0],
            'dst_host_rerror_rate': [0, 0, 0],
            'dst_host_srv_rerror_rate': [0, 0, 0],
            'class': ['normal', 'neptune', 'normal']
        })
        
        self.test_data = pd.DataFrame({
            'duration': [0, 0],
            'protocol_type': ['tcp', 'udp'],
            'service': ['http', 'private'],
            'flag': ['SF', 'SF'],
            'src_bytes': [181, 239],
            'dst_bytes': [5450, 486],
            'land': [0, 0],
            'wrong_fragment': [0, 0],
            'urgent': [0, 0],
            'hot': [0, 0],
            'num_failed_logins': [0, 0],
            'logged_in': [1, 1],
            'num_compromised': [0, 0],
            'root_shell': [0, 0],
            'su_attempted': [0, 0],
            'num_root': [0, 0],
            'num_file_creations': [0, 0],
            'num_shells': [0, 0],
            'num_access_files': [0, 0],
            'num_outbound_cmds': [0, 0],
            'is_host_login': [0, 0],
            'is_guest_login': [0, 0],
            'count': [1, 2],
            'srv_count': [1, 2],
            'serror_rate': [0, 0],
            'srv_serror_rate': [0, 0],
            'rerror_rate': [0, 0],
            'srv_rerror_rate': [0, 0],
            'same_srv_rate': [1, 1],
            'diff_srv_rate': [0, 0],
            'srv_diff_host_rate': [0, 0],
            'dst_host_count': [9, 9],
            'dst_host_srv_count': [9, 9],
            'dst_host_same_srv_rate': [1, 1],
            'dst_host_diff_srv_rate': [0, 0],
            'dst_host_same_src_port_rate': [0.11, 0.11],
            'dst_host_srv_diff_host_rate': [0, 0],
            'dst_host_serror_rate': [0, 0],
            'dst_host_srv_serror_rate': [0, 0],
            'dst_host_rerror_rate': [0, 0],
            'dst_host_srv_rerror_rate': [0, 0],
            'class': ['normal', 'neptune']
        })
        
        # Save the mock datasets
        os.makedirs(os.path.join(self.temp_data_dir, 'NSL-KDD'), exist_ok=True)
        self.train_data.to_csv(os.path.join(self.temp_data_dir, 'NSL-KDD', 'KDDTrain+.txt'), index=False, header=False)
        self.test_data.to_csv(os.path.join(self.temp_data_dir, 'NSL-KDD', 'KDDTest+.txt'), index=False, header=False)
        
        # Create the loader
        self.loader = NSLKDDDatasetLoader(data_dir=self.temp_data_dir)
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary data files
        for root, dirs, files in os.walk(self.temp_data_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        
        os.rmdir(self.temp_data_dir)
    
    def test_load_data(self):
        """Test loading data from the NSL-KDD dataset."""
        X_train, y_train, X_test, y_test = self.loader.load_data()
        
        # Check that the data was loaded correctly
        self.assertEqual(X_train.shape[0], 3)  # 3 training samples
        self.assertEqual(X_test.shape[0], 2)   # 2 test samples
        self.assertEqual(y_train.shape[0], 3)  # 3 training labels
        self.assertEqual(y_test.shape[0], 2)   # 2 test labels
        
        # Check that the labels are correct
        self.assertEqual(y_train[0], 'normal')
        self.assertEqual(y_train[1], 'neptune')
        self.assertEqual(y_train[2], 'normal')
        self.assertEqual(y_test[0], 'normal')
        self.assertEqual(y_test[1], 'neptune')
    
    def test_get_feature_info(self):
        """Test getting feature information."""
        feature_info = self.loader.get_feature_info()
        
        # Check that the feature information is correct
        self.assertIsInstance(feature_info, dict)
        self.assertIn('categorical', feature_info)
        self.assertIn('numerical', feature_info)
        
        # Check that the categorical features are correct
        self.assertIn('protocol_type', feature_info['categorical'])
        self.assertIn('service', feature_info['categorical'])
        self.assertIn('flag', feature_info['categorical'])
        
        # Check that the numerical features are correct
        self.assertIn('duration', feature_info['numerical'])
        self.assertIn('src_bytes', feature_info['numerical'])
        self.assertIn('dst_bytes', feature_info['numerical'])


class TestPreprocessingPipeline(unittest.TestCase):
    """Test the PreprocessingPipeline class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a simple dataset for testing
        self.X_train = pd.DataFrame({
            'numerical1': [1, 2, 3, 4, 5],
            'numerical2': [10, 20, 30, 40, 50],
            'categorical1': ['A', 'B', 'A', 'C', 'B'],
            'categorical2': ['X', 'Y', 'Z', 'X', 'Y']
        })
        
        self.X_test = pd.DataFrame({
            'numerical1': [6, 7],
            'numerical2': [60, 70],
            'categorical1': ['A', 'C'],
            'categorical2': ['Z', 'X']
        })
        
        self.y_train = np.array(['normal', 'attack', 'normal', 'attack', 'normal'])
        self.y_test = np.array(['attack', 'normal'])
        
        # Define feature information
        self.feature_info = {
            'numerical': ['numerical1', 'numerical2'],
            'categorical': ['categorical1', 'categorical2']
        }
        
        # Create the pipeline
        self.pipeline = PreprocessingPipeline()
    
    def test_fit_transform(self):
        """Test fitting and transforming data."""
        # Fit the pipeline
        self.pipeline.fit(self.X_train, self.y_train, self.feature_info)
        
        # Transform the training data
        X_train_transformed, y_train_transformed = self.pipeline.transform(self.X_train, self.y_train)
        
        # Check that the transformed data has the correct shape
        self.assertEqual(X_train_transformed.shape[0], 5)  # 5 samples
        self.assertEqual(y_train_transformed.shape[0], 5)  # 5 labels
        
        # Check that the categorical features were one-hot encoded
        self.assertGreater(X_train_transformed.shape[1], 4)  # More features after one-hot encoding
        
        # Check that the numerical features were scaled
        self.assertTrue(np.all(X_train_transformed[:, 0] <= 1.0))  # Scaled values should be <= 1.0
        self.assertTrue(np.all(X_train_transformed[:, 0] >= -1.0))  # Scaled values should be >= -1.0
    
    def test_transform_test_data(self):
        """Test transforming test data."""
        # Fit the pipeline
        self.pipeline.fit(self.X_train, self.y_train, self.feature_info)
        
        # Transform the test data
        X_test_transformed, y_test_transformed = self.pipeline.transform(self.X_test, self.y_test)
        
        # Check that the transformed data has the correct shape
        self.assertEqual(X_test_transformed.shape[0], 2)  # 2 samples
        self.assertEqual(y_test_transformed.shape[0], 2)  # 2 labels
        
        # Check that the categorical features were one-hot encoded
        self.assertGreater(X_test_transformed.shape[1], 4)  # More features after one-hot encoding
        
        # Check that the numerical features were scaled
        self.assertTrue(np.all(X_test_transformed[:, 0] <= 3.0))  # Scaled values might be outside [-1, 1] for test data
        self.assertTrue(np.all(X_test_transformed[:, 0] >= -3.0))  # Scaled values might be outside [-1, 1] for test data


class TestFeatureExtractor(unittest.TestCase):
    """Test the FeatureExtractor class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a feature extractor
        self.extractor = FeatureExtractor()
    
    def test_extract_dataset_features(self):
        """Test extracting features from a dataset."""
        # Create a simple dataset for testing
        data = pd.DataFrame({
            'src_bytes': [100, 200, 300],
            'dst_bytes': [1000, 2000, 3000],
            'protocol_type': ['tcp', 'udp', 'icmp'],
            'flag': ['SF', 'REJ', 'S0']
        })
        
        # Extract features
        features = self.extractor.extract_dataset_features(data)
        
        # Check that the features were extracted correctly
        self.assertIn('bytes_ratio', features.columns)
        self.assertIn('total_bytes', features.columns)
        self.assertIn('log_src_bytes', features.columns)
        self.assertIn('log_dst_bytes', features.columns)
        
        # Check that the interaction features were created
        self.assertIn('protocol_type_flag', features.columns)
        
        # Check that the values are correct
        self.assertEqual(features['total_bytes'][0], 1100)  # 100 + 1000
        self.assertEqual(features['total_bytes'][1], 2200)  # 200 + 2000
        self.assertEqual(features['total_bytes'][2], 3300)  # 300 + 3000
        
        self.assertAlmostEqual(features['bytes_ratio'][0], 0.1)  # 100 / 1000
        self.assertAlmostEqual(features['bytes_ratio'][1], 0.1)  # 200 / 2000
        self.assertAlmostEqual(features['bytes_ratio'][2], 0.1)  # 300 / 3000


if __name__ == '__main__':
    unittest.main()