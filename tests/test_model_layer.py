#!/usr/bin/env python
# SentinelX Model Layer Tests

import os
import sys
import unittest
import tempfile
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.model_layer.base_model import BaseModel
from src.model_layer.random_forest_model import RandomForestModel
from src.model_layer.model_factory import ModelFactory
from src.core.config_manager import ConfigManager


class TestBaseModel(unittest.TestCase):
    """Test the BaseModel class."""
    
    def test_abstract_methods(self):
        """Test that abstract methods raise NotImplementedError."""
        model = BaseModel()
        
        with self.assertRaises(NotImplementedError):
            model.train(None, None)
        
        with self.assertRaises(NotImplementedError):
            model.predict(None)
        
        with self.assertRaises(NotImplementedError):
            model.predict_proba(None)


class TestRandomForestModel(unittest.TestCase):
    """Test the RandomForestModel class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
        
        # Create a temporary model directory
        self.temp_model_dir = tempfile.mkdtemp()
        
        # Create test data
        self.X_train = np.array([
            [1, 2, 3, 0, 0, 1],
            [4, 5, 6, 1, 0, 0],
            [7, 8, 9, 0, 1, 0],
            [10, 11, 12, 1, 0, 0],
            [13, 14, 15, 0, 0, 1]
        ])
        
        self.y_train = np.array(['normal', 'attack', 'normal', 'attack', 'normal'])
        
        self.X_test = np.array([
            [16, 17, 18, 0, 0, 1],
            [19, 20, 21, 1, 0, 0]
        ])
        
        self.y_test = np.array(['normal', 'attack'])
        
        # Create a model
        self.model = RandomForestModel()
    
    def tearDown(self):
        """Clean up the test environment."""
        if os.path.exists(self.temp_config.name):
            os.unlink(self.temp_config.name)
        
        # Remove temporary model files
        for root, dirs, files in os.walk(self.temp_model_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        if os.path.exists(self.temp_model_dir):
            os.rmdir(self.temp_model_dir)
    
    def test_train_predict(self):
        """Test training and prediction."""
        # Train the model
        self.model.train(self.X_train, self.y_train)
        
        # Make predictions
        y_pred = self.model.predict(self.X_test)
        
        # Check that the predictions have the correct shape
        self.assertEqual(y_pred.shape, (2,))
        
        # Check that the predictions are strings (class labels)
        self.assertIsInstance(y_pred[0], str)
    
    def test_predict_proba(self):
        """Test probability prediction."""
        # Train the model
        self.model.train(self.X_train, self.y_train)
        
        # Make probability predictions
        y_proba = self.model.predict_proba(self.X_test)
        
        # Check that the probabilities have the correct shape
        self.assertEqual(y_proba.shape, (2, 2))  # 2 samples, 2 classes
        
        # Check that the probabilities sum to 1 for each sample
        self.assertAlmostEqual(np.sum(y_proba[0]), 1.0)
        self.assertAlmostEqual(np.sum(y_proba[1]), 1.0)
    
    def test_evaluate(self):
        """Test model evaluation."""
        # Train the model
        self.model.train(self.X_train, self.y_train)
        
        # Evaluate the model
        metrics = self.model.evaluate(self.X_test, self.y_test)
        
        # Check that the metrics were calculated correctly
        self.assertIn('accuracy', metrics)
        self.assertIn('precision', metrics)
        self.assertIn('recall', metrics)
        self.assertIn('f1', metrics)
        
        # Check that the metrics are between 0 and 1
        self.assertGreaterEqual(metrics['accuracy'], 0.0)
        self.assertLessEqual(metrics['accuracy'], 1.0)
        self.assertGreaterEqual(metrics['precision'], 0.0)
        self.assertLessEqual(metrics['precision'], 1.0)
        self.assertGreaterEqual(metrics['recall'], 0.0)
        self.assertLessEqual(metrics['recall'], 1.0)
        self.assertGreaterEqual(metrics['f1'], 0.0)
        self.assertLessEqual(metrics['f1'], 1.0)
    
    def test_save_load(self):
        """Test saving and loading the model."""
        # Train the model
        self.model.train(self.X_train, self.y_train)
        
        # Save the model
        model_path = os.path.join(self.temp_model_dir, 'random_forest.joblib')
        self.model.save(model_path)
        
        # Check that the model file exists
        self.assertTrue(os.path.exists(model_path))
        
        # Create a new model
        new_model = RandomForestModel()
        
        # Load the model
        new_model.load(model_path)
        
        # Make predictions with the loaded model
        y_pred = new_model.predict(self.X_test)
        
        # Check that the predictions have the correct shape
        self.assertEqual(y_pred.shape, (2,))
        
        # Check that the predictions are strings (class labels)
        self.assertIsInstance(y_pred[0], str)
    
    def test_get_feature_importances(self):
        """Test getting feature importances."""
        # Train the model
        self.model.train(self.X_train, self.y_train)
        
        # Get feature importances
        importances = self.model.get_feature_importances()
        
        # Check that the importances have the correct shape
        self.assertEqual(importances.shape, (6,))  # 6 features
        
        # Check that the importances sum to 1
        self.assertAlmostEqual(np.sum(importances), 1.0)


class TestModelFactory(unittest.TestCase):
    """Test the ModelFactory class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
        
        # Reset ConfigManager singleton
        ConfigManager._instance = None
        
        # Create the factory
        self.factory = ModelFactory()
    
    def tearDown(self):
        """Clean up the test environment."""
        if os.path.exists(self.temp_config.name):
            os.unlink(self.temp_config.name)
    
    def test_get_model(self):
        """Test getting a model from the factory."""
        # Get a RandomForestModel
        model = self.factory.get_model('random_forest')
        
        # Check that the model is a RandomForestModel
        self.assertIsInstance(model, RandomForestModel)
        
        # Try to get a non-existent model
        with self.assertRaises(ValueError):
            self.factory.get_model('non_existent_model')
    
    def test_list_models(self):
        """Test listing available models."""
        # Get the list of available models
        models = self.factory.list_models()
        
        # Check that the list contains RandomForestModel
        self.assertIn('random_forest', models)


if __name__ == '__main__':
    unittest.main()