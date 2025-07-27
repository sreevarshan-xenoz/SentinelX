# SentinelX Base Model

from abc import ABC, abstractmethod
import numpy as np
from typing import Dict, List, Tuple, Any, Optional, Union
import logging
import os
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

from ..core.config_manager import ConfigManager

class BaseModel(ABC):
    """Abstract base class for intrusion detection models.
    
    This class defines the interface that all intrusion detection models must implement.
    """
    
    def __init__(self, model_name: str):
        """Initialize the base model.
        
        Args:
            model_name: Name of the model
        """
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        self.model_name = model_name
        self.model = None
        
        # Get models directory from config
        models_dir = self.config.get('paths', 'models_dir', '../models')
        
        # Get the directory of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to the models directory
        self.models_dir = os.path.abspath(os.path.join(current_dir, '..', '..', models_dir))
        
        if not os.path.exists(self.models_dir):
            os.makedirs(self.models_dir)
            self.logger.info(f"Created models directory: {self.models_dir}")
        
        # Path to save model
        self.model_path = os.path.join(self.models_dir, f"{self.model_name}.joblib")
    
    @abstractmethod
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """Train the model on the provided data.
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        pass
    
    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions using the trained model.
        
        Args:
            X: Input features
            
        Returns:
            Predicted labels
        """
        pass
    
    @abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get probability estimates for each class.
        
        Args:
            X: Input features
            
        Returns:
            Probability estimates for each class
        """
        pass
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """Evaluate the model on test data.
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary containing evaluation metrics
        """
        if self.model is None:
            raise ValueError("Model has not been trained. Call train() first.")
        
        # Get evaluation metrics from config
        metrics = self.config.get('model', 'evaluation_metrics', 
                                 ['accuracy', 'precision', 'recall', 'f1_score'])
        
        # Make predictions
        y_pred = self.predict(X_test)
        
        # Calculate metrics
        results = {}
        
        if 'accuracy' in metrics:
            results['accuracy'] = accuracy_score(y_test, y_pred)
        
        # For multi-class classification, we use weighted averaging
        if 'precision' in metrics:
            results['precision'] = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        
        if 'recall' in metrics:
            results['recall'] = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        
        if 'f1_score' in metrics:
            results['f1_score'] = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Log results
        self.logger.info(f"Evaluation results for {self.model_name}:")
        for metric, value in results.items():
            self.logger.info(f"  {metric}: {value:.4f}")
        
        return results
    
    def plot_confusion_matrix(self, X_test: np.ndarray, y_test: np.ndarray, 
                             class_names: Optional[List[str]] = None,
                             save_path: Optional[str] = None) -> None:
        """Plot confusion matrix for model evaluation.
        
        Args:
            X_test: Test features
            y_test: Test labels
            class_names: Names of the classes (optional)
            save_path: Path to save the plot (optional)
        """
        if self.model is None:
            raise ValueError("Model has not been trained. Call train() first.")
        
        # Make predictions
        y_pred = self.predict(X_test)
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Plot confusion matrix
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=class_names, yticklabels=class_names)
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title(f'Confusion Matrix - {self.model_name}')
        
        # Save plot if path is provided
        if save_path:
            plt.savefig(save_path)
            self.logger.info(f"Confusion matrix saved to {save_path}")
        
        plt.close()
    
    def save(self) -> bool:
        """Save the model to disk.
        
        Returns:
            True if successful, False otherwise
        """
        if self.model is None:
            self.logger.error("Cannot save model: Model has not been trained.")
            return False
        
        try:
            joblib.dump(self.model, self.model_path)
            self.logger.info(f"Model saved to {self.model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            return False
    
    def load(self) -> bool:
        """Load the model from disk.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.logger.info(f"Model loaded from {self.model_path}")
                return True
            else:
                self.logger.warning(f"Model file not found at {self.model_path}")
                return False
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False