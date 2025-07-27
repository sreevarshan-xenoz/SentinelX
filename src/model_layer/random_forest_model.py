# SentinelX RandomForest Model

import numpy as np
from typing import Dict, List, Tuple, Any, Optional
import logging
from sklearn.ensemble import RandomForestClassifier

from .base_model import BaseModel
from ..core.config_manager import ConfigManager

class RandomForestModel(BaseModel):
    """Random Forest model for intrusion detection.
    
    This class implements a Random Forest classifier for detecting network intrusions.
    """
    
    def __init__(self):
        """Initialize the Random Forest model."""
        super().__init__(model_name="RandomForest")
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get hyperparameters from config
        hyperparams = self.config.get('model', 'hyperparameters', {})
        
        # Default hyperparameters if not specified in config
        self.n_estimators = hyperparams.get('n_estimators', 100)
        self.max_depth = hyperparams.get('max_depth', 10)
        self.random_state = hyperparams.get('random_state', 42)
        self.n_jobs = hyperparams.get('n_jobs', -1)  # Use all available cores
        
        # Initialize the model
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbose=0
        )
        
        self.logger.info(f"Initialized RandomForest model with {self.n_estimators} estimators")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """Train the Random Forest model.
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        self.logger.info(f"Training RandomForest model on {X_train.shape[0]} samples")
        
        # Train the model
        self.model.fit(X_train, y_train)
        
        # Log feature importances
        if hasattr(self.model, 'feature_importances_'):
            self.logger.info("Top 10 feature importances:")
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1][:10]  # Top 10 features
            for i, idx in enumerate(indices):
                self.logger.info(f"  {i+1}. Feature {idx}: {importances[idx]:.4f}")
        
        self.logger.info("RandomForest model training completed")
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions using the trained Random Forest model.
        
        Args:
            X: Input features
            
        Returns:
            Predicted labels
        """
        if self.model is None:
            raise ValueError("Model has not been trained. Call train() first.")
        
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get probability estimates for each class.
        
        Args:
            X: Input features
            
        Returns:
            Probability estimates for each class
        """
        if self.model is None:
            raise ValueError("Model has not been trained. Call train() first.")
        
        return self.model.predict_proba(X)
    
    def get_feature_importances(self, feature_names: Optional[List[str]] = None) -> Dict[str, float]:
        """Get feature importances from the trained model.
        
        Args:
            feature_names: Names of the features (optional)
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.model is None or not hasattr(self.model, 'feature_importances_'):
            raise ValueError("Model has not been trained or does not support feature importances.")
        
        importances = self.model.feature_importances_
        
        if feature_names is None:
            # Use feature indices as names
            feature_names = [f"feature_{i}" for i in range(len(importances))]
        
        # Ensure feature_names has the same length as importances
        if len(feature_names) != len(importances):
            self.logger.warning(f"Feature names length ({len(feature_names)}) does not match "
                              f"feature importances length ({len(importances)}). Using indices.")
            feature_names = [f"feature_{i}" for i in range(len(importances))]
        
        # Create dictionary of feature importances
        importance_dict = {name: float(importance) for name, importance in zip(feature_names, importances)}
        
        # Sort by importance (descending)
        importance_dict = dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
        
        return importance_dict