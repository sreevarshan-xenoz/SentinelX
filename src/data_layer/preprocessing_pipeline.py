# SentinelX Preprocessing Pipeline

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional, Union
import logging
from sklearn.preprocessing import StandardScaler, MinMaxScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import os

from ..core.config_manager import ConfigManager

class PreprocessingPipeline:
    """Preprocessing pipeline for network traffic data.
    
    This class handles data preprocessing tasks such as feature scaling,
    encoding categorical variables, and preparing data for model training.
    """
    
    def __init__(self, feature_info: Dict[str, Any]):
        """Initialize the preprocessing pipeline.
        
        Args:
            feature_info: Dictionary containing feature information
        """
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        self.feature_info = feature_info
        
        # Get preprocessing configuration
        self.feature_scaling = self.config.get('data_processing', 'feature_scaling', True)
        self.one_hot_encoding = self.config.get('data_processing', 'one_hot_encoding', True)
        
        # Initialize transformers
        self.numeric_transformer = None
        self.categorical_transformer = None
        self.preprocessor = None
        self.label_encoder = None
        
        # Get models directory from config
        models_dir = self.config.get('paths', 'models_dir', '../models')
        
        # Get the directory of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to the models directory
        self.models_dir = os.path.abspath(os.path.join(current_dir, '..', '..', models_dir))
        
        if not os.path.exists(self.models_dir):
            os.makedirs(self.models_dir)
            self.logger.info(f"Created models directory: {self.models_dir}")
        
        # Path to save preprocessor
        self.preprocessor_path = os.path.join(self.models_dir, 'preprocessor.joblib')
        self.label_encoder_path = os.path.join(self.models_dir, 'label_encoder.joblib')
    
    def build_pipeline(self) -> None:
        """Build the preprocessing pipeline based on configuration."""
        # Configure numeric transformer
        if self.feature_scaling:
            scaler_type = self.config.get('data_processing', 'scaler_type', 'standard')
            if scaler_type.lower() == 'minmax':
                self.numeric_transformer = Pipeline(steps=[
                    ('scaler', MinMaxScaler())
                ])
            else:  # default to standard scaler
                self.numeric_transformer = Pipeline(steps=[
                    ('scaler', StandardScaler())
                ])
        else:
            # Identity transformer (no transformation)
            self.numeric_transformer = 'passthrough'
        
        # Configure categorical transformer
        if self.one_hot_encoding:
            self.categorical_transformer = Pipeline(steps=[
                ('onehot', OneHotEncoder(handle_unknown='ignore'))
            ])
        else:
            # Use label encoding instead
            self.categorical_transformer = Pipeline(steps=[
                ('label', LabelEncoder())
            ])
        
        # Create column transformer
        transformers = []
        
        # Add numeric features
        if self.feature_info['numeric_features']:
            transformers.append(('num', self.numeric_transformer, self.feature_info['numeric_features']))
        
        # Add categorical features
        if self.feature_info['categorical_features']:
            transformers.append(('cat', self.categorical_transformer, self.feature_info['categorical_features']))
        
        # Add binary features (no transformation needed)
        if self.feature_info['binary_features']:
            transformers.append(('bin', 'passthrough', self.feature_info['binary_features']))
        
        # Create the preprocessor
        self.preprocessor = ColumnTransformer(
            transformers=transformers,
            remainder='drop'  # Drop columns not specified
        )
        
        # Create label encoder for target variable
        self.label_encoder = LabelEncoder()
        
        self.logger.info("Preprocessing pipeline built successfully")
    
    def fit_transform(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fit the preprocessing pipeline to the data and transform it.
        
        Args:
            X: Input features DataFrame
            y: Target variable Series (optional)
            
        Returns:
            Tuple containing transformed features and target (if provided)
        """
        if self.preprocessor is None:
            self.build_pipeline()
        
        # Fit and transform features
        X_transformed = self.preprocessor.fit_transform(X)
        
        # Fit and transform target if provided
        y_transformed = None
        if y is not None:
            y_transformed = self.label_encoder.fit_transform(y)
        
        self.logger.info(f"Data transformed: {X_transformed.shape} features")
        
        return X_transformed, y_transformed
    
    def transform(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Transform data using the fitted preprocessing pipeline.
        
        Args:
            X: Input features DataFrame
            y: Target variable Series (optional)
            
        Returns:
            Tuple containing transformed features and target (if provided)
        """
        if self.preprocessor is None:
            raise ValueError("Preprocessor has not been fitted. Call fit_transform first.")
        
        # Transform features
        X_transformed = self.preprocessor.transform(X)
        
        # Transform target if provided
        y_transformed = None
        if y is not None and self.label_encoder is not None:
            y_transformed = self.label_encoder.transform(y)
        
        return X_transformed, y_transformed
    
    def inverse_transform_labels(self, y: np.ndarray) -> np.ndarray:
        """Convert encoded labels back to original form.
        
        Args:
            y: Encoded labels
            
        Returns:
            Original labels
        """
        if self.label_encoder is None:
            raise ValueError("Label encoder has not been fitted.")
        
        return self.label_encoder.inverse_transform(y)
    
    def save(self) -> bool:
        """Save the preprocessing pipeline to disk.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.preprocessor is not None:
                joblib.dump(self.preprocessor, self.preprocessor_path)
                self.logger.info(f"Preprocessor saved to {self.preprocessor_path}")
            
            if self.label_encoder is not None:
                joblib.dump(self.label_encoder, self.label_encoder_path)
                self.logger.info(f"Label encoder saved to {self.label_encoder_path}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error saving preprocessing pipeline: {str(e)}")
            return False
    
    def load(self) -> bool:
        """Load the preprocessing pipeline from disk.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(self.preprocessor_path):
                self.preprocessor = joblib.load(self.preprocessor_path)
                self.logger.info(f"Preprocessor loaded from {self.preprocessor_path}")
            else:
                self.logger.warning(f"Preprocessor file not found at {self.preprocessor_path}")
                return False
            
            if os.path.exists(self.label_encoder_path):
                self.label_encoder = joblib.load(self.label_encoder_path)
                self.logger.info(f"Label encoder loaded from {self.label_encoder_path}")
            else:
                self.logger.warning(f"Label encoder file not found at {self.label_encoder_path}")
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"Error loading preprocessing pipeline: {str(e)}")
            return False