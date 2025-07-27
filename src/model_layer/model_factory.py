# SentinelX Model Factory

from typing import Dict, Any, Optional, Type
import logging

from .base_model import BaseModel
from .random_forest_model import RandomForestModel
# Import other model implementations as they are added
# from .xgboost_model import XGBoostModel
# from .lstm_model import LSTMModel
# from .transformer_model import TransformerModel

from ..core.config_manager import ConfigManager

class ModelFactory:
    """Factory class for creating intrusion detection models.
    
    This class is responsible for creating and managing different model instances
    based on configuration.
    """
    
    def __init__(self):
        """Initialize the model factory."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Register available models
        self.available_models: Dict[str, Type[BaseModel]] = {
            'RandomForest': RandomForestModel,
            # Add other models as they are implemented
            # 'XGBoost': XGBoostModel,
            # 'LSTM': LSTMModel,
            # 'Transformer': TransformerModel,
        }
        
        self.logger.info(f"Model factory initialized with {len(self.available_models)} available models")
    
    def get_model(self, model_type: Optional[str] = None) -> BaseModel:
        """Get a model instance based on configuration or specified type.
        
        Args:
            model_type: Type of model to create (optional, uses config if not specified)
            
        Returns:
            An instance of the specified model
            
        Raises:
            ValueError: If the specified model type is not available
        """
        # If model_type is not specified, get it from config
        if model_type is None:
            model_type = self.config.get('model', 'type', 'RandomForest')
        
        # Check if the model type is available
        if model_type not in self.available_models:
            self.logger.error(f"Model type '{model_type}' is not available")
            self.logger.info(f"Available models: {', '.join(self.available_models.keys())}")
            raise ValueError(f"Model type '{model_type}' is not available. "
                           f"Available models: {', '.join(self.available_models.keys())}")
        
        # Create and return the model instance
        model_class = self.available_models[model_type]
        model = model_class()
        
        self.logger.info(f"Created model of type '{model_type}'")
        return model
    
    def get_available_models(self) -> Dict[str, str]:
        """Get a dictionary of available models with descriptions.
        
        Returns:
            Dictionary mapping model names to descriptions
        """
        return {
            'RandomForest': 'Random Forest classifier for intrusion detection',
            # Add descriptions for other models as they are implemented
            # 'XGBoost': 'XGBoost classifier for intrusion detection',
            # 'LSTM': 'LSTM neural network for sequence-aware intrusion detection',
            # 'Transformer': 'Transformer model for contextual intrusion detection',
        }