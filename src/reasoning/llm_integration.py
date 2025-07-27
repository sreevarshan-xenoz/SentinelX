# SentinelX LLM Integration Module

import logging
import os
import json
import time
from typing import Dict, List, Any, Optional, Union, Callable
import threading
import queue
from datetime import datetime
import re

# Try to import LLM libraries
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from langchain.llms import OpenAI as LangchainOpenAI
    from langchain.prompts import PromptTemplate
    from langchain.chains import LLMChain
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

try:
    from llama_cpp import Llama
    LLAMACPP_AVAILABLE = True
except ImportError:
    LLAMACPP_AVAILABLE = False

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager


class LLMIntegration:
    """LLM Integration class for SentinelX.
    
    This class provides a unified interface for interacting with different LLM backends,
    including OpenAI, Langchain, and local models like llama.cpp.
    """
    
    def __init__(self):
        """Initialize the LLM integration."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get LLM configuration
        self.llm_config = self.config.get('reasoning', {}).get('llm', {})
        self.llm_type = self.llm_config.get('type', 'local')  # 'openai', 'local', 'langchain'
        self.model_path = self.llm_config.get('model_path', None)
        self.openai_api_key = self.llm_config.get('openai_api_key', None)
        self.openai_model = self.llm_config.get('openai_model', 'gpt-3.5-turbo')
        self.temperature = self.llm_config.get('temperature', 0.3)
        self.max_tokens = self.llm_config.get('max_tokens', 1000)
        
        # Initialize LLM
        self.llm = self._initialize_llm()
        
        # Initialize prompt templates
        self.prompt_templates = self._load_prompt_templates()
        
        self.logger.info(f"LLM integration initialized with {self.llm_type} backend")
    
    def _initialize_llm(self) -> Any:
        """Initialize the language model.
        
        Returns:
            Initialized language model or None if initialization fails
        """
        if self.llm_type == 'openai':
            if not OPENAI_AVAILABLE:
                self.logger.error("OpenAI library not available. Please install it: pip install openai")
                return None
            
            if not self.openai_api_key:
                self.logger.error("OpenAI API key not configured")
                return None
            
            # Initialize OpenAI client
            openai.api_key = self.openai_api_key
            self.logger.info(f"Initialized OpenAI client with model {self.openai_model}")
            return openai
        
        elif self.llm_type == 'langchain':
            if not LANGCHAIN_AVAILABLE:
                self.logger.error("Langchain library not available. Please install it: pip install langchain")
                return None
            
            if not self.openai_api_key:
                self.logger.error("OpenAI API key not configured for Langchain")
                return None
            
            # Initialize Langchain
            llm = LangchainOpenAI(openai_api_key=self.openai_api_key)
            self.logger.info("Initialized Langchain with OpenAI")
            return llm
        
        elif self.llm_type == 'local':
            if not LLAMACPP_AVAILABLE:
                self.logger.error("llama-cpp-python library not available. Please install it: pip install llama-cpp-python")
                return None
            
            if not self.model_path or not os.path.exists(self.model_path):
                self.logger.error(f"Local model path not found: {self.model_path}")
                return None
            
            # Initialize local LLM
            try:
                llm = Llama(model_path=self.model_path)
                self.logger.info(f"Initialized local LLM from {self.model_path}")
                return llm
            except Exception as e:
                self.logger.error(f"Error initializing local LLM: {str(e)}")
                return None
        
        else:
            self.logger.error(f"Unknown LLM type: {self.llm_type}")
            return None
    
    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load prompt templates from configuration or use defaults.
        
        Returns:
            Dictionary of prompt templates
        """
        # Get templates from config
        config_templates = self.config.get('reasoning', {}).get('prompts', {})
        
        # Default templates
        default_templates = {
            "alert_analysis": """You are a cybersecurity expert analyzing a security alert. Based on the following alert information, provide a detailed explanation of what this alert means, why it might be important, and what kind of attack it could represent. Be specific and technical, but also explain in a way that a security analyst would understand.

{context}

Explanation:""",
            
            "remediation": """You are a cybersecurity expert providing remediation advice for a security alert. Based on the following information, provide specific, actionable steps that a security team should take to address this alert. Include both immediate actions to mitigate the threat and longer-term recommendations to prevent similar issues in the future.

{context}

Remediation Steps:""",
            
            "threat_hunting": """You are a threat hunter analyzing potential security threats. Based on the following information, suggest specific threat hunting queries, indicators to look for, and techniques to identify if this threat exists elsewhere in the environment. Be specific and provide actionable advice.

{context}

Threat Hunting Recommendations:""",
            
            "attack_simulation": """You are a red team member planning an attack simulation. Based on the following alert or vulnerability information, describe how you would simulate this attack in a controlled environment to test defenses. Include specific tools, techniques, and procedures you would use.

{context}

Attack Simulation Plan:""",
            
            "executive_summary": """You are a security analyst preparing an executive summary of a security incident. Based on the following technical details, create a concise, non-technical summary suitable for executives. Focus on business impact, risk, and high-level recommendations.

{context}

Executive Summary:"""
        }
        
        # Merge default templates with config templates
        templates = {**default_templates, **config_templates}
        
        return templates
    
    def generate_response(self, prompt_template: str, context: Dict[str, Any]) -> str:
        """Generate a response using the LLM.
        
        Args:
            prompt_template: The name of the prompt template to use
            context: The context to fill in the prompt template
            
        Returns:
            Generated response
        """
        if not self.llm:
            self.logger.error("LLM not initialized, cannot generate response")
            return "Error: LLM not initialized"
        
        # Get the prompt template
        template = self.prompt_templates.get(prompt_template)
        if not template:
            self.logger.error(f"Prompt template not found: {prompt_template}")
            return f"Error: Prompt template not found: {prompt_template}"
        
        # Format the prompt with context
        try:
            # Convert context dict to string if needed
            if isinstance(context, dict):
                context_str = json.dumps(context, indent=2)
            else:
                context_str = str(context)
            
            prompt = template.format(context=context_str)
        except Exception as e:
            self.logger.error(f"Error formatting prompt: {str(e)}")
            return f"Error formatting prompt: {str(e)}"
        
        # Generate response
        try:
            if self.llm_type == 'openai':
                response = self.llm.ChatCompletion.create(
                    model=self.openai_model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature
                )
                return response.choices[0].message.content.strip()
            
            elif self.llm_type == 'langchain':
                prompt_template = PromptTemplate(template=prompt, input_variables=[])
                chain = LLMChain(llm=self.llm, prompt=prompt_template)
                return chain.run({})
            
            elif self.llm_type == 'local':
                response = self.llm(prompt, max_tokens=self.max_tokens, temperature=self.temperature, stop=["\n\n"])
                return response.strip()
            
            else:
                self.logger.error(f"Unknown LLM type: {self.llm_type}")
                return "Error: Unknown LLM type"
        
        except Exception as e:
            self.logger.error(f"Error generating response: {str(e)}")
            return f"Error generating response: {str(e)}"
    
    def generate_custom_response(self, prompt: str) -> str:
        """Generate a response using a custom prompt.
        
        Args:
            prompt: The custom prompt
            
        Returns:
            Generated response
        """
        if not self.llm:
            self.logger.error("LLM not initialized, cannot generate response")
            return "Error: LLM not initialized"
        
        # Generate response
        try:
            if self.llm_type == 'openai':
                response = self.llm.ChatCompletion.create(
                    model=self.openai_model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=self.max_tokens,
                    temperature=self.temperature
                )
                return response.choices[0].message.content.strip()
            
            elif self.llm_type == 'langchain':
                prompt_template = PromptTemplate(template=prompt, input_variables=[])
                chain = LLMChain(llm=self.llm, prompt=prompt_template)
                return chain.run({})
            
            elif self.llm_type == 'local':
                response = self.llm(prompt, max_tokens=self.max_tokens, temperature=self.temperature, stop=["\n\n"])
                return response.strip()
            
            else:
                self.logger.error(f"Unknown LLM type: {self.llm_type}")
                return "Error: Unknown LLM type"
        
        except Exception as e:
            self.logger.error(f"Error generating response: {str(e)}")
            return f"Error generating response: {str(e)}"
    
    def add_prompt_template(self, name: str, template: str) -> bool:
        """Add a new prompt template.
        
        Args:
            name: The name of the template
            template: The template string
            
        Returns:
            True if successful, False otherwise
        """
        if name in self.prompt_templates:
            self.logger.warning(f"Overwriting existing prompt template: {name}")
        
        self.prompt_templates[name] = template
        self.logger.info(f"Added prompt template: {name}")
        return True
    
    def get_prompt_template(self, name: str) -> Optional[str]:
        """Get a prompt template by name.
        
        Args:
            name: The name of the template
            
        Returns:
            The template string or None if not found
        """
        return self.prompt_templates.get(name)
    
    def list_prompt_templates(self) -> List[str]:
        """List all available prompt templates.
        
        Returns:
            List of template names
        """
        return list(self.prompt_templates.keys())
    
    def is_available(self) -> bool:
        """Check if the LLM is available.
        
        Returns:
            True if the LLM is available, False otherwise
        """
        return self.llm is not None


class AsyncLLMProcessor:
    """Asynchronous LLM processor for handling multiple requests.
    
    This class provides a queue-based approach to process multiple LLM requests
    asynchronously, which is useful for batch processing or handling concurrent requests.
    """
    
    def __init__(self, max_workers: int = 2):
        """Initialize the async LLM processor.
        
        Args:
            max_workers: Maximum number of worker threads
        """
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        self.llm = LLMIntegration()
        self.max_workers = max_workers
        self.request_queue = queue.Queue()
        self.workers = []
        self.running = False
        
        self.logger.info(f"AsyncLLMProcessor initialized with {max_workers} workers")
    
    def start(self) -> None:
        """Start the worker threads."""
        if self.running:
            self.logger.warning("AsyncLLMProcessor is already running")
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.max_workers):
            worker = threading.Thread(target=self._worker_loop, name=f"LLMWorker-{i}")
            worker.daemon = True
            worker.start()
            self.workers.append(worker)
        
        self.logger.info(f"Started {self.max_workers} LLM worker threads")
    
    def stop(self) -> None:
        """Stop the worker threads."""
        if not self.running:
            self.logger.warning("AsyncLLMProcessor is not running")
            return
        
        self.running = False
        
        # Add termination signals to the queue
        for _ in range(self.max_workers):
            self.request_queue.put(None)
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=1.0)
        
        self.workers = []
        self.logger.info("Stopped LLM worker threads")
    
    def _worker_loop(self) -> None:
        """Worker thread loop."""
        while self.running:
            try:
                # Get a request from the queue
                request = self.request_queue.get(timeout=1.0)
                
                # Check for termination signal
                if request is None:
                    self.request_queue.task_done()
                    break
                
                # Process the request
                prompt_template, context, callback = request
                
                try:
                    # Generate response
                    response = self.llm.generate_response(prompt_template, context)
                    
                    # Call the callback with the response
                    if callback:
                        callback(response, None)
                
                except Exception as e:
                    self.logger.error(f"Error processing LLM request: {str(e)}")
                    if callback:
                        callback(None, str(e))
                
                # Mark the task as done
                self.request_queue.task_done()
            
            except queue.Empty:
                # Queue timeout, continue the loop
                continue
            
            except Exception as e:
                self.logger.error(f"Error in LLM worker loop: {str(e)}")
    
    def submit_request(self, prompt_template: str, context: Dict[str, Any], 
                      callback: Optional[Callable[[str, Optional[str]], None]] = None) -> bool:
        """Submit a request to the queue.
        
        Args:
            prompt_template: The name of the prompt template to use
            context: The context to fill in the prompt template
            callback: Optional callback function to call with the response
            
        Returns:
            True if the request was submitted, False otherwise
        """
        if not self.running:
            self.logger.error("AsyncLLMProcessor is not running")
            return False
        
        try:
            self.request_queue.put((prompt_template, context, callback), timeout=1.0)
            return True
        except queue.Full:
            self.logger.error("Request queue is full")
            return False
    
    def submit_custom_request(self, prompt: str, 
                            callback: Optional[Callable[[str, Optional[str]], None]] = None) -> bool:
        """Submit a custom request to the queue.
        
        Args:
            prompt: The custom prompt
            callback: Optional callback function to call with the response
            
        Returns:
            True if the request was submitted, False otherwise
        """
        if not self.running:
            self.logger.error("AsyncLLMProcessor is not running")
            return False
        
        try:
            # Use a special prompt template name for custom prompts
            self.request_queue.put(("__custom__", prompt, callback), timeout=1.0)
            return True
        except queue.Full:
            self.logger.error("Request queue is full")
            return False
    
    def queue_size(self) -> int:
        """Get the current queue size.
        
        Returns:
            Current queue size
        """
        return self.request_queue.qsize()
    
    def is_idle(self) -> bool:
        """Check if the processor is idle.
        
        Returns:
            True if the queue is empty, False otherwise
        """
        return self.request_queue.empty()