# SentinelX Threat Reasoning Module

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
from ..threat_enrichment.alert_manager import Alert


class ThreatReasoning:
    """Threat reasoning class for SentinelX.
    
    This class is responsible for generating human-readable explanations of detected threats,
    contextualizing alerts with known CVEs and MITRE ATT&CK patterns, and suggesting remediation steps.
    """
    
    def __init__(self):
        """Initialize the threat reasoning module."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get reasoning configuration
        self.reasoning_config = self.config.get('reasoning', {})
        self.llm_type = self.reasoning_config.get('llm_type', 'local')  # 'openai', 'local', 'langchain'
        self.model_path = self.reasoning_config.get('model_path', None)
        self.openai_api_key = self.reasoning_config.get('openai_api_key', None)
        self.openai_model = self.reasoning_config.get('openai_model', 'gpt-3.5-turbo')
        
        # Initialize LLM
        self.llm = self._initialize_llm()
        
        # Load MITRE ATT&CK data
        self.mitre_data = self._load_mitre_data()
        
        # Load CVE data
        self.cve_data = self._load_cve_data()
        
        self.logger.info("Threat reasoning module initialized")
    
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
    
    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK data.
        
        Returns:
            Dictionary of MITRE ATT&CK data
        """
        mitre_file = self.reasoning_config.get('mitre_file', None)
        
        if not mitre_file or not os.path.exists(mitre_file):
            self.logger.warning(f"MITRE ATT&CK data file not found: {mitre_file}")
            return {}
        
        try:
            with open(mitre_file, 'r') as f:
                data = json.load(f)
            
            self.logger.info(f"Loaded MITRE ATT&CK data from {mitre_file}")
            return data
        except Exception as e:
            self.logger.error(f"Error loading MITRE ATT&CK data: {str(e)}")
            return {}
    
    def _load_cve_data(self) -> Dict[str, Any]:
        """Load CVE data.
        
        Returns:
            Dictionary of CVE data
        """
        cve_file = self.reasoning_config.get('cve_file', None)
        
        if not cve_file or not os.path.exists(cve_file):
            self.logger.warning(f"CVE data file not found: {cve_file}")
            return {}
        
        try:
            with open(cve_file, 'r') as f:
                data = json.load(f)
            
            self.logger.info(f"Loaded CVE data from {cve_file}")
            return data
        except Exception as e:
            self.logger.error(f"Error loading CVE data: {str(e)}")
            return {}
    
    def analyze_alert(self, alert: Alert) -> Dict[str, Any]:
        """Analyze an alert and generate a human-readable explanation.
        
        Args:
            alert: The alert to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        if not self.llm:
            self.logger.error("LLM not initialized, cannot analyze alert")
            return {
                "success": False,
                "error": "LLM not initialized"
            }
        
        # Prepare context for the LLM
        context = self._prepare_context(alert)
        
        # Generate explanation
        explanation = self._generate_explanation(context)
        
        # Extract insights
        insights = self._extract_insights(explanation)
        
        # Find related MITRE ATT&CK techniques
        mitre_techniques = self._find_mitre_techniques(alert, explanation)
        
        # Find related CVEs
        cves = self._find_cves(alert, explanation)
        
        # Generate remediation steps
        remediation = self._generate_remediation(alert, explanation, mitre_techniques, cves)
        
        return {
            "success": True,
            "alert_id": alert.alert_id,
            "timestamp": datetime.now().isoformat(),
            "explanation": explanation,
            "insights": insights,
            "mitre_techniques": mitre_techniques,
            "cves": cves,
            "remediation": remediation
        }
    
    def _prepare_context(self, alert: Alert) -> str:
        """Prepare context for the LLM.
        
        Args:
            alert: The alert to prepare context for
            
        Returns:
            Context string for the LLM
        """
        context = f"""Alert Information:
- Alert ID: {alert.alert_id}
- Type: {alert.alert_type}
- Severity: {alert.severity}
- Source: {alert.source}
- Timestamp: {alert.timestamp}

Alert Details:
{json.dumps(alert.details, indent=2)}
"""
        
        # Add enrichment data if available
        if alert.enrichment:
            context += f"\nEnrichment Data:\n{json.dumps(alert.enrichment, indent=2)}"
        
        return context
    
    def _generate_explanation(self, context: str) -> str:
        """Generate a human-readable explanation using the LLM.
        
        Args:
            context: Context string for the LLM
            
        Returns:
            Generated explanation
        """
        prompt = f"""You are a cybersecurity expert analyzing a security alert. Based on the following alert information, provide a detailed explanation of what this alert means, why it might be important, and what kind of attack it could represent. Be specific and technical, but also explain in a way that a security analyst would understand.

{context}

Explanation:"""
        
        try:
            if self.llm_type == 'openai':
                response = self.llm.ChatCompletion.create(
                    model=self.openai_model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.3
                )
                return response.choices[0].message.content.strip()
            
            elif self.llm_type == 'langchain':
                prompt_template = PromptTemplate(template=prompt, input_variables=[])
                chain = LLMChain(llm=self.llm, prompt=prompt_template)
                return chain.run({})
            
            elif self.llm_type == 'local':
                response = self.llm(prompt, max_tokens=1000, temperature=0.3, stop=["\n\n"])
                return response.strip()
            
            else:
                self.logger.error(f"Unknown LLM type: {self.llm_type}")
                return "Error: Unknown LLM type"
        
        except Exception as e:
            self.logger.error(f"Error generating explanation: {str(e)}")
            return f"Error generating explanation: {str(e)}"
    
    def _extract_insights(self, explanation: str) -> List[str]:
        """Extract key insights from the explanation.
        
        Args:
            explanation: The generated explanation
            
        Returns:
            List of key insights
        """
        # Simple extraction based on bullet points or numbered lists
        insights = []
        
        # Look for bullet points
        bullet_pattern = r'[•\*\-]\s+(.+?)(?=[•\*\-]|$)'
        bullet_matches = re.findall(bullet_pattern, explanation, re.DOTALL)
        insights.extend([match.strip() for match in bullet_matches])
        
        # Look for numbered lists
        numbered_pattern = r'\d+\.\s+(.+?)(?=\d+\.|$)'
        numbered_matches = re.findall(numbered_pattern, explanation, re.DOTALL)
        insights.extend([match.strip() for match in numbered_matches])
        
        # If no structured insights found, split by sentences and take the first few
        if not insights:
            sentences = re.split(r'(?<=[.!?])\s+', explanation)
            insights = [s.strip() for s in sentences[:3] if len(s.strip()) > 20]
        
        return insights
    
    def _find_mitre_techniques(self, alert: Alert, explanation: str) -> List[Dict[str, Any]]:
        """Find related MITRE ATT&CK techniques.
        
        Args:
            alert: The alert being analyzed
            explanation: The generated explanation
            
        Returns:
            List of related MITRE ATT&CK techniques
        """
        if not self.mitre_data:
            return []
        
        techniques = []
        
        # Extract potential technique IDs from the explanation (e.g., T1234)
        technique_ids = re.findall(r'T\d{4}(?:\.\d{3})?', explanation)
        
        # Add techniques mentioned by ID
        for technique_id in technique_ids:
            if technique_id in self.mitre_data:
                techniques.append({
                    "id": technique_id,
                    "name": self.mitre_data[technique_id].get("name", "Unknown"),
                    "description": self.mitre_data[technique_id].get("description", "No description available"),
                    "tactics": self.mitre_data[technique_id].get("tactics", []),
                    "url": f"https://attack.mitre.org/techniques/{technique_id}/"
                })
        
        # If no techniques found by ID, try to match by keywords
        if not techniques:
            # Combine alert details and explanation for keyword matching
            text_to_search = explanation
            if alert.details:
                text_to_search += " " + json.dumps(alert.details)
            
            # Search for technique names in the text
            for technique_id, technique_data in self.mitre_data.items():
                technique_name = technique_data.get("name", "").lower()
                if technique_name and technique_name in text_to_search.lower():
                    techniques.append({
                        "id": technique_id,
                        "name": technique_data.get("name", "Unknown"),
                        "description": technique_data.get("description", "No description available"),
                        "tactics": technique_data.get("tactics", []),
                        "url": f"https://attack.mitre.org/techniques/{technique_id}/"
                    })
        
        # Limit to top 5 techniques
        return techniques[:5]
    
    def _find_cves(self, alert: Alert, explanation: str) -> List[Dict[str, Any]]:
        """Find related CVEs.
        
        Args:
            alert: The alert being analyzed
            explanation: The generated explanation
            
        Returns:
            List of related CVEs
        """
        if not self.cve_data:
            return []
        
        cves = []
        
        # Extract potential CVE IDs from the explanation (e.g., CVE-2021-1234)
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', explanation)
        
        # Add CVEs mentioned by ID
        for cve_id in cve_ids:
            if cve_id in self.cve_data:
                cves.append({
                    "id": cve_id,
                    "description": self.cve_data[cve_id].get("description", "No description available"),
                    "severity": self.cve_data[cve_id].get("severity", "Unknown"),
                    "published": self.cve_data[cve_id].get("published", "Unknown"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
        
        # If no CVEs found by ID, try to match by keywords from enrichment data
        if not cves and alert.enrichment:
            # Look for malware names or attack patterns in enrichment data
            malware_names = []
            if 'ip' in alert.enrichment and 'sources' in alert.enrichment['ip']:
                for source, data in alert.enrichment['ip']['sources'].items():
                    if 'malware' in data:
                        malware_names.extend(data['malware'])
            
            # Search for malware names in CVE descriptions
            for malware in malware_names:
                for cve_id, cve_data in self.cve_data.items():
                    description = cve_data.get("description", "").lower()
                    if malware.lower() in description:
                        cves.append({
                            "id": cve_id,
                            "description": cve_data.get("description", "No description available"),
                            "severity": cve_data.get("severity", "Unknown"),
                            "published": cve_data.get("published", "Unknown"),
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        })
        
        # Limit to top 5 CVEs
        return cves[:5]
    
    def _generate_remediation(self, alert: Alert, explanation: str, 
                            mitre_techniques: List[Dict[str, Any]],
                            cves: List[Dict[str, Any]]) -> str:
        """Generate remediation steps.
        
        Args:
            alert: The alert being analyzed
            explanation: The generated explanation
            mitre_techniques: Related MITRE ATT&CK techniques
            cves: Related CVEs
            
        Returns:
            Remediation steps
        """
        # Prepare context for remediation
        context = f"""Alert Information:
- Alert ID: {alert.alert_id}
- Type: {alert.alert_type}
- Severity: {alert.severity}

Alert Explanation:
{explanation}
"""
        
        # Add MITRE techniques
        if mitre_techniques:
            context += "\nRelated MITRE ATT&CK Techniques:\n"
            for technique in mitre_techniques:
                context += f"- {technique['id']}: {technique['name']}\n"
        
        # Add CVEs
        if cves:
            context += "\nRelated CVEs:\n"
            for cve in cves:
                context += f"- {cve['id']}: {cve['description']}\n"
        
        # Generate remediation steps
        prompt = f"""You are a cybersecurity expert providing remediation advice for a security alert. Based on the following information, provide specific, actionable steps that a security team should take to address this alert. Include both immediate actions to mitigate the threat and longer-term recommendations to prevent similar issues in the future.

{context}

Remediation Steps:"""
        
        try:
            if self.llm_type == 'openai':
                response = self.llm.ChatCompletion.create(
                    model=self.openai_model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.3
                )
                return response.choices[0].message.content.strip()
            
            elif self.llm_type == 'langchain':
                prompt_template = PromptTemplate(template=prompt, input_variables=[])
                chain = LLMChain(llm=self.llm, prompt=prompt_template)
                return chain.run({})
            
            elif self.llm_type == 'local':
                response = self.llm(prompt, max_tokens=1000, temperature=0.3, stop=["\n\n"])
                return response.strip()
            
            else:
                self.logger.error(f"Unknown LLM type: {self.llm_type}")
                return "Error: Unknown LLM type"
        
        except Exception as e:
            self.logger.error(f"Error generating remediation: {str(e)}")
            return f"Error generating remediation: {str(e)}"
    
    def batch_analyze_alerts(self, alerts: List[Alert]) -> List[Dict[str, Any]]:
        """Analyze multiple alerts in batch.
        
        Args:
            alerts: List of alerts to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        
        for alert in alerts:
            try:
                result = self.analyze_alert(alert)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error analyzing alert {alert.alert_id}: {str(e)}")
                results.append({
                    "success": False,
                    "alert_id": alert.alert_id,
                    "error": str(e)
                })
        
        return results
    
    def download_mitre_data(self, output_file: Optional[str] = None) -> bool:
        """Download the latest MITRE ATT&CK data.
        
        Args:
            output_file: Path to save the data (optional)
            
        Returns:
            True if successful, False otherwise
        """
        import requests
        
        # MITRE ATT&CK Enterprise data URL
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            # Download data
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            # Process data into a more usable format
            techniques = {}
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    technique_id = obj.get('external_references', [{}])[0].get('external_id')
                    if technique_id and technique_id.startswith('T'):
                        # Extract tactics (kill chain phases)
                        tactics = []
                        for phase in obj.get('kill_chain_phases', []):
                            if phase.get('kill_chain_name') == 'mitre-attack':
                                tactics.append(phase.get('phase_name'))
                        
                        techniques[technique_id] = {
                            "name": obj.get('name', 'Unknown'),
                            "description": obj.get('description', 'No description available'),
                            "tactics": tactics
                        }
            
            # Determine output file
            if not output_file:
                output_file = self.reasoning_config.get('mitre_file', 'mitre_attack.json')
            
            # Save data
            with open(output_file, 'w') as f:
                json.dump(techniques, f, indent=2)
            
            # Update internal data
            self.mitre_data = techniques
            
            self.logger.info(f"Downloaded MITRE ATT&CK data with {len(techniques)} techniques to {output_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error downloading MITRE ATT&CK data: {str(e)}")
            return False
    
    def download_cve_data(self, output_file: Optional[str] = None, limit: int = 1000) -> bool:
        """Download recent CVE data.
        
        Args:
            output_file: Path to save the data (optional)
            limit: Maximum number of CVEs to download
            
        Returns:
            True if successful, False otherwise
        """
        import requests
        
        # NVD API URL for recent CVEs
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={limit}"
        
        try:
            # Download data
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            # Process data into a more usable format
            cves = {}
            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id')
                if cve_id:
                    # Get description
                    descriptions = cve_data.get('descriptions', [])
                    description = next((d.get('value') for d in descriptions if d.get('lang') == 'en'), 'No description available')
                    
                    # Get metrics
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    severity = cvss_v3.get('baseSeverity', 'Unknown')
                    
                    # Get published date
                    published = cve_data.get('published', 'Unknown')
                    
                    cves[cve_id] = {
                        "description": description,
                        "severity": severity,
                        "published": published
                    }
            
            # Determine output file
            if not output_file:
                output_file = self.reasoning_config.get('cve_file', 'cve_data.json')
            
            # Save data
            with open(output_file, 'w') as f:
                json.dump(cves, f, indent=2)
            
            # Update internal data
            self.cve_data = cves
            
            self.logger.info(f"Downloaded {len(cves)} CVEs to {output_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error downloading CVE data: {str(e)}")
            return False