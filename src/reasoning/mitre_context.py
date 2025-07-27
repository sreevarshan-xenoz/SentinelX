# SentinelX MITRE ATT&CK Context Module

import logging
import os
import json
import time
from typing import Dict, List, Any, Optional, Union
import re
import requests
from datetime import datetime

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager
from ..threat_enrichment.alert_manager import Alert


class MITREContext:
    """MITRE ATT&CK context provider for SentinelX.
    
    This class is responsible for mapping alerts to MITRE ATT&CK techniques and tactics,
    providing context about attack patterns, and suggesting defensive measures.
    """
    
    def __init__(self):
        """Initialize the MITRE ATT&CK context provider."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get MITRE configuration
        self.mitre_config = self.config.get('reasoning', {}).get('mitre', {})
        self.mitre_file = self.mitre_config.get('mitre_file', None)
        
        # Load MITRE ATT&CK data
        self.mitre_data = self._load_mitre_data()
        
        # Load technique mappings
        self.technique_mappings = self._load_technique_mappings()
        
        self.logger.info("MITRE ATT&CK context provider initialized")
    
    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK data.
        
        Returns:
            Dictionary of MITRE ATT&CK data
        """
        if not self.mitre_file or not os.path.exists(self.mitre_file):
            self.logger.warning(f"MITRE ATT&CK data file not found: {self.mitre_file}")
            return {}
        
        try:
            with open(self.mitre_file, 'r') as f:
                data = json.load(f)
            
            self.logger.info(f"Loaded MITRE ATT&CK data from {self.mitre_file}")
            return data
        except Exception as e:
            self.logger.error(f"Error loading MITRE ATT&CK data: {str(e)}")
            return {}
    
    def _load_technique_mappings(self) -> Dict[str, List[str]]:
        """Load technique mappings for alert types.
        
        Returns:
            Dictionary mapping alert types to MITRE technique IDs
        """
        mappings_file = self.mitre_config.get('mappings_file', None)
        
        if not mappings_file or not os.path.exists(mappings_file):
            self.logger.warning(f"Technique mappings file not found: {mappings_file}")
            return self._get_default_mappings()
        
        try:
            with open(mappings_file, 'r') as f:
                mappings = json.load(f)
            
            self.logger.info(f"Loaded technique mappings from {mappings_file}")
            return mappings
        except Exception as e:
            self.logger.error(f"Error loading technique mappings: {str(e)}")
            return self._get_default_mappings()
    
    def _get_default_mappings(self) -> Dict[str, List[str]]:
        """Get default technique mappings.
        
        Returns:
            Dictionary of default mappings
        """
        # Default mappings for common alert types
        default_mappings = {
            "port_scan": ["T1046"],  # Network Service Scanning
            "brute_force": ["T1110"],  # Brute Force
            "credential_access": ["T1110", "T1555", "T1212"],  # Brute Force, Credentials from Password Stores, Exploitation for Credential Access
            "lateral_movement": ["T1021", "T1091", "T1534"],  # Remote Services, Replication Through Removable Media, Internal Spearphishing
            "privilege_escalation": ["T1068", "T1134", "T1484"],  # Exploitation for Privilege Escalation, Access Token Manipulation, Domain Policy Modification
            "defense_evasion": ["T1070", "T1027", "T1562"],  # Indicator Removal on Host, Obfuscated Files or Information, Impair Defenses
            "persistence": ["T1098", "T1136", "T1505"],  # Account Manipulation, Create Account, Server Software Component
            "command_and_control": ["T1071", "T1090", "T1572"],  # Application Layer Protocol, Proxy, Protocol Tunneling
            "exfiltration": ["T1048", "T1567", "T1020"],  # Exfiltration Over Alternative Protocol, Exfiltration Over Web Service, Automated Exfiltration
            "impact": ["T1485", "T1486", "T1489"],  # Data Destruction, Data Encrypted for Impact, Service Stop
            "reconnaissance": ["T1595", "T1592", "T1590"],  # Active Scanning, Gather Victim Host Information, Gather Victim Network Information
            "resource_development": ["T1583", "T1587", "T1588"],  # Acquire Infrastructure, Develop Capabilities, Obtain Capabilities
            "initial_access": ["T1190", "T1133", "T1566"],  # Exploit Public-Facing Application, External Remote Services, Phishing
            "execution": ["T1059", "T1203", "T1569"],  # Command and Scripting Interpreter, Exploitation for Client Execution, System Services
            "collection": ["T1560", "T1113", "T1114"],  # Archive Collected Data, Screen Capture, Email Collection
            "discovery": ["T1087", "T1082", "T1018"],  # Account Discovery, System Information Discovery, Remote System Discovery
            "malware": ["T1059", "T1027", "T1055"],  # Command and Scripting Interpreter, Obfuscated Files or Information, Process Injection
            "anomaly": ["T1078", "T1204", "T1195"],  # Valid Accounts, User Execution, Supply Chain Compromise
            "dos": ["T1498", "T1499"],  # Network Denial of Service, Endpoint Denial of Service
            "web_attack": ["T1190", "T1059.007"],  # Exploit Public-Facing Application, Command and Scripting Interpreter: JavaScript
            "sql_injection": ["T1190"],  # Exploit Public-Facing Application
            "xss": ["T1059.007"],  # Command and Scripting Interpreter: JavaScript
            "file_inclusion": ["T1190"],  # Exploit Public-Facing Application
            "backdoor": ["T1133", "T1505"],  # External Remote Services, Server Software Component
            "trojan": ["T1204", "T1059"],  # User Execution, Command and Scripting Interpreter
            "ransomware": ["T1486", "T1489"],  # Data Encrypted for Impact, Service Stop
            "cryptominer": ["T1496"],  # Resource Hijacking
            "botnet": ["T1071", "T1498"],  # Application Layer Protocol, Network Denial of Service
            "data_exfiltration": ["T1048", "T1567"],  # Exfiltration Over Alternative Protocol, Exfiltration Over Web Service
            "suspicious_traffic": ["T1071", "T1095", "T1571"],  # Application Layer Protocol, Non-Application Layer Protocol, Non-Standard Port
            "suspicious_process": ["T1059", "T1055", "T1569"],  # Command and Scripting Interpreter, Process Injection, System Services
            "suspicious_file": ["T1027", "T1140", "T1553"],  # Obfuscated Files or Information, Deobfuscate/Decode Files or Information, Subvert Trust Controls
            "suspicious_email": ["T1566"],  # Phishing
            "suspicious_login": ["T1078", "T1110"],  # Valid Accounts, Brute Force
            "suspicious_account": ["T1136", "T1098"],  # Create Account, Account Manipulation
            "suspicious_command": ["T1059"],  # Command and Scripting Interpreter
            "suspicious_script": ["T1059"],  # Command and Scripting Interpreter
            "suspicious_network": ["T1046", "T1048", "T1071"],  # Network Service Scanning, Exfiltration Over Alternative Protocol, Application Layer Protocol
        }
        
        return default_mappings
    
    def map_alert_to_techniques(self, alert: Alert) -> List[Dict[str, Any]]:
        """Map an alert to MITRE ATT&CK techniques.
        
        Args:
            alert: The alert to map
            
        Returns:
            List of mapped techniques with details
        """
        if not self.mitre_data:
            self.logger.warning("MITRE ATT&CK data not loaded, cannot map alert")
            return []
        
        techniques = []
        
        # Try to map based on alert type
        alert_type = alert.alert_type.lower()
        mapped_technique_ids = self.technique_mappings.get(alert_type, [])
        
        # Add techniques from mappings
        for technique_id in mapped_technique_ids:
            if technique_id in self.mitre_data:
                techniques.append(self._get_technique_details(technique_id))
        
        # Try to extract technique IDs from alert details or enrichment
        extracted_ids = self._extract_technique_ids(alert)
        for technique_id in extracted_ids:
            if technique_id in self.mitre_data and technique_id not in mapped_technique_ids:
                techniques.append(self._get_technique_details(technique_id))
        
        # Try to match based on keywords in alert details
        if not techniques:
            keyword_matches = self._match_by_keywords(alert)
            techniques.extend(keyword_matches)
        
        return techniques
    
    def _get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """Get details for a MITRE ATT&CK technique.
        
        Args:
            technique_id: The technique ID
            
        Returns:
            Dictionary of technique details
        """
        technique_data = self.mitre_data.get(technique_id, {})
        
        return {
            "id": technique_id,
            "name": technique_data.get("name", "Unknown"),
            "description": technique_data.get("description", "No description available"),
            "tactics": technique_data.get("tactics", []),
            "url": f"https://attack.mitre.org/techniques/{technique_id}/"
        }
    
    def _extract_technique_ids(self, alert: Alert) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from alert data.
        
        Args:
            alert: The alert to extract from
            
        Returns:
            List of extracted technique IDs
        """
        technique_ids = []
        
        # Convert alert details and enrichment to string for regex search
        text_to_search = ""
        
        if alert.details:
            text_to_search += json.dumps(alert.details)
        
        if alert.enrichment:
            text_to_search += json.dumps(alert.enrichment)
        
        # Extract technique IDs (e.g., T1234, T1234.001)
        matches = re.findall(r'T\d{4}(?:\.\d{3})?', text_to_search)
        technique_ids.extend(matches)
        
        return technique_ids
    
    def _match_by_keywords(self, alert: Alert) -> List[Dict[str, Any]]:
        """Match alert to techniques based on keywords.
        
        Args:
            alert: The alert to match
            
        Returns:
            List of matched techniques with details
        """
        matches = []
        
        # Convert alert details to string for keyword matching
        text_to_search = ""
        
        if alert.details:
            text_to_search += json.dumps(alert.details).lower()
        
        if alert.enrichment:
            text_to_search += json.dumps(alert.enrichment).lower()
        
        # Add alert type and source
        text_to_search += f" {alert.alert_type.lower()} {alert.source.lower()}"
        
        # Match against technique names and descriptions
        for technique_id, technique_data in self.mitre_data.items():
            name = technique_data.get("name", "").lower()
            description = technique_data.get("description", "").lower()
            
            # Check if technique name or keywords from description appear in the alert
            if name and name in text_to_search:
                matches.append(self._get_technique_details(technique_id))
                continue
            
            # Extract keywords from description and check if they appear in the alert
            # This is a simple approach; more sophisticated NLP could be used
            keywords = self._extract_keywords(description)
            keyword_matches = sum(1 for keyword in keywords if keyword in text_to_search)
            
            # If multiple keywords match, consider it a match
            if keyword_matches >= 3:  # Arbitrary threshold, can be adjusted
                matches.append(self._get_technique_details(technique_id))
        
        # Limit to top 5 matches to avoid overwhelming
        return matches[:5]
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text.
        
        Args:
            text: The text to extract keywords from
            
        Returns:
            List of keywords
        """
        # Simple keyword extraction by splitting and filtering
        # More sophisticated NLP could be used here
        words = re.findall(r'\b[a-z]{4,}\b', text.lower())
        
        # Filter out common words
        stopwords = {
            'this', 'that', 'these', 'those', 'with', 'from', 'have', 'has', 'had',
            'were', 'been', 'being', 'which', 'where', 'when', 'what', 'will', 'would',
            'should', 'could', 'their', 'there', 'they', 'them', 'then', 'than',
            'some', 'such', 'also', 'however', 'therefore', 'thus', 'although',
            'because', 'since', 'while', 'about', 'above', 'across', 'after',
            'against', 'along', 'among', 'around', 'before', 'behind', 'below',
            'beneath', 'beside', 'between', 'beyond', 'during', 'except', 'inside',
            'into', 'like', 'near', 'onto', 'outside', 'over', 'through', 'throughout',
            'under', 'until', 'within', 'without'
        }
        
        keywords = [word for word in words if word not in stopwords]
        
        return keywords
    
    def get_tactic_details(self, tactic_name: str) -> Dict[str, Any]:
        """Get details for a MITRE ATT&CK tactic.
        
        Args:
            tactic_name: The tactic name (e.g., 'initial-access')
            
        Returns:
            Dictionary of tactic details
        """
        # Map of tactic names to their details
        tactics = {
            "reconnaissance": {
                "name": "Reconnaissance",
                "description": "The adversary is trying to gather information they can use to plan future operations.",
                "url": "https://attack.mitre.org/tactics/TA0043/"
            },
            "resource-development": {
                "name": "Resource Development",
                "description": "The adversary is trying to establish resources they can use to support operations.",
                "url": "https://attack.mitre.org/tactics/TA0042/"
            },
            "initial-access": {
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network.",
                "url": "https://attack.mitre.org/tactics/TA0001/"
            },
            "execution": {
                "name": "Execution",
                "description": "The adversary is trying to run malicious code.",
                "url": "https://attack.mitre.org/tactics/TA0002/"
            },
            "persistence": {
                "name": "Persistence",
                "description": "The adversary is trying to maintain their foothold.",
                "url": "https://attack.mitre.org/tactics/TA0003/"
            },
            "privilege-escalation": {
                "name": "Privilege Escalation",
                "description": "The adversary is trying to gain higher-level permissions.",
                "url": "https://attack.mitre.org/tactics/TA0004/"
            },
            "defense-evasion": {
                "name": "Defense Evasion",
                "description": "The adversary is trying to avoid being detected.",
                "url": "https://attack.mitre.org/tactics/TA0005/"
            },
            "credential-access": {
                "name": "Credential Access",
                "description": "The adversary is trying to steal account names and passwords.",
                "url": "https://attack.mitre.org/tactics/TA0006/"
            },
            "discovery": {
                "name": "Discovery",
                "description": "The adversary is trying to figure out your environment.",
                "url": "https://attack.mitre.org/tactics/TA0007/"
            },
            "lateral-movement": {
                "name": "Lateral Movement",
                "description": "The adversary is trying to move through your environment.",
                "url": "https://attack.mitre.org/tactics/TA0008/"
            },
            "collection": {
                "name": "Collection",
                "description": "The adversary is trying to gather data of interest to their goal.",
                "url": "https://attack.mitre.org/tactics/TA0009/"
            },
            "command-and-control": {
                "name": "Command and Control",
                "description": "The adversary is trying to communicate with compromised systems to control them.",
                "url": "https://attack.mitre.org/tactics/TA0011/"
            },
            "exfiltration": {
                "name": "Exfiltration",
                "description": "The adversary is trying to steal data.",
                "url": "https://attack.mitre.org/tactics/TA0010/"
            },
            "impact": {
                "name": "Impact",
                "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                "url": "https://attack.mitre.org/tactics/TA0040/"
            }
        }
        
        # Normalize tactic name
        normalized_name = tactic_name.lower().replace('_', '-')
        
        return tactics.get(normalized_name, {
            "name": tactic_name,
            "description": "No description available",
            "url": "https://attack.mitre.org/tactics/"
        })
    
    def get_techniques_by_tactic(self, tactic_name: str) -> List[Dict[str, Any]]:
        """Get techniques for a specific tactic.
        
        Args:
            tactic_name: The tactic name (e.g., 'initial-access')
            
        Returns:
            List of techniques for the tactic
        """
        if not self.mitre_data:
            self.logger.warning("MITRE ATT&CK data not loaded, cannot get techniques by tactic")
            return []
        
        # Normalize tactic name
        normalized_name = tactic_name.lower().replace('-', '_')
        
        techniques = []
        for technique_id, technique_data in self.mitre_data.items():
            tactics = technique_data.get("tactics", [])
            if normalized_name in tactics:
                techniques.append(self._get_technique_details(technique_id))
        
        return techniques
    
    def get_defensive_measures(self, technique_id: str) -> Dict[str, Any]:
        """Get defensive measures for a specific technique.
        
        Args:
            technique_id: The technique ID
            
        Returns:
            Dictionary of defensive measures
        """
        # This would ideally come from a database of defensive measures
        # For now, we'll return some generic advice based on the technique
        
        if not technique_id in self.mitre_data:
            self.logger.warning(f"Technique ID not found: {technique_id}")
            return {
                "mitigations": [],
                "detections": []
            }
        
        technique_data = self.mitre_data[technique_id]
        technique_name = technique_data.get("name", "Unknown")
        tactics = technique_data.get("tactics", [])
        
        # Generic mitigations based on tactic
        mitigations = []
        detections = []
        
        if "initial_access" in tactics:
            mitigations.extend([
                "Implement network segmentation and restrict inbound connections",
                "Use multi-factor authentication for all remote access",
                "Keep systems and applications updated with the latest patches",
                "Implement email filtering and web content filtering"
            ])
            detections.extend([
                "Monitor for unusual authentication attempts",
                "Monitor for connections from unusual geographic locations",
                "Deploy network IDS/IPS to detect exploitation attempts",
                "Monitor for unusual email attachments and links"
            ])
        
        if "execution" in tactics:
            mitigations.extend([
                "Implement application whitelisting",
                "Restrict execution of scripts and interpreted code",
                "Use least privilege principles for user accounts",
                "Implement Software Restriction Policies or AppLocker"
            ])
            detections.extend([
                "Monitor for unusual process executions",
                "Monitor for script executions (PowerShell, VBScript, etc.)",
                "Deploy endpoint detection and response (EDR) solutions",
                "Monitor command-line arguments for suspicious patterns"
            ])
        
        if "persistence" in tactics:
            mitigations.extend([
                "Regularly audit user accounts and permissions",
                "Monitor and validate scheduled tasks and services",
                "Use secure boot mechanisms",
                "Implement host-based firewalls"
            ])
            detections.extend([
                "Monitor for new or modified scheduled tasks",
                "Monitor for new or modified services",
                "Monitor registry for persistence mechanisms",
                "Monitor startup folders and run keys"
            ])
        
        if "privilege_escalation" in tactics:
            mitigations.extend([
                "Keep systems and applications updated with the latest patches",
                "Use least privilege principles for user accounts",
                "Implement application whitelisting",
                "Use privileged access management solutions"
            ])
            detections.extend([
                "Monitor for unusual privilege changes",
                "Monitor for exploitation of known vulnerabilities",
                "Monitor for unusual process access patterns",
                "Monitor for unusual service installations"
            ])
        
        if "defense_evasion" in tactics:
            mitigations.extend([
                "Implement centralized logging",
                "Use application whitelisting",
                "Deploy anti-malware solutions with behavioral detection",
                "Implement file integrity monitoring"
            ])
            detections.extend([
                "Monitor for log clearing or tampering",
                "Monitor for unusual file modifications or deletions",
                "Monitor for known obfuscation techniques",
                "Monitor for disabling of security tools"
            ])
        
        if "credential_access" in tactics:
            mitigations.extend([
                "Use multi-factor authentication",
                "Implement strong password policies",
                "Protect credential storage",
                "Use privileged access management solutions"
            ])
            detections.extend([
                "Monitor for brute force attempts",
                "Monitor for credential dumping tools",
                "Monitor for access to credential stores",
                "Monitor for unusual authentication patterns"
            ])
        
        if "discovery" in tactics:
            mitigations.extend([
                "Implement network segmentation",
                "Use least privilege principles",
                "Hide sensitive information from unauthorized users",
                "Implement honeypots and honeyfiles"
            ])
            detections.extend([
                "Monitor for unusual network scanning activity",
                "Monitor for enumeration commands",
                "Monitor for unusual queries to directory services",
                "Monitor for unusual system information gathering"
            ])
        
        if "lateral_movement" in tactics:
            mitigations.extend([
                "Implement network segmentation",
                "Use multi-factor authentication",
                "Implement account lockout policies",
                "Restrict lateral tool transfer"
            ])
            detections.extend([
                "Monitor for unusual remote service usage",
                "Monitor for unusual authentication patterns",
                "Monitor for unusual file transfers between systems",
                "Monitor for use of lateral movement tools"
            ])
        
        if "collection" in tactics:
            mitigations.extend([
                "Encrypt sensitive data",
                "Implement data access controls",
                "Use data loss prevention solutions",
                "Restrict access to sensitive information"
            ])
            detections.extend([
                "Monitor for unusual file access patterns",
                "Monitor for unusual data transfers",
                "Monitor for screen capture tools",
                "Monitor for audio/video recording"
            ])
        
        if "command_and_control" in tactics:
            mitigations.extend([
                "Implement network-based IDS/IPS",
                "Use web proxies for outbound traffic",
                "Implement DNS filtering",
                "Use TLS inspection for encrypted traffic"
            ])
            detections.extend([
                "Monitor for unusual outbound connections",
                "Monitor for beaconing patterns",
                "Monitor for unusual DNS queries",
                "Monitor for unusual protocol usage"
            ])
        
        if "exfiltration" in tactics:
            mitigations.extend([
                "Implement data loss prevention solutions",
                "Monitor and restrict data transfers",
                "Encrypt sensitive data",
                "Implement egress filtering"
            ])
            detections.extend([
                "Monitor for large data transfers",
                "Monitor for unusual outbound connections",
                "Monitor for unusual email attachments",
                "Monitor for data encoding or encryption"
            ])
        
        if "impact" in tactics:
            mitigations.extend([
                "Implement regular backups and test restoration",
                "Implement DDoS protection",
                "Implement resource usage monitoring",
                "Implement system and data recovery plans"
            ])
            detections.extend([
                "Monitor for unusual system or service disruptions",
                "Monitor for data destruction or encryption",
                "Monitor for resource usage spikes",
                "Monitor for defacement or manipulation of data"
            ])
        
        # Add technique-specific mitigations and detections
        # This would be expanded with a more comprehensive database
        if "T1190" in technique_id:  # Exploit Public-Facing Application
            mitigations.extend([
                "Keep public-facing applications updated with the latest patches",
                "Implement web application firewalls",
                "Conduct regular vulnerability scanning and penetration testing",
                "Use secure coding practices and input validation"
            ])
            detections.extend([
                "Monitor web server logs for exploitation attempts",
                "Deploy web application firewalls with alerting",
                "Monitor for unusual web application behavior",
                "Monitor for known web exploitation signatures"
            ])
        
        if "T1133" in technique_id:  # External Remote Services
            mitigations.extend([
                "Use multi-factor authentication for all remote access",
                "Restrict access to remote services by IP address",
                "Implement VPN with strong authentication",
                "Regularly audit remote access logs"
            ])
            detections.extend([
                "Monitor for authentication attempts from unusual locations",
                "Monitor for brute force attempts against remote services",
                "Monitor for unusual times of remote access",
                "Monitor for unusual accounts using remote services"
            ])
        
        # Remove duplicates while preserving order
        unique_mitigations = []
        for item in mitigations:
            if item not in unique_mitigations:
                unique_mitigations.append(item)
        
        unique_detections = []
        for item in detections:
            if item not in unique_detections:
                unique_detections.append(item)
        
        return {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "mitigations": unique_mitigations[:5],  # Limit to top 5
            "detections": unique_detections[:5]  # Limit to top 5
        }
    
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
                output_file = self.mitre_config.get('mitre_file', 'mitre_attack.json')
            
            # Save data
            with open(output_file, 'w') as f:
                json.dump(techniques, f, indent=2)
            
            # Update internal data
            self.mitre_data = techniques
            self.mitre_file = output_file
            
            self.logger.info(f"Downloaded MITRE ATT&CK data with {len(techniques)} techniques to {output_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error downloading MITRE ATT&CK data: {str(e)}")
            return False
    
    def create_default_mappings_file(self, output_file: Optional[str] = None) -> bool:
        """Create a default mappings file.
        
        Args:
            output_file: Path to save the mappings (optional)
            
        Returns:
            True if successful, False otherwise
        """
        # Get default mappings
        default_mappings = self._get_default_mappings()
        
        # Determine output file
        if not output_file:
            output_file = self.mitre_config.get('mappings_file', 'technique_mappings.json')
        
        try:
            # Save mappings
            with open(output_file, 'w') as f:
                json.dump(default_mappings, f, indent=2)
            
            self.logger.info(f"Created default technique mappings file at {output_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error creating default mappings file: {str(e)}")
            return False