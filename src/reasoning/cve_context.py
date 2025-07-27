# SentinelX CVE Context Module

import logging
import os
import json
import time
from typing import Dict, List, Any, Optional, Union
import re
import requests
from datetime import datetime, timedelta

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager
from ..threat_enrichment.alert_manager import Alert


class CVEContext:
    """CVE context provider for SentinelX.
    
    This class is responsible for providing context about Common Vulnerabilities and Exposures (CVEs)
    that may be relevant to security alerts, including severity information, affected products,
    and remediation advice.
    """
    
    def __init__(self):
        """Initialize the CVE context provider."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get CVE configuration
        self.cve_config = self.config.get('reasoning', {}).get('cve', {})
        self.cve_file = self.cve_config.get('cve_file', None)
        self.cve_cache_days = self.cve_config.get('cache_days', 7)
        
        # Load CVE data
        self.cve_data = self._load_cve_data()
        
        self.logger.info("CVE context provider initialized")
    
    def _load_cve_data(self) -> Dict[str, Any]:
        """Load CVE data from file.
        
        Returns:
            Dictionary of CVE data
        """
        if not self.cve_file or not os.path.exists(self.cve_file):
            self.logger.warning(f"CVE data file not found: {self.cve_file}")
            return {}
        
        try:
            # Check if file is too old
            file_age = time.time() - os.path.getmtime(self.cve_file)
            if file_age > (self.cve_cache_days * 86400):  # Convert days to seconds
                self.logger.warning(f"CVE data file is older than {self.cve_cache_days} days")
                return {}
            
            with open(self.cve_file, 'r') as f:
                data = json.load(f)
            
            self.logger.info(f"Loaded CVE data from {self.cve_file} with {len(data)} entries")
            return data
        except Exception as e:
            self.logger.error(f"Error loading CVE data: {str(e)}")
            return {}
    
    def find_cves_for_alert(self, alert: Alert) -> List[Dict[str, Any]]:
        """Find CVEs that may be relevant to an alert.
        
        Args:
            alert: The alert to find CVEs for
            
        Returns:
            List of relevant CVEs with details
        """
        if not self.cve_data:
            self.logger.warning("CVE data not loaded, cannot find CVEs for alert")
            return []
        
        relevant_cves = []
        
        # Extract text from alert for searching
        search_text = self._get_search_text(alert)
        
        # First, look for explicit CVE IDs in the alert
        cve_ids = self._extract_cve_ids(search_text)
        for cve_id in cve_ids:
            if cve_id in self.cve_data:
                relevant_cves.append(self._get_cve_details(cve_id))
        
        # If no explicit CVEs found, try to match based on keywords and products
        if not relevant_cves:
            # Extract potential product names and versions from alert
            products = self._extract_products(search_text)
            
            # Match CVEs based on products and alert type
            for cve_id, cve_info in self.cve_data.items():
                if self._is_cve_relevant(cve_info, products, alert.alert_type):
                    relevant_cves.append(self._get_cve_details(cve_id))
        
        # Sort by severity (highest first) and limit results
        relevant_cves.sort(key=lambda x: self._severity_to_number(x.get('severity', 'UNKNOWN')), reverse=True)
        
        return relevant_cves[:5]  # Limit to top 5 most relevant CVEs
    
    def _get_search_text(self, alert: Alert) -> str:
        """Extract text from alert for searching.
        
        Args:
            alert: The alert to extract text from
            
        Returns:
            String of text to search
        """
        search_text = ""
        
        # Add alert type and source
        search_text += f"{alert.alert_type} {alert.source} "
        
        # Add alert message
        search_text += f"{alert.message} "
        
        # Add details if available
        if alert.details:
            if isinstance(alert.details, dict):
                search_text += json.dumps(alert.details) + " "
            elif isinstance(alert.details, str):
                search_text += alert.details + " "
        
        # Add enrichment if available
        if alert.enrichment:
            if isinstance(alert.enrichment, dict):
                search_text += json.dumps(alert.enrichment) + " "
            elif isinstance(alert.enrichment, str):
                search_text += alert.enrichment + " "
        
        return search_text
    
    def _extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text.
        
        Args:
            text: The text to extract CVE IDs from
            
        Returns:
            List of CVE IDs
        """
        # Match CVE IDs (e.g., CVE-2021-1234)
        matches = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        
        # Normalize to uppercase
        return [match.upper() for match in matches]
    
    def _extract_products(self, text: str) -> List[Dict[str, str]]:
        """Extract product names and versions from text.
        
        Args:
            text: The text to extract products from
            
        Returns:
            List of dictionaries with product name and version
        """
        products = []
        
        # Common software product patterns
        # This is a simplified approach; more sophisticated NLP could be used
        product_patterns = [
            # Format: Product Version
            r'(Apache|Nginx|IIS|Tomcat|Jenkins|Jira|Confluence|WordPress|Drupal|PHP|MySQL|MariaDB|PostgreSQL|MongoDB|Redis|Elasticsearch|Kibana|Logstash|Node\.js|Python|Ruby|Java|Spring|Struts|Log4j|OpenSSL|OpenSSH|Samba|Windows|Linux|Ubuntu|Debian|CentOS|RHEL|Fedora|macOS|iOS|Android)\s+([\d\.]+)',
            # Format: Microsoft Product Version
            r'Microsoft\s+(Windows|Office|Exchange|SharePoint|SQL Server|IIS|Edge|Internet Explorer)\s+([\d\.]+)',
            # Format: Product/Version
            r'(Apache|Nginx|Tomcat|Jenkins|Jira|Confluence|WordPress|Drupal|PHP|MySQL|MariaDB|PostgreSQL|MongoDB|Redis|Elasticsearch|Kibana|Logstash|Node\.js|Python|Ruby|Java|Spring|Struts|Log4j|OpenSSL|OpenSSH|Samba)\/([\d\.]+)'
        ]
        
        for pattern in product_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                products.append({
                    "name": match[0].lower(),
                    "version": match[1]
                })
        
        return products
    
    def _is_cve_relevant(self, cve_info: Dict[str, Any], products: List[Dict[str, str]], alert_type: str) -> bool:
        """Check if a CVE is relevant to the alert.
        
        Args:
            cve_info: The CVE information
            products: List of products extracted from the alert
            alert_type: The alert type
            
        Returns:
            True if the CVE is relevant, False otherwise
        """
        # Check if any products match
        if products and 'affected_products' in cve_info:
            for product in products:
                for affected in cve_info['affected_products']:
                    if product['name'].lower() in affected['name'].lower():
                        # If version is specified, check version match
                        if 'version' in product and 'version' in affected:
                            # Simple version match (could be improved with version range checking)
                            if product['version'] == affected['version'] or affected['version'] == '*':
                                return True
                        else:
                            # If no version specified, consider it a match
                            return True
        
        # Check if CVE description contains keywords related to the alert type
        if 'description' in cve_info and alert_type:
            alert_keywords = self._get_alert_type_keywords(alert_type)
            description = cve_info['description'].lower()
            
            for keyword in alert_keywords:
                if keyword in description:
                    return True
        
        return False
    
    def _get_alert_type_keywords(self, alert_type: str) -> List[str]:
        """Get keywords related to an alert type.
        
        Args:
            alert_type: The alert type
            
        Returns:
            List of keywords
        """
        # Map alert types to relevant keywords for CVE matching
        alert_type_keywords = {
            "port_scan": ["scan", "reconnaissance", "discovery", "enumeration"],
            "brute_force": ["brute force", "password", "credential", "authentication"],
            "web_attack": ["web", "http", "https", "injection", "xss", "csrf", "sqli"],
            "sql_injection": ["sql", "injection", "database", "query"],
            "xss": ["xss", "cross-site", "script", "javascript", "html"],
            "file_inclusion": ["file inclusion", "lfi", "rfi", "path traversal", "directory traversal"],
            "command_injection": ["command", "injection", "shell", "exec", "os command"],
            "malware": ["malware", "virus", "trojan", "backdoor", "spyware", "ransomware"],
            "ransomware": ["ransomware", "encrypt", "ransom", "payment"],
            "backdoor": ["backdoor", "remote access", "rat", "trojan"],
            "dos": ["dos", "ddos", "denial of service", "availability"],
            "privilege_escalation": ["privilege", "escalation", "elevation", "admin", "root", "sudo"],
            "lateral_movement": ["lateral", "movement", "pivot", "spread"],
            "data_exfiltration": ["exfiltration", "data theft", "leak", "steal"],
            "suspicious_traffic": ["traffic", "communication", "protocol", "network"],
            "suspicious_process": ["process", "execution", "binary", "executable"],
            "suspicious_file": ["file", "download", "upload", "modification"],
            "suspicious_email": ["email", "phishing", "spam", "attachment"],
            "suspicious_login": ["login", "authentication", "credential", "account"],
            "suspicious_account": ["account", "user", "permission", "access"],
            "suspicious_command": ["command", "shell", "terminal", "console"],
            "suspicious_script": ["script", "powershell", "bash", "python", "javascript"],
            "suspicious_network": ["network", "connection", "packet", "traffic"],
            "anomaly": ["anomaly", "unusual", "abnormal", "deviation"],
            "threat_intel": ["threat", "intelligence", "ioc", "indicator"],
            "vulnerability": ["vulnerability", "exploit", "patch", "update"],
        }
        
        # Normalize alert type
        normalized_type = alert_type.lower()
        
        # Return keywords for the alert type, or a default set
        return alert_type_keywords.get(normalized_type, ["vulnerability", "exploit", "remote", "attack"])
    
    def _get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Get details for a CVE.
        
        Args:
            cve_id: The CVE ID
            
        Returns:
            Dictionary of CVE details
        """
        cve_info = self.cve_data.get(cve_id, {})
        
        return {
            "id": cve_id,
            "description": cve_info.get("description", "No description available"),
            "severity": cve_info.get("severity", "UNKNOWN"),
            "cvss_score": cve_info.get("cvss_score", 0.0),
            "affected_products": cve_info.get("affected_products", []),
            "references": cve_info.get("references", []),
            "published_date": cve_info.get("published_date", ""),
            "last_modified_date": cve_info.get("last_modified_date", ""),
            "remediation": cve_info.get("remediation", "No remediation information available"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }
    
    def _severity_to_number(self, severity: str) -> float:
        """Convert severity string to number for sorting.
        
        Args:
            severity: The severity string
            
        Returns:
            Numeric value for sorting
        """
        severity_map = {
            "CRITICAL": 4.0,
            "HIGH": 3.0,
            "MEDIUM": 2.0,
            "LOW": 1.0,
            "UNKNOWN": 0.0
        }
        
        return severity_map.get(severity.upper(), 0.0)
    
    def get_cve_by_id(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE details by ID.
        
        Args:
            cve_id: The CVE ID
            
        Returns:
            Dictionary of CVE details
        """
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        
        cve_id = cve_id.upper()
        
        if cve_id in self.cve_data:
            return self._get_cve_details(cve_id)
        else:
            # Try to fetch from NVD API
            cve_details = self._fetch_cve_from_nvd(cve_id)
            if cve_details:
                # Add to local data
                self.cve_data[cve_id] = cve_details
                return self._get_cve_details(cve_id)
            else:
                return {
                    "id": cve_id,
                    "description": "CVE not found",
                    "severity": "UNKNOWN",
                    "cvss_score": 0.0,
                    "affected_products": [],
                    "references": [],
                    "published_date": "",
                    "last_modified_date": "",
                    "remediation": "No information available",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
    
    def _fetch_cve_from_nvd(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE details from NVD API.
        
        Args:
            cve_id: The CVE ID
            
        Returns:
            Dictionary of CVE details or None if not found
        """
        try:
            # NVD API URL
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            
            # Get API key from config if available
            api_key = self.cve_config.get('nvd_api_key', None)
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
            
            # Make request
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # Extract CVE details
            cve_item = data.get('result', {}).get('CVE_Items', [])[0]
            if not cve_item:
                return None
            
            # Extract basic info
            cve_data = cve_item.get('cve', {})
            impact = cve_item.get('impact', {})
            
            # Extract description
            description = ""
            for desc_data in cve_data.get('description', {}).get('description_data', []):
                if desc_data.get('lang') == 'en':
                    description = desc_data.get('value', '')
                    break
            
            # Extract CVSS data
            cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
            cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})
            
            # Use V3 if available, otherwise V2
            if cvss_v3:
                severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
                cvss_score = cvss_v3.get('baseScore', 0.0)
            elif cvss_v2:
                severity = cvss_v2.get('severity', 'UNKNOWN')
                cvss_score = cvss_v2.get('baseScore', 0.0)
            else:
                severity = 'UNKNOWN'
                cvss_score = 0.0
            
            # Extract affected products
            affected_products = []
            for node in cve_data.get('affects', {}).get('vendor', {}).get('vendor_data', []):
                vendor_name = node.get('vendor_name', '')
                for product in node.get('product', {}).get('product_data', []):
                    product_name = product.get('product_name', '')
                    for version in product.get('version', {}).get('version_data', []):
                        affected_products.append({
                            "name": f"{vendor_name} {product_name}",
                            "version": version.get('version_value', '*')
                        })
            
            # Extract references
            references = []
            for ref_data in cve_data.get('references', {}).get('reference_data', []):
                references.append({
                    "url": ref_data.get('url', ''),
                    "name": ref_data.get('name', ''),
                    "source": ref_data.get('source', '')
                })
            
            # Extract dates
            published_date = cve_item.get('publishedDate', '')
            last_modified_date = cve_item.get('lastModifiedDate', '')
            
            # Create CVE details
            cve_details = {
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_products": affected_products,
                "references": references,
                "published_date": published_date,
                "last_modified_date": last_modified_date,
                "remediation": "Update to the latest version of the affected software."
            }
            
            self.logger.info(f"Fetched CVE details for {cve_id} from NVD API")
            return cve_details
        
        except Exception as e:
            self.logger.error(f"Error fetching CVE details from NVD API: {str(e)}")
            return None
    
    def download_recent_cves(self, days: int = 30, output_file: Optional[str] = None) -> bool:
        """Download recent CVEs from NVD.
        
        Args:
            days: Number of days to look back
            output_file: Path to save the data (optional)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Calculate start date
            start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00:000 UTC-00:00")
            
            # NVD API URL for recent CVEs
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?pubStartDate={start_date}"
            
            # Get API key from config if available
            api_key = self.cve_config.get('nvd_api_key', None)
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
            
            # Make request
            self.logger.info(f"Downloading CVEs published since {start_date}")
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # Process CVEs
            cves = {}
            for cve_item in data.get('result', {}).get('CVE_Items', []):
                cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    continue
                
                # Extract CVE details using the same logic as _fetch_cve_from_nvd
                cve_data = cve_item.get('cve', {})
                impact = cve_item.get('impact', {})
                
                # Extract description
                description = ""
                for desc_data in cve_data.get('description', {}).get('description_data', []):
                    if desc_data.get('lang') == 'en':
                        description = desc_data.get('value', '')
                        break
                
                # Extract CVSS data
                cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
                cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})
                
                # Use V3 if available, otherwise V2
                if cvss_v3:
                    severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
                    cvss_score = cvss_v3.get('baseScore', 0.0)
                elif cvss_v2:
                    severity = cvss_v2.get('severity', 'UNKNOWN')
                    cvss_score = cvss_v2.get('baseScore', 0.0)
                else:
                    severity = 'UNKNOWN'
                    cvss_score = 0.0
                
                # Extract affected products
                affected_products = []
                for node in cve_data.get('affects', {}).get('vendor', {}).get('vendor_data', []):
                    vendor_name = node.get('vendor_name', '')
                    for product in node.get('product', {}).get('product_data', []):
                        product_name = product.get('product_name', '')
                        for version in product.get('version', {}).get('version_data', []):
                            affected_products.append({
                                "name": f"{vendor_name} {product_name}",
                                "version": version.get('version_value', '*')
                            })
                
                # Extract references
                references = []
                for ref_data in cve_data.get('references', {}).get('reference_data', []):
                    references.append({
                        "url": ref_data.get('url', ''),
                        "name": ref_data.get('name', ''),
                        "source": ref_data.get('source', '')
                    })
                
                # Extract dates
                published_date = cve_item.get('publishedDate', '')
                last_modified_date = cve_item.get('lastModifiedDate', '')
                
                # Create CVE details
                cves[cve_id] = {
                    "description": description,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "affected_products": affected_products,
                    "references": references,
                    "published_date": published_date,
                    "last_modified_date": last_modified_date,
                    "remediation": "Update to the latest version of the affected software."
                }
            
            # Determine output file
            if not output_file:
                output_file = self.cve_config.get('cve_file', 'cve_data.json')
            
            # Merge with existing data if file exists
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        existing_data = json.load(f)
                    
                    # Update existing data with new CVEs
                    existing_data.update(cves)
                    cves = existing_data
                except Exception as e:
                    self.logger.error(f"Error reading existing CVE data: {str(e)}")
            
            # Save data
            with open(output_file, 'w') as f:
                json.dump(cves, f, indent=2)
            
            # Update internal data
            self.cve_data = cves
            self.cve_file = output_file
            
            self.logger.info(f"Downloaded {len(cves)} CVEs to {output_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error downloading CVEs: {str(e)}")
            return False
    
    def search_cves(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for CVEs by keyword.
        
        Args:
            query: The search query
            limit: Maximum number of results to return
            
        Returns:
            List of matching CVEs
        """
        if not self.cve_data:
            self.logger.warning("CVE data not loaded, cannot search CVEs")
            return []
        
        matches = []
        query = query.lower()
        
        for cve_id, cve_info in self.cve_data.items():
            # Check if query matches CVE ID
            if query in cve_id.lower():
                matches.append(self._get_cve_details(cve_id))
                continue
            
            # Check if query matches description
            if 'description' in cve_info and query in cve_info['description'].lower():
                matches.append(self._get_cve_details(cve_id))
                continue
            
            # Check if query matches affected products
            if 'affected_products' in cve_info:
                for product in cve_info['affected_products']:
                    if query in product.get('name', '').lower():
                        matches.append(self._get_cve_details(cve_id))
                        break
        
        # Sort by severity (highest first) and limit results
        matches.sort(key=lambda x: self._severity_to_number(x.get('severity', 'UNKNOWN')), reverse=True)
        
        return matches[:limit]
    
    def get_remediation_advice(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed remediation advice for a CVE.
        
        Args:
            cve_id: The CVE ID
            
        Returns:
            Dictionary with remediation advice
        """
        cve_details = self.get_cve_by_id(cve_id)
        
        # Default remediation advice
        default_advice = {
            "general": "Update to the latest version of the affected software.",
            "specific": [],
            "references": []
        }
        
        # If CVE not found, return default advice
        if cve_details.get('description') == "CVE not found":
            return default_advice
        
        # Extract references that might contain remediation information
        remediation_references = []
        for ref in cve_details.get('references', []):
            url = ref.get('url', '')
            # Look for references that might contain patches or advisories
            if any(keyword in url.lower() for keyword in ['patch', 'update', 'advisory', 'security', 'fix', 'remediation']):
                remediation_references.append(ref)
        
        # Generate specific advice based on severity
        specific_advice = []
        severity = cve_details.get('severity', 'UNKNOWN')
        
        if severity in ['CRITICAL', 'HIGH']:
            specific_advice.append("Apply patches immediately or implement mitigations if patches are not available.")
            specific_advice.append("Consider isolating affected systems until remediation is complete.")
        elif severity == 'MEDIUM':
            specific_advice.append("Apply patches as soon as possible following change management procedures.")
        elif severity == 'LOW':
            specific_advice.append("Apply patches during the next maintenance window.")
        
        # Add product-specific advice
        for product in cve_details.get('affected_products', []):
            product_name = product.get('name', '')
            product_version = product.get('version', '')
            
            if product_name and product_version:
                specific_advice.append(f"Update {product_name} from version {product_version} to the latest available version.")
        
        # Return remediation advice
        return {
            "general": cve_details.get('remediation', default_advice['general']),
            "specific": specific_advice,
            "references": remediation_references
        }
    
    def get_recent_critical_cves(self, days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent critical CVEs.
        
        Args:
            days: Number of days to look back
            limit: Maximum number of results to return
            
        Returns:
            List of recent critical CVEs
        """
        if not self.cve_data:
            self.logger.warning("CVE data not loaded, cannot get recent critical CVEs")
            return []
        
        # Calculate cutoff date
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        recent_critical_cves = []
        for cve_id, cve_info in self.cve_data.items():
            # Check if CVE is recent
            published_date = cve_info.get('published_date', '')
            if not published_date or published_date < cutoff_date:
                continue
            
            # Check if CVE is critical or high severity
            severity = cve_info.get('severity', 'UNKNOWN')
            if severity in ['CRITICAL', 'HIGH']:
                recent_critical_cves.append(self._get_cve_details(cve_id))
        
        # Sort by published date (newest first)
        recent_critical_cves.sort(key=lambda x: x.get('published_date', ''), reverse=True)
        
        return recent_critical_cves[:limit]