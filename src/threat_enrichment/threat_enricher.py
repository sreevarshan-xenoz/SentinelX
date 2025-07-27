# SentinelX Threat Enricher

import requests
import json
import time
from typing import Dict, List, Any, Optional, Union
import logging
import os
from datetime import datetime, timedelta
import ipaddress
import re

from ..core.config_manager import ConfigManager

class ThreatEnricher:
    """Threat enricher for SentinelX.
    
    This class is responsible for enriching detected threats with additional context
    from external threat intelligence sources.
    """
    
    def __init__(self):
        """Initialize the threat enricher."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get threat intelligence configuration
        self.sources = self.config.get('threat_intelligence', 'sources', [])
        
        # Initialize cache
        self.cache: Dict[str, Dict[str, Any]] = {}
        
        self.logger.info(f"Threat enricher initialized with {len(self.sources)} sources")
    
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich an IP address with threat intelligence data.
        
        Args:
            ip_address: The IP address to enrich
            
        Returns:
            Dictionary containing enriched threat data
        """
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip_address}")
            return {'error': f"Invalid IP address: {ip_address}"}
        
        # Check cache first
        cache_key = f"ip:{ip_address}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            cache_time = cache_entry.get('timestamp', 0)
            cache_ttl = cache_entry.get('ttl', 3600)  # Default 1 hour TTL
            
            # If cache is still valid, return cached data
            if time.time() - cache_time < cache_ttl:
                self.logger.debug(f"Using cached data for IP: {ip_address}")
                return cache_entry['data']
        
        # Initialize result
        result = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Query each enabled source
        for source in self.sources:
            if not source.get('enabled', False):
                continue
            
            source_name = source.get('name', 'Unknown')
            api_key = source.get('api_key', '')
            
            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                self.logger.warning(f"API key not configured for {source_name}")
                continue
            
            try:
                if source_name == 'AlienVault OTX':
                    source_data = self._query_alienvault_otx(ip_address, api_key)
                elif source_name == 'AbuseIPDB':
                    source_data = self._query_abuseipdb(ip_address, api_key)
                elif source_name == 'VirusTotal':
                    source_data = self._query_virustotal(ip_address, api_key)
                else:
                    self.logger.warning(f"Unknown source: {source_name}")
                    continue
                
                result['sources'][source_name] = source_data
            except Exception as e:
                self.logger.error(f"Error querying {source_name} for IP {ip_address}: {str(e)}")
                result['sources'][source_name] = {'error': str(e)}
        
        # Aggregate results
        result['malicious'] = any(source.get('malicious', False) 
                                for source in result['sources'].values() 
                                if isinstance(source, dict))
        
        result['risk_score'] = self._calculate_risk_score(result)
        
        # Cache the result
        max_ttl = max([source.get('cache_ttl_minutes', 60) * 60 
                      for source in self.sources if source.get('enabled', False)], 
                     default=3600)  # Default 1 hour TTL
        
        self.cache[cache_key] = {
            'timestamp': time.time(),
            'ttl': max_ttl,
            'data': result
        }
        
        return result
    
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich a domain with threat intelligence data.
        
        Args:
            domain: The domain to enrich
            
        Returns:
            Dictionary containing enriched threat data
        """
        # Validate domain
        if not self._is_valid_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return {'error': f"Invalid domain: {domain}"}
        
        # Check cache first
        cache_key = f"domain:{domain}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            cache_time = cache_entry.get('timestamp', 0)
            cache_ttl = cache_entry.get('ttl', 3600)  # Default 1 hour TTL
            
            # If cache is still valid, return cached data
            if time.time() - cache_time < cache_ttl:
                self.logger.debug(f"Using cached data for domain: {domain}")
                return cache_entry['data']
        
        # Initialize result
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Query each enabled source
        for source in self.sources:
            if not source.get('enabled', False):
                continue
            
            source_name = source.get('name', 'Unknown')
            api_key = source.get('api_key', '')
            
            if not api_key or api_key == 'YOUR_API_KEY_HERE':
                self.logger.warning(f"API key not configured for {source_name}")
                continue
            
            try:
                if source_name == 'AlienVault OTX':
                    source_data = self._query_alienvault_otx_domain(domain, api_key)
                elif source_name == 'VirusTotal':
                    source_data = self._query_virustotal_domain(domain, api_key)
                else:
                    # Skip sources that don't support domain lookups
                    continue
                
                result['sources'][source_name] = source_data
            except Exception as e:
                self.logger.error(f"Error querying {source_name} for domain {domain}: {str(e)}")
                result['sources'][source_name] = {'error': str(e)}
        
        # Aggregate results
        result['malicious'] = any(source.get('malicious', False) 
                                for source in result['sources'].values() 
                                if isinstance(source, dict))
        
        result['risk_score'] = self._calculate_risk_score(result)
        
        # Cache the result
        max_ttl = max([source.get('cache_ttl_minutes', 60) * 60 
                      for source in self.sources if source.get('enabled', False)], 
                     default=3600)  # Default 1 hour TTL
        
        self.cache[cache_key] = {
            'timestamp': time.time(),
            'ttl': max_ttl,
            'data': result
        }
        
        return result
    
    def _query_alienvault_otx(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query AlienVault OTX for IP reputation data.
        
        Args:
            ip_address: The IP address to query
            api_key: AlienVault OTX API key
            
        Returns:
            Dictionary containing threat data from AlienVault OTX
        """
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/reputation"
        headers = {'X-OTX-API-KEY': api_key}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information
        result = {
            'reputation': data.get('reputation', 0),
            'malicious': False,
            'threat_types': [],
            'raw_data': data
        }
        
        # Check if IP is considered malicious
        if result['reputation'] < 0:
            result['malicious'] = True
        
        # Get pulse information (threat intelligence reports)
        pulses_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        pulses_response = requests.get(pulses_url, headers=headers)
        
        if pulses_response.status_code == 200:
            pulses_data = pulses_response.json()
            pulses = pulses_data.get('pulse_info', {}).get('pulses', [])
            
            # Extract threat types from pulses
            for pulse in pulses:
                tags = pulse.get('tags', [])
                result['threat_types'].extend(tags)
            
            # Remove duplicates
            result['threat_types'] = list(set(result['threat_types']))
            
            # If there are pulses, consider the IP malicious
            if pulses:
                result['malicious'] = True
        
        return result
    
    def _query_alienvault_otx_domain(self, domain: str, api_key: str) -> Dict[str, Any]:
        """Query AlienVault OTX for domain reputation data.
        
        Args:
            domain: The domain to query
            api_key: AlienVault OTX API key
            
        Returns:
            Dictionary containing threat data from AlienVault OTX
        """
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {'X-OTX-API-KEY': api_key}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information
        result = {
            'malicious': False,
            'threat_types': [],
            'raw_data': data
        }
        
        # Get pulse information (threat intelligence reports)
        pulses = data.get('pulse_info', {}).get('pulses', [])
        
        # Extract threat types from pulses
        for pulse in pulses:
            tags = pulse.get('tags', [])
            result['threat_types'].extend(tags)
        
        # Remove duplicates
        result['threat_types'] = list(set(result['threat_types']))
        
        # If there are pulses, consider the domain malicious
        if pulses:
            result['malicious'] = True
        
        return result
    
    def _query_abuseipdb(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation data.
        
        Args:
            ip_address: The IP address to query
            api_key: AbuseIPDB API key
            
        Returns:
            Dictionary containing threat data from AbuseIPDB
        """
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information
        result = {
            'confidence_score': data.get('data', {}).get('abuseConfidenceScore', 0),
            'total_reports': data.get('data', {}).get('totalReports', 0),
            'country_code': data.get('data', {}).get('countryCode', ''),
            'usage_type': data.get('data', {}).get('usageType', ''),
            'malicious': False,
            'categories': [],
            'raw_data': data
        }
        
        # Check if IP is considered malicious (confidence score > 50%)
        if result['confidence_score'] > 50:
            result['malicious'] = True
        
        # Extract categories
        reports = data.get('data', {}).get('reports', [])
        for report in reports:
            categories = report.get('categories', [])
            result['categories'].extend(categories)
        
        # Remove duplicates and convert to category names
        result['categories'] = list(set(result['categories']))
        
        # Map category IDs to names
        category_map = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
        
        result['category_names'] = [category_map.get(cat, f"Unknown ({cat})") 
                                  for cat in result['categories']]
        
        return result
    
    def _query_virustotal(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query VirusTotal for IP reputation data.
        
        Args:
            ip_address: The IP address to query
            api_key: VirusTotal API key
            
        Returns:
            Dictionary containing threat data from VirusTotal
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {'x-apikey': api_key}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information
        attributes = data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        last_analysis_results = attributes.get('last_analysis_results', {})
        
        result = {
            'malicious_count': last_analysis_stats.get('malicious', 0),
            'suspicious_count': last_analysis_stats.get('suspicious', 0),
            'harmless_count': last_analysis_stats.get('harmless', 0),
            'undetected_count': last_analysis_stats.get('undetected', 0),
            'total_engines': sum(last_analysis_stats.values()),
            'malicious': False,
            'detections': [],
            'raw_data': data
        }
        
        # Check if IP is considered malicious
        if result['malicious_count'] > 0:
            result['malicious'] = True
        
        # Extract detections
        for engine, engine_result in last_analysis_results.items():
            if engine_result.get('category') == 'malicious':
                result['detections'].append({
                    'engine': engine,
                    'result': engine_result.get('result', 'unknown')
                })
        
        return result
    
    def _query_virustotal_domain(self, domain: str, api_key: str) -> Dict[str, Any]:
        """Query VirusTotal for domain reputation data.
        
        Args:
            domain: The domain to query
            api_key: VirusTotal API key
            
        Returns:
            Dictionary containing threat data from VirusTotal
        """
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information
        attributes = data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        last_analysis_results = attributes.get('last_analysis_results', {})
        
        result = {
            'malicious_count': last_analysis_stats.get('malicious', 0),
            'suspicious_count': last_analysis_stats.get('suspicious', 0),
            'harmless_count': last_analysis_stats.get('harmless', 0),
            'undetected_count': last_analysis_stats.get('undetected', 0),
            'total_engines': sum(last_analysis_stats.values()),
            'malicious': False,
            'detections': [],
            'raw_data': data
        }
        
        # Check if domain is considered malicious
        if result['malicious_count'] > 0:
            result['malicious'] = True
        
        # Extract detections
        for engine, engine_result in last_analysis_results.items():
            if engine_result.get('category') == 'malicious':
                result['detections'].append({
                    'engine': engine,
                    'result': engine_result.get('result', 'unknown')
                })
        
        return result
    
    def _calculate_risk_score(self, result: Dict[str, Any]) -> float:
        """Calculate a normalized risk score based on enrichment results.
        
        Args:
            result: Enrichment result dictionary
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        scores = []
        
        # Process each source
        for source_name, source_data in result.get('sources', {}).items():
            if not isinstance(source_data, dict):
                continue
            
            if source_name == 'AlienVault OTX':
                # AlienVault reputation is between -100 and 0, normalize to 0-1
                reputation = source_data.get('reputation', 0)
                if reputation < 0:
                    scores.append(min(1.0, abs(reputation) / 100))
                else:
                    scores.append(0.0)
            
            elif source_name == 'AbuseIPDB':
                # AbuseIPDB confidence score is already 0-100, normalize to 0-1
                confidence = source_data.get('confidence_score', 0)
                scores.append(confidence / 100)
            
            elif source_name == 'VirusTotal':
                # Calculate ratio of malicious detections
                malicious = source_data.get('malicious_count', 0)
                total = source_data.get('total_engines', 0)
                if total > 0:
                    scores.append(malicious / total)
                else:
                    scores.append(0.0)
        
        # If no scores, return 0
        if not scores:
            return 0.0
        
        # Return weighted average (currently equal weights)
        return sum(scores) / len(scores)
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if a string is a valid domain name.
        
        Args:
            domain: The domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Simple regex for domain validation
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def clear_cache(self) -> None:
        """Clear the enrichment cache."""
        self.cache.clear()
        self.logger.info("Threat enrichment cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get statistics about the enrichment cache.
        
        Returns:
            Dictionary containing cache statistics
        """
        stats = {
            'total_entries': len(self.cache),
            'ip_entries': sum(1 for key in self.cache if key.startswith('ip:')),
            'domain_entries': sum(1 for key in self.cache if key.startswith('domain:')),
            'cache_size_bytes': sum(len(json.dumps(entry)) for entry in self.cache.values())
        }
        
        return stats