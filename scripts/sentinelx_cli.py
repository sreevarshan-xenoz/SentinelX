#!/usr/bin/env python
# SentinelX Command Line Interface

import argparse
import sys
import os
import json
import time
from datetime import datetime
import signal
import logging
import textwrap
from typing import Dict, List, Any, Optional, Union
import ipaddress
import tabulate
import colorama
from colorama import Fore, Back, Style

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.sentinelx import SentinelX
from src.core.config_manager import ConfigManager


# Initialize colorama
colorama.init(autoreset=True)


class SentinelXCLI:
    """Command Line Interface for SentinelX."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.sentinelx = None
        self.config = None
        self.is_monitoring = False
        self.monitoring_interface = None
    
    def setup(self, config_path: Optional[str] = None):
        """Set up the SentinelX system.
        
        Args:
            config_path: Path to the configuration file (optional)
        """
        print(f"{Fore.CYAN}Initializing SentinelX...{Style.RESET_ALL}")
        self.sentinelx = SentinelX(config_path)
        self.config = self.sentinelx.config
        self.sentinelx.setup()
        print(f"{Fore.GREEN}SentinelX initialized successfully{Style.RESET_ALL}")
    
    def train(self, model_type: str, dataset: Optional[str] = None):
        """Train a model.
        
        Args:
            model_type: Type of model to train
            dataset: Path to the dataset (optional)
        """
        print(f"{Fore.CYAN}Training {model_type} model...{Style.RESET_ALL}")
        success = self.sentinelx.train_model(model_type, dataset)
        if success:
            print(f"{Fore.GREEN}Model training complete{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Model training failed{Style.RESET_ALL}")
    
    def evaluate(self, model_type: str, dataset: Optional[str] = None):
        """Evaluate a model.
        
        Args:
            model_type: Type of model to evaluate
            dataset: Path to the dataset (optional)
        """
        print(f"{Fore.CYAN}Evaluating {model_type} model...{Style.RESET_ALL}")
        metrics = self.sentinelx.evaluate_model(model_type, dataset)
        if metrics:
            print(f"{Fore.GREEN}Evaluation metrics:{Style.RESET_ALL}")
            for metric, value in metrics.items():
                print(f"  {metric}: {value}")
        else:
            print(f"{Fore.RED}Model evaluation failed{Style.RESET_ALL}")
    
    def start_monitoring(self, interface: Optional[str] = None):
        """Start monitoring network traffic.
        
        Args:
            interface: Network interface to monitor (optional)
        """
        if self.is_monitoring:
            print(f"{Fore.YELLOW}Monitoring is already running{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Starting network monitoring...{Style.RESET_ALL}")
        success = self.sentinelx.start_monitoring(interface)
        if success:
            self.is_monitoring = True
            self.monitoring_interface = interface or self.config.get('network', {}).get('interface', 'unknown')
            print(f"{Fore.GREEN}Monitoring started on interface {self.monitoring_interface}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to start monitoring{Style.RESET_ALL}")
    
    def stop_monitoring(self):
        """Stop monitoring network traffic."""
        if not self.is_monitoring:
            print(f"{Fore.YELLOW}Monitoring is not running{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Stopping network monitoring...{Style.RESET_ALL}")
        success = self.sentinelx.stop_monitoring()
        if success:
            self.is_monitoring = False
            print(f"{Fore.GREEN}Monitoring stopped{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to stop monitoring{Style.RESET_ALL}")
    
    def list_interfaces(self):
        """List available network interfaces."""
        print(f"{Fore.CYAN}Available network interfaces:{Style.RESET_ALL}")
        interfaces = self.sentinelx.get_available_interfaces()
        if interfaces:
            for i, interface in enumerate(interfaces, 1):
                print(f"  {i}. {interface}")
        else:
            print(f"{Fore.YELLOW}No interfaces found{Style.RESET_ALL}")
    
    def show_stats(self):
        """Show network statistics."""
        stats = self.sentinelx.get_network_stats()
        if not stats:
            print(f"{Fore.RED}Failed to get network statistics{Style.RESET_ALL}")
            return
        
        # Print monitoring status
        if stats.get('monitoring_active', False):
            print(f"{Fore.GREEN}Monitoring active on interface {self.monitoring_interface}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Monitoring inactive{Style.RESET_ALL}")
        
        # Print packet stats
        packet_stats = stats.get('packet_stats', {})
        print(f"\n{Fore.CYAN}Packet Statistics:{Style.RESET_ALL}")
        print(f"  Total packets: {packet_stats.get('total_packets', 0)}")
        print(f"  Packets per second: {packet_stats.get('packets_per_second', 0):.2f}")
        print(f"  Total bytes: {packet_stats.get('total_bytes', 0)}")
        print(f"  Bytes per second: {packet_stats.get('bytes_per_second', 0):.2f}")
        
        # Print flow stats
        flow_stats = stats.get('flow_stats', {})
        print(f"\n{Fore.CYAN}Flow Statistics:{Style.RESET_ALL}")
        print(f"  Active flows: {flow_stats.get('active_flows', 0)}")
        print(f"  Total flows: {flow_stats.get('total_flows', 0)}")
        print(f"  Expired flows: {flow_stats.get('expired_flows', 0)}")
        
        # Print top talkers
        top_talkers = stats.get('top_talkers', [])
        if top_talkers:
            print(f"\n{Fore.CYAN}Top Talkers:{Style.RESET_ALL}")
            headers = ["Source IP", "Destination IP", "Protocol", "Packets", "Bytes"]
            table = []
            for talker in top_talkers:
                table.append([
                    talker.get('src_ip', 'Unknown'),
                    talker.get('dst_ip', 'Unknown'),
                    talker.get('protocol', 'Unknown'),
                    talker.get('packets', 0),
                    talker.get('bytes', 0)
                ])
            print(tabulate.tabulate(table, headers=headers, tablefmt="grid"))
        
        # Print alert stats
        alert_stats = stats.get('alert_stats', {})
        print(f"\n{Fore.CYAN}Alert Statistics:{Style.RESET_ALL}")
        print(f"  Total alerts: {alert_stats.get('total_alerts', 0)}")
        by_severity = alert_stats.get('by_severity', {})
        print(f"  Critical: {by_severity.get('critical', 0)}")
        print(f"  High: {by_severity.get('high', 0)}")
        print(f"  Medium: {by_severity.get('medium', 0)}")
        print(f"  Low: {by_severity.get('low', 0)}")
    
    def list_alerts(self, limit: int = 10, offset: int = 0, severity: Optional[str] = None):
        """List alerts.
        
        Args:
            limit: Maximum number of alerts to show
            offset: Offset for pagination
            severity: Filter by severity
        """
        alerts = self.sentinelx.get_alerts(limit, offset, severity)
        if not alerts:
            print(f"{Fore.YELLOW}No alerts found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Alerts:{Style.RESET_ALL}")
        headers = ["ID", "Timestamp", "Type", "Severity", "Source", "Message"]
        table = []
        for alert in alerts:
            # Format timestamp
            timestamp = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Format severity with color
            severity_color = {
                "critical": Fore.RED,
                "high": Fore.MAGENTA,
                "medium": Fore.YELLOW,
                "low": Fore.GREEN
            }.get(alert.severity.lower(), "")
            
            severity_text = f"{severity_color}{alert.severity.upper()}{Style.RESET_ALL}"
            
            # Format message (truncate if too long)
            message = alert.message
            if len(message) > 50:
                message = message[:47] + "..."
            
            table.append([
                alert.alert_id,
                timestamp,
                alert.alert_type,
                severity_text,
                alert.source,
                message
            ])
        
        print(tabulate.tabulate(table, headers=headers, tablefmt="grid"))
        
        # Print pagination info
        total_alerts = self.sentinelx.alert_manager.get_alert_count(severity=severity)
        print(f"Showing {len(alerts)} of {total_alerts} alerts")
        if offset > 0 or len(alerts) == limit:
            print("Use --limit and --offset for pagination")
    
    def show_alert(self, alert_id: str):
        """Show details of a specific alert.
        
        Args:
            alert_id: The alert ID
        """
        alert = self.sentinelx.get_alert(alert_id)
        if not alert:
            print(f"{Fore.RED}Alert {alert_id} not found{Style.RESET_ALL}")
            return
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Format severity with color
        severity_color = {
            "critical": Fore.RED,
            "high": Fore.MAGENTA,
            "medium": Fore.YELLOW,
            "low": Fore.GREEN
        }.get(alert.severity.lower(), "")
        
        severity_text = f"{severity_color}{alert.severity.upper()}{Style.RESET_ALL}"
        
        print(f"{Fore.CYAN}Alert Details:{Style.RESET_ALL}")
        print(f"  ID: {alert.alert_id}")
        print(f"  Timestamp: {timestamp}")
        print(f"  Type: {alert.alert_type}")
        print(f"  Severity: {severity_text}")
        print(f"  Source: {alert.source}")
        print(f"  Status: {alert.status}")
        print(f"  Message: {alert.message}")
        
        # Print details
        if alert.details:
            print(f"\n{Fore.CYAN}Details:{Style.RESET_ALL}")
            if isinstance(alert.details, dict):
                for key, value in alert.details.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {alert.details}")
        
        # Print enrichment
        if alert.enrichment:
            print(f"\n{Fore.CYAN}Enrichment:{Style.RESET_ALL}")
            if isinstance(alert.enrichment, dict):
                for key, value in alert.enrichment.items():
                    if isinstance(value, dict):
                        print(f"  {key}:")
                        for k, v in value.items():
                            print(f"    {k}: {v}")
                    else:
                        print(f"  {key}: {value}")
            else:
                print(f"  {alert.enrichment}")
        
        # Print notes
        if alert.notes:
            print(f"\n{Fore.CYAN}Notes:{Style.RESET_ALL}")
            for note in alert.notes:
                print(f"  {note}")
    
    def update_alert(self, alert_id: str, status: Optional[str] = None, notes: Optional[str] = None):
        """Update an alert.
        
        Args:
            alert_id: The alert ID
            status: New status (optional)
            notes: Notes to add (optional)
        """
        success = self.sentinelx.update_alert(alert_id, status, notes)
        if success:
            print(f"{Fore.GREEN}Alert {alert_id} updated successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to update alert {alert_id}{Style.RESET_ALL}")
    
    def analyze_alert(self, alert_id: str):
        """Analyze an alert.
        
        Args:
            alert_id: The alert ID
        """
        print(f"{Fore.CYAN}Analyzing alert {alert_id}...{Style.RESET_ALL}")
        analysis = self.sentinelx.analyze_alert(alert_id)
        if not analysis:
            print(f"{Fore.RED}Failed to analyze alert {alert_id}{Style.RESET_ALL}")
            return
        
        # Print analysis
        print(f"\n{Fore.CYAN}Analysis:{Style.RESET_ALL}")
        for key, value in analysis.get('analysis', {}).items():
            print(f"  {key}: {value}")
        
        # Print MITRE ATT&CK techniques
        mitre_techniques = analysis.get('mitre_techniques', [])
        if mitre_techniques:
            print(f"\n{Fore.CYAN}MITRE ATT&CK Techniques:{Style.RESET_ALL}")
            for technique in mitre_techniques:
                print(f"  {technique.get('id')}: {technique.get('name')}")
                print(f"    {technique.get('description')[:100]}...")
                print(f"    Tactics: {', '.join(technique.get('tactics', []))}")
                print(f"    URL: {technique.get('url')}")
                print()
        
        # Print CVEs
        cves = analysis.get('cves', [])
        if cves:
            print(f"\n{Fore.CYAN}Related CVEs:{Style.RESET_ALL}")
            for cve in cves:
                severity_color = {
                    "CRITICAL": Fore.RED,
                    "HIGH": Fore.MAGENTA,
                    "MEDIUM": Fore.YELLOW,
                    "LOW": Fore.GREEN,
                    "UNKNOWN": Fore.WHITE
                }.get(cve.get('severity', 'UNKNOWN'), "")
                
                print(f"  {cve.get('id')}: {severity_color}{cve.get('severity')}{Style.RESET_ALL} (CVSS: {cve.get('cvss_score')})")
                print(f"    {cve.get('description')[:100]}...")
                print(f"    URL: {cve.get('url')}")
                print()
    
    def generate_report(self, alert_id: str, format: str = 'markdown'):
        """Generate a report for an alert.
        
        Args:
            alert_id: The alert ID
            format: Report format ('json', 'html', or 'markdown')
        """
        print(f"{Fore.CYAN}Generating {format} report for alert {alert_id}...{Style.RESET_ALL}")
        report_data = self.sentinelx.generate_report(alert_id, format)
        if not report_data:
            print(f"{Fore.RED}Failed to generate report for alert {alert_id}{Style.RESET_ALL}")
            return
        
        report_file = report_data.get('file')
        print(f"{Fore.GREEN}Report generated: {report_file}{Style.RESET_ALL}")
    
    def enrich_ip(self, ip_address: str):
        """Enrich an IP address with threat intelligence.
        
        Args:
            ip_address: The IP address to enrich
        """
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
        except ValueError:
            print(f"{Fore.RED}Invalid IP address: {ip_address}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Enriching IP address {ip_address}...{Style.RESET_ALL}")
        enrichment = self.sentinelx.enrich_ip(ip_address)
        if not enrichment:
            print(f"{Fore.YELLOW}No enrichment data found for {ip_address}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Enrichment for {ip_address}:{Style.RESET_ALL}")
        for source, data in enrichment.items():
            print(f"\n  {Fore.CYAN}Source: {source}{Style.RESET_ALL}")
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        print(f"    {key}:")
                        for k, v in value.items():
                            print(f"      {k}: {v}")
                    elif isinstance(value, list):
                        print(f"    {key}:")
                        for item in value:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    print(f"      {k}: {v}")
                            else:
                                print(f"      {item}")
                    else:
                        print(f"    {key}: {value}")
            else:
                print(f"    {data}")
    
    def enrich_domain(self, domain: str):
        """Enrich a domain with threat intelligence.
        
        Args:
            domain: The domain to enrich
        """
        print(f"{Fore.CYAN}Enriching domain {domain}...{Style.RESET_ALL}")
        enrichment = self.sentinelx.enrich_domain(domain)
        if not enrichment:
            print(f"{Fore.YELLOW}No enrichment data found for {domain}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Enrichment for {domain}:{Style.RESET_ALL}")
        for source, data in enrichment.items():
            print(f"\n  {Fore.CYAN}Source: {source}{Style.RESET_ALL}")
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        print(f"    {key}:")
                        for k, v in value.items():
                            print(f"      {k}: {v}")
                    elif isinstance(value, list):
                        print(f"    {key}:")
                        for item in value:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    print(f"      {k}: {v}")
                            else:
                                print(f"      {item}")
                    else:
                        print(f"    {key}: {value}")
            else:
                print(f"    {data}")
    
    def shutdown(self):
        """Shutdown the SentinelX system."""
        if self.is_monitoring:
            self.stop_monitoring()
        
        if self.sentinelx:
            print(f"{Fore.CYAN}Shutting down SentinelX...{Style.RESET_ALL}")
            self.sentinelx.shutdown()
            print(f"{Fore.GREEN}SentinelX shutdown complete{Style.RESET_ALL}")


def main():
    """Main entry point for the SentinelX CLI."""
    # Create the CLI
    cli = SentinelXCLI()
    
    # Create the argument parser
    parser = argparse.ArgumentParser(
        description="SentinelX - AI-Powered Cyber Threat Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              sentinelx_cli.py train --model random_forest
              sentinelx_cli.py monitor --interface eth0
              sentinelx_cli.py alerts --limit 10
              sentinelx_cli.py enrich-ip 8.8.8.8
        """)
    )
    
    # Add global arguments
    parser.add_argument("--config", help="Path to configuration file")
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train a model")
    train_parser.add_argument("--model", default="random_forest", help="Model type to use")
    train_parser.add_argument("--dataset", help="Path to dataset")
    
    # Evaluate command
    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate a model")
    evaluate_parser.add_argument("--model", default="random_forest", help="Model type to use")
    evaluate_parser.add_argument("--dataset", help="Path to dataset")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start network monitoring")
    monitor_parser.add_argument("--interface", help="Network interface to monitor")
    
    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop network monitoring")
    
    # Interfaces command
    interfaces_parser = subparsers.add_parser("interfaces", help="List available network interfaces")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show network statistics")
    
    # Alerts command
    alerts_parser = subparsers.add_parser("alerts", help="List alerts")
    alerts_parser.add_argument("--limit", type=int, default=10, help="Maximum number of alerts to show")
    alerts_parser.add_argument("--offset", type=int, default=0, help="Offset for pagination")
    alerts_parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Filter by severity")
    
    # Alert command
    alert_parser = subparsers.add_parser("alert", help="Show details of a specific alert")
    alert_parser.add_argument("alert_id", help="Alert ID")
    
    # Update alert command
    update_parser = subparsers.add_parser("update", help="Update an alert")
    update_parser.add_argument("alert_id", help="Alert ID")
    update_parser.add_argument("--status", choices=["new", "in_progress", "resolved", "false_positive"], help="New status")
    update_parser.add_argument("--notes", help="Notes to add")
    
    # Analyze alert command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an alert")
    analyze_parser.add_argument("alert_id", help="Alert ID")
    
    # Generate report command
    report_parser = subparsers.add_parser("report", help="Generate a report for an alert")
    report_parser.add_argument("alert_id", help="Alert ID")
    report_parser.add_argument("--format", choices=["json", "html", "markdown"], default="markdown", help="Report format")
    
    # Enrich IP command
    enrich_ip_parser = subparsers.add_parser("enrich-ip", help="Enrich an IP address with threat intelligence")
    enrich_ip_parser.add_argument("ip_address", help="IP address to enrich")
    
    # Enrich domain command
    enrich_domain_parser = subparsers.add_parser("enrich-domain", help="Enrich a domain with threat intelligence")
    enrich_domain_parser.add_argument("domain", help="Domain to enrich")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Register signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Received signal {sig}, shutting down...{Style.RESET_ALL}")
        cli.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize SentinelX
        cli.setup(args.config)
        
        # Execute command
        if args.command == "train":
            cli.train(args.model, args.dataset)
        elif args.command == "evaluate":
            cli.evaluate(args.model, args.dataset)
        elif args.command == "monitor":
            cli.start_monitoring(args.interface)
            # Keep the main thread alive
            while True:
                time.sleep(1)
        elif args.command == "stop":
            cli.stop_monitoring()
        elif args.command == "interfaces":
            cli.list_interfaces()
        elif args.command == "stats":
            cli.show_stats()
        elif args.command == "alerts":
            cli.list_alerts(args.limit, args.offset, args.severity)
        elif args.command == "alert":
            cli.show_alert(args.alert_id)
        elif args.command == "update":
            cli.update_alert(args.alert_id, args.status, args.notes)
        elif args.command == "analyze":
            cli.analyze_alert(args.alert_id)
        elif args.command == "report":
            cli.generate_report(args.alert_id, args.format)
        elif args.command == "enrich-ip":
            cli.enrich_ip(args.ip_address)
        elif args.command == "enrich-domain":
            cli.enrich_domain(args.domain)
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted, shutting down...{Style.RESET_ALL}")
        cli.shutdown()
    
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        cli.shutdown()


if __name__ == "__main__":
    main()