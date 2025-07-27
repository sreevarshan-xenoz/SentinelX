# SentinelX Report Generator Module

import logging
import os
import json
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import time
import markdown
import re

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager
from ..threat_enrichment.alert_manager import Alert
from .threat_reasoning import ThreatReasoning


class ReportGenerator:
    """Report generator class for SentinelX.
    
    This class is responsible for generating human-readable reports from threat analysis,
    including detailed explanations, visualizations, and remediation steps.
    """
    
    def __init__(self):
        """Initialize the report generator."""
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get report configuration
        self.report_config = self.config.get('reporting', {})
        self.report_dir = self.report_config.get('report_dir', 'reports')
        
        # Create report directory if it doesn't exist
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Initialize threat reasoning
        self.threat_reasoning = ThreatReasoning()
        
        self.logger.info("Report generator initialized")
    
    def generate_alert_report(self, alert: Alert, include_reasoning: bool = True) -> Dict[str, Any]:
        """Generate a report for a single alert.
        
        Args:
            alert: The alert to generate a report for
            include_reasoning: Whether to include threat reasoning
            
        Returns:
            Dictionary containing the report data
        """
        report = {
            "alert_id": alert.alert_id,
            "timestamp": datetime.now().isoformat(),
            "alert_data": {
                "type": alert.alert_type,
                "severity": alert.severity,
                "source": alert.source,
                "timestamp": alert.timestamp,
                "details": alert.details
            },
            "enrichment": alert.enrichment if alert.enrichment else {}
        }
        
        # Add threat reasoning if requested
        if include_reasoning:
            reasoning_result = self.threat_reasoning.analyze_alert(alert)
            if reasoning_result.get("success", False):
                report["reasoning"] = {
                    "explanation": reasoning_result.get("explanation", ""),
                    "insights": reasoning_result.get("insights", []),
                    "mitre_techniques": reasoning_result.get("mitre_techniques", []),
                    "cves": reasoning_result.get("cves", []),
                    "remediation": reasoning_result.get("remediation", "")
                }
            else:
                report["reasoning"] = {
                    "error": reasoning_result.get("error", "Unknown error in threat reasoning")
                }
        
        return report
    
    def generate_summary_report(self, alerts: List[Alert], 
                              time_period: str = "24h",
                              include_reasoning: bool = True) -> Dict[str, Any]:
        """Generate a summary report for multiple alerts.
        
        Args:
            alerts: List of alerts to include in the report
            time_period: Time period covered by the report
            include_reasoning: Whether to include threat reasoning
            
        Returns:
            Dictionary containing the summary report data
        """
        # Basic report metadata
        report = {
            "report_id": f"summary-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "time_period": time_period,
            "total_alerts": len(alerts),
            "severity_counts": self._count_severities(alerts),
            "type_counts": self._count_alert_types(alerts),
            "source_counts": self._count_sources(alerts),
            "alerts": []
        }
        
        # Process each alert
        for alert in alerts:
            alert_report = self.generate_alert_report(alert, include_reasoning)
            report["alerts"].append(alert_report)
        
        # Generate top insights across all alerts
        if include_reasoning:
            report["top_insights"] = self._extract_top_insights(report["alerts"])
            report["top_mitre_techniques"] = self._extract_top_mitre_techniques(report["alerts"])
            report["top_cves"] = self._extract_top_cves(report["alerts"])
            report["common_remediation_steps"] = self._extract_common_remediation(report["alerts"])
        
        return report
    
    def _count_severities(self, alerts: List[Alert]) -> Dict[str, int]:
        """Count alerts by severity.
        
        Args:
            alerts: List of alerts
            
        Returns:
            Dictionary of severity counts
        """
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for alert in alerts:
            severity = alert.severity.lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["info"] += 1  # Default to info for unknown severities
        
        return counts
    
    def _count_alert_types(self, alerts: List[Alert]) -> Dict[str, int]:
        """Count alerts by type.
        
        Args:
            alerts: List of alerts
            
        Returns:
            Dictionary of alert type counts
        """
        counts = {}
        
        for alert in alerts:
            alert_type = alert.alert_type
            if alert_type in counts:
                counts[alert_type] += 1
            else:
                counts[alert_type] = 1
        
        return counts
    
    def _count_sources(self, alerts: List[Alert]) -> Dict[str, int]:
        """Count alerts by source.
        
        Args:
            alerts: List of alerts
            
        Returns:
            Dictionary of source counts
        """
        counts = {}
        
        for alert in alerts:
            source = alert.source
            if source in counts:
                counts[source] += 1
            else:
                counts[source] = 1
        
        return counts
    
    def _extract_top_insights(self, alert_reports: List[Dict[str, Any]]) -> List[str]:
        """Extract top insights across all alerts.
        
        Args:
            alert_reports: List of alert reports
            
        Returns:
            List of top insights
        """
        # Collect all insights
        all_insights = []
        for report in alert_reports:
            if "reasoning" in report and "insights" in report["reasoning"]:
                all_insights.extend(report["reasoning"]["insights"])
        
        # Count occurrences of each insight
        insight_counts = {}
        for insight in all_insights:
            # Normalize insight text to group similar insights
            normalized = re.sub(r'\b\d+\b', 'X', insight.lower())
            if normalized in insight_counts:
                insight_counts[normalized]["count"] += 1
                insight_counts[normalized]["examples"].append(insight)
            else:
                insight_counts[normalized] = {"count": 1, "examples": [insight]}
        
        # Sort by count and take top 10
        sorted_insights = sorted(insight_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        top_insights = []
        for _, data in sorted_insights[:10]:
            # Use the most common example as the representative insight
            top_insights.append(max(data["examples"], key=data["examples"].count))
        
        return top_insights
    
    def _extract_top_mitre_techniques(self, alert_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract top MITRE ATT&CK techniques across all alerts.
        
        Args:
            alert_reports: List of alert reports
            
        Returns:
            List of top MITRE ATT&CK techniques
        """
        # Count occurrences of each technique
        technique_counts = {}
        
        for report in alert_reports:
            if "reasoning" in report and "mitre_techniques" in report["reasoning"]:
                for technique in report["reasoning"]["mitre_techniques"]:
                    technique_id = technique.get("id")
                    if technique_id:
                        if technique_id in technique_counts:
                            technique_counts[technique_id]["count"] += 1
                        else:
                            technique_counts[technique_id] = {
                                "count": 1,
                                "technique": technique
                            }
        
        # Sort by count and take top 10
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        top_techniques = []
        for _, data in sorted_techniques[:10]:
            technique = data["technique"]
            technique["count"] = data["count"]
            top_techniques.append(technique)
        
        return top_techniques
    
    def _extract_top_cves(self, alert_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract top CVEs across all alerts.
        
        Args:
            alert_reports: List of alert reports
            
        Returns:
            List of top CVEs
        """
        # Count occurrences of each CVE
        cve_counts = {}
        
        for report in alert_reports:
            if "reasoning" in report and "cves" in report["reasoning"]:
                for cve in report["reasoning"]["cves"]:
                    cve_id = cve.get("id")
                    if cve_id:
                        if cve_id in cve_counts:
                            cve_counts[cve_id]["count"] += 1
                        else:
                            cve_counts[cve_id] = {
                                "count": 1,
                                "cve": cve
                            }
        
        # Sort by count and take top 10
        sorted_cves = sorted(cve_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        top_cves = []
        for _, data in sorted_cves[:10]:
            cve = data["cve"]
            cve["count"] = data["count"]
            top_cves.append(cve)
        
        return top_cves
    
    def _extract_common_remediation(self, alert_reports: List[Dict[str, Any]]) -> List[str]:
        """Extract common remediation steps across all alerts.
        
        Args:
            alert_reports: List of alert reports
            
        Returns:
            List of common remediation steps
        """
        # Collect all remediation steps
        all_remediation = []
        for report in alert_reports:
            if "reasoning" in report and "remediation" in report["reasoning"]:
                remediation = report["reasoning"]["remediation"]
                # Split into individual steps
                steps = re.split(r'\d+\.\s+', remediation)
                steps = [step.strip() for step in steps if step.strip()]
                all_remediation.extend(steps)
        
        # Count occurrences of each step
        step_counts = {}
        for step in all_remediation:
            # Normalize step text to group similar steps
            normalized = re.sub(r'\b\d+\b', 'X', step.lower())
            normalized = re.sub(r'\b[a-f0-9]{8,}\b', 'HASH', normalized)
            if normalized in step_counts:
                step_counts[normalized]["count"] += 1
                step_counts[normalized]["examples"].append(step)
            else:
                step_counts[normalized] = {"count": 1, "examples": [step]}
        
        # Sort by count and take top 10
        sorted_steps = sorted(step_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        common_steps = []
        for _, data in sorted_steps[:10]:
            # Use the most common example as the representative step
            common_steps.append(max(data["examples"], key=data["examples"].count))
        
        return common_steps
    
    def save_report_to_file(self, report: Dict[str, Any], output_format: str = "json") -> str:
        """Save a report to a file.
        
        Args:
            report: The report to save
            output_format: The output format (json, html, markdown)
            
        Returns:
            Path to the saved report file
        """
        report_id = report.get("report_id", f"report-{int(time.time())}")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        if output_format == "json":
            filename = f"{report_id}-{timestamp}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Saved JSON report to {filepath}")
            return filepath
        
        elif output_format == "html":
            filename = f"{report_id}-{timestamp}.html"
            filepath = os.path.join(self.report_dir, filename)
            
            html_content = self._generate_html_report(report)
            
            with open(filepath, 'w') as f:
                f.write(html_content)
            
            self.logger.info(f"Saved HTML report to {filepath}")
            return filepath
        
        elif output_format == "markdown":
            filename = f"{report_id}-{timestamp}.md"
            filepath = os.path.join(self.report_dir, filename)
            
            md_content = self._generate_markdown_report(report)
            
            with open(filepath, 'w') as f:
                f.write(md_content)
            
            self.logger.info(f"Saved Markdown report to {filepath}")
            return filepath
        
        else:
            self.logger.error(f"Unsupported output format: {output_format}")
            return ""
    
    def _generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """Generate a markdown report.
        
        Args:
            report: The report data
            
        Returns:
            Markdown report content
        """
        # Determine if this is a summary report or a single alert report
        is_summary = "total_alerts" in report
        
        if is_summary:
            return self._generate_summary_markdown(report)
        else:
            return self._generate_alert_markdown(report)
    
    def _generate_summary_markdown(self, report: Dict[str, Any]) -> str:
        """Generate a markdown summary report.
        
        Args:
            report: The summary report data
            
        Returns:
            Markdown report content
        """
        md = f"# SentinelX Security Report\n\n"
        md += f"**Report ID:** {report.get('report_id', 'Unknown')}\n\n"
        md += f"**Generated:** {report.get('timestamp', 'Unknown')}\n\n"
        md += f"**Time Period:** {report.get('time_period', 'Unknown')}\n\n"
        
        # Summary statistics
        md += f"## Summary\n\n"
        md += f"**Total Alerts:** {report.get('total_alerts', 0)}\n\n"
        
        # Severity breakdown
        md += f"### Severity Breakdown\n\n"
        severity_counts = report.get('severity_counts', {})
        for severity, count in severity_counts.items():
            md += f"- **{severity.capitalize()}:** {count}\n"
        md += "\n"
        
        # Alert type breakdown
        md += f"### Alert Type Breakdown\n\n"
        type_counts = report.get('type_counts', {})
        for alert_type, count in type_counts.items():
            md += f"- **{alert_type}:** {count}\n"
        md += "\n"
        
        # Top insights
        if "top_insights" in report and report["top_insights"]:
            md += f"## Top Insights\n\n"
            for i, insight in enumerate(report["top_insights"], 1):
                md += f"{i}. {insight}\n"
            md += "\n"
        
        # Top MITRE techniques
        if "top_mitre_techniques" in report and report["top_mitre_techniques"]:
            md += f"## Top MITRE ATT&CK Techniques\n\n"
            for technique in report["top_mitre_techniques"]:
                md += f"### {technique.get('id')}: {technique.get('name')}\n\n"
                md += f"**Count:** {technique.get('count', 1)}\n\n"
                md += f"**Description:** {technique.get('description', 'No description available')}\n\n"
                if technique.get('tactics'):
                    md += f"**Tactics:** {', '.join(technique.get('tactics', []))}\n\n"
                md += f"**Reference:** [{technique.get('id')}]({technique.get('url', '#')})\n\n"
        
        # Top CVEs
        if "top_cves" in report and report["top_cves"]:
            md += f"## Top CVEs\n\n"
            for cve in report["top_cves"]:
                md += f"### {cve.get('id')}\n\n"
                md += f"**Count:** {cve.get('count', 1)}\n\n"
                md += f"**Severity:** {cve.get('severity', 'Unknown')}\n\n"
                md += f"**Description:** {cve.get('description', 'No description available')}\n\n"
                md += f"**Published:** {cve.get('published', 'Unknown')}\n\n"
                md += f"**Reference:** [{cve.get('id')}]({cve.get('url', '#')})\n\n"
        
        # Common remediation steps
        if "common_remediation_steps" in report and report["common_remediation_steps"]:
            md += f"## Common Remediation Steps\n\n"
            for i, step in enumerate(report["common_remediation_steps"], 1):
                md += f"{i}. {step}\n"
            md += "\n"
        
        # Individual alerts (limited to top 10 for brevity)
        md += f"## Detailed Alerts\n\n"
        for i, alert in enumerate(report.get("alerts", [])[:10], 1):
            md += f"### Alert {i}: {alert.get('alert_data', {}).get('type', 'Unknown')}\n\n"
            md += f"**ID:** {alert.get('alert_id', 'Unknown')}\n\n"
            md += f"**Severity:** {alert.get('alert_data', {}).get('severity', 'Unknown')}\n\n"
            md += f"**Source:** {alert.get('alert_data', {}).get('source', 'Unknown')}\n\n"
            md += f"**Timestamp:** {alert.get('alert_data', {}).get('timestamp', 'Unknown')}\n\n"
            
            # Add reasoning if available
            if "reasoning" in alert and "explanation" in alert["reasoning"]:
                md += f"**Analysis:**\n\n{alert['reasoning']['explanation']}\n\n"
                
                if "remediation" in alert["reasoning"]:
                    md += f"**Remediation:**\n\n{alert['reasoning']['remediation']}\n\n"
        
        # Note if there are more alerts
        if len(report.get("alerts", [])) > 10:
            md += f"*Note: {len(report.get('alerts', [])) - 10} more alerts not shown in this report.*\n\n"
        
        return md
    
    def _generate_alert_markdown(self, report: Dict[str, Any]) -> str:
        """Generate a markdown report for a single alert.
        
        Args:
            report: The alert report data
            
        Returns:
            Markdown report content
        """
        md = f"# SentinelX Alert Report\n\n"
        md += f"**Alert ID:** {report.get('alert_id', 'Unknown')}\n\n"
        md += f"**Generated:** {report.get('timestamp', 'Unknown')}\n\n"
        
        # Alert details
        md += f"## Alert Details\n\n"
        alert_data = report.get('alert_data', {})
        md += f"**Type:** {alert_data.get('type', 'Unknown')}\n\n"
        md += f"**Severity:** {alert_data.get('severity', 'Unknown')}\n\n"
        md += f"**Source:** {alert_data.get('source', 'Unknown')}\n\n"
        md += f"**Timestamp:** {alert_data.get('timestamp', 'Unknown')}\n\n"
        
        # Alert details
        if alert_data.get('details'):
            md += f"## Technical Details\n\n"
            md += f"```json\n{json.dumps(alert_data.get('details', {}), indent=2)}\n```\n\n"
        
        # Enrichment data
        if report.get('enrichment'):
            md += f"## Threat Intelligence Enrichment\n\n"
            
            # IP enrichment
            if 'ip' in report['enrichment']:
                ip_data = report['enrichment']['ip']
                md += f"### IP: {ip_data.get('ip', 'Unknown')}\n\n"
                md += f"**Risk Score:** {ip_data.get('risk_score', 'Unknown')}\n\n"
                md += f"**Country:** {ip_data.get('country', 'Unknown')}\n\n"
                
                if 'sources' in ip_data:
                    md += f"**Intelligence Sources:**\n\n"
                    for source, data in ip_data['sources'].items():
                        md += f"#### {source}\n\n"
                        for key, value in data.items():
                            if isinstance(value, list):
                                md += f"**{key.capitalize()}:** {', '.join(value)}\n\n"
                            else:
                                md += f"**{key.capitalize()}:** {value}\n\n"
            
            # Domain enrichment
            if 'domain' in report['enrichment']:
                domain_data = report['enrichment']['domain']
                md += f"### Domain: {domain_data.get('domain', 'Unknown')}\n\n"
                md += f"**Risk Score:** {domain_data.get('risk_score', 'Unknown')}\n\n"
                
                if 'sources' in domain_data:
                    md += f"**Intelligence Sources:**\n\n"
                    for source, data in domain_data['sources'].items():
                        md += f"#### {source}\n\n"
                        for key, value in data.items():
                            if isinstance(value, list):
                                md += f"**{key.capitalize()}:** {', '.join(value)}\n\n"
                            else:
                                md += f"**{key.capitalize()}:** {value}\n\n"
        
        # Reasoning
        if "reasoning" in report:
            reasoning = report["reasoning"]
            
            if "error" in reasoning:
                md += f"## Analysis\n\n"
                md += f"*Error: {reasoning['error']}*\n\n"
            else:
                # Explanation
                if "explanation" in reasoning:
                    md += f"## Analysis\n\n"
                    md += f"{reasoning['explanation']}\n\n"
                
                # Insights
                if "insights" in reasoning and reasoning["insights"]:
                    md += f"## Key Insights\n\n"
                    for i, insight in enumerate(reasoning["insights"], 1):
                        md += f"{i}. {insight}\n"
                    md += "\n"
                
                # MITRE techniques
                if "mitre_techniques" in reasoning and reasoning["mitre_techniques"]:
                    md += f"## MITRE ATT&CK Techniques\n\n"
                    for technique in reasoning["mitre_techniques"]:
                        md += f"### {technique.get('id')}: {technique.get('name')}\n\n"
                        md += f"**Description:** {technique.get('description', 'No description available')}\n\n"
                        if technique.get('tactics'):
                            md += f"**Tactics:** {', '.join(technique.get('tactics', []))}\n\n"
                        md += f"**Reference:** [{technique.get('id')}]({technique.get('url', '#')})\n\n"
                
                # CVEs
                if "cves" in reasoning and reasoning["cves"]:
                    md += f"## Related CVEs\n\n"
                    for cve in reasoning["cves"]:
                        md += f"### {cve.get('id')}\n\n"
                        md += f"**Severity:** {cve.get('severity', 'Unknown')}\n\n"
                        md += f"**Description:** {cve.get('description', 'No description available')}\n\n"
                        md += f"**Published:** {cve.get('published', 'Unknown')}\n\n"
                        md += f"**Reference:** [{cve.get('id')}]({cve.get('url', '#')})\n\n"
                
                # Remediation
                if "remediation" in reasoning:
                    md += f"## Remediation Steps\n\n"
                    md += f"{reasoning['remediation']}\n\n"
        
        return md
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate an HTML report.
        
        Args:
            report: The report data
            
        Returns:
            HTML report content
        """
        # Generate markdown first
        md_content = self._generate_markdown_report(report)
        
        # Convert markdown to HTML
        html_body = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
        
        # Add HTML header, CSS, and footer
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelX Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        pre {{
            background-color: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 10px;
            overflow-x: auto;
        }}
        code {{
            font-family: 'Courier New', Courier, monospace;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .severity-critical {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .severity-high {{
            color: #e67e22;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f39c12;
        }}
        .severity-low {{
            color: #3498db;
        }}
        .severity-info {{
            color: #2ecc71;
        }}
        .footer {{
            margin-top: 50px;
            border-top: 1px solid #ddd;
            padding-top: 20px;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    {html_body}
    <div class="footer">
        <p>Generated by SentinelX - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
</body>
</html>
"""
        
        return html