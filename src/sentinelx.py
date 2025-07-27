# SentinelX Main Module

import logging
import os
import json
import time
import argparse
from typing import Dict, List, Any, Optional, Union
import threading
import signal
import sys

from .core.config_manager import ConfigManager
from .core.logging_manager import LoggingManager
from .data_layer.dataset_loader import DatasetLoader, NSLKDDDatasetLoader
from .data_layer.preprocessing_pipeline import PreprocessingPipeline
from .data_layer.feature_extractor import FeatureExtractor
from .model_layer.model_factory import ModelFactory
from .threat_enrichment.threat_enricher import ThreatEnricher
from .threat_enrichment.alert_manager import AlertManager, Alert
from .network.packet_capture import PacketCapture
from .network.flow_analyzer import FlowAnalyzer
from .reasoning.threat_reasoning import ThreatReasoning
from .reasoning.report_generator import ReportGenerator
from .reasoning.mitre_context import MITREContext
from .reasoning.cve_context import CVEContext


class SentinelX:
    """Main SentinelX class that integrates all components.
    
    This class serves as the central coordinator for the SentinelX system,
    integrating data processing, model training, threat enrichment, network
    monitoring, and reasoning capabilities.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the SentinelX system.
        
        Args:
            config_path: Path to the configuration file (optional)
        """
        # Initialize configuration and logging
        self.config = ConfigManager(config_path)
        self.logging_manager = LoggingManager()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.dataset_loader = None
        self.preprocessing_pipeline = None
        self.feature_extractor = None
        self.model_factory = None
        self.threat_enricher = None
        self.alert_manager = None
        self.packet_capture = None
        self.flow_analyzer = None
        self.threat_reasoning = None
        self.report_generator = None
        self.mitre_context = None
        self.cve_context = None
        
        # Initialize state
        self.is_running = False
        self.monitoring_thread = None
        
        self.logger.info("SentinelX initialized")
    
    def setup(self):
        """Set up all components of the SentinelX system."""
        self.logger.info("Setting up SentinelX components")
        
        # Set up data layer
        self._setup_data_layer()
        
        # Set up model layer
        self._setup_model_layer()
        
        # Set up threat enrichment
        self._setup_threat_enrichment()
        
        # Set up network monitoring
        self._setup_network_monitoring()
        
        # Set up reasoning
        self._setup_reasoning()
        
        self.logger.info("SentinelX setup complete")
    
    def _setup_data_layer(self):
        """Set up the data layer components."""
        self.logger.info("Setting up data layer")
        
        # Initialize dataset loader based on configuration
        dataset_type = self.config.get('data', {}).get('dataset_type', 'nsl-kdd')
        if dataset_type == 'nsl-kdd':
            self.dataset_loader = NSLKDDDatasetLoader()
        else:
            self.logger.warning(f"Unknown dataset type: {dataset_type}, defaulting to NSL-KDD")
            self.dataset_loader = NSLKDDDatasetLoader()
        
        # Initialize preprocessing pipeline
        self.preprocessing_pipeline = PreprocessingPipeline()
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()
        
        self.logger.info("Data layer setup complete")
    
    def _setup_model_layer(self):
        """Set up the model layer components."""
        self.logger.info("Setting up model layer")
        
        # Initialize model factory
        self.model_factory = ModelFactory()
        
        self.logger.info("Model layer setup complete")
    
    def _setup_threat_enrichment(self):
        """Set up the threat enrichment components."""
        self.logger.info("Setting up threat enrichment")
        
        # Initialize threat enricher
        self.threat_enricher = ThreatEnricher()
        
        # Initialize alert manager
        self.alert_manager = AlertManager(self.threat_enricher)
        
        self.logger.info("Threat enrichment setup complete")
    
    def _setup_network_monitoring(self):
        """Set up the network monitoring components."""
        self.logger.info("Setting up network monitoring")
        
        # Initialize packet capture
        self.packet_capture = PacketCapture()
        
        # Initialize flow analyzer
        self.flow_analyzer = FlowAnalyzer()
        
        self.logger.info("Network monitoring setup complete")
    
    def _setup_reasoning(self):
        """Set up the reasoning components."""
        self.logger.info("Setting up reasoning")
        
        # Initialize threat reasoning
        self.threat_reasoning = ThreatReasoning()
        
        # Initialize report generator
        self.report_generator = ReportGenerator()
        
        # Initialize MITRE context
        self.mitre_context = MITREContext()
        
        # Initialize CVE context
        self.cve_context = CVEContext()
        
        self.logger.info("Reasoning setup complete")
    
    def train_model(self, model_type: str = 'random_forest', dataset: Optional[str] = None):
        """Train a model using the specified dataset.
        
        Args:
            model_type: Type of model to train
            dataset: Path to the dataset (optional)
        
        Returns:
            True if training was successful, False otherwise
        """
        self.logger.info(f"Training {model_type} model")
        
        try:
            # Load dataset
            if dataset:
                X, y = self.dataset_loader.load_dataset(dataset)
            else:
                X, y = self.dataset_loader.load_dataset()
            
            self.logger.info(f"Loaded dataset with {len(X)} samples")
            
            # Preprocess data
            X_processed = self.preprocessing_pipeline.fit_transform(X)
            
            # Get model instance
            model = self.model_factory.get_model(model_type)
            
            # Train model
            model.train(X_processed, y)
            
            # Save model
            model_path = self.config.get('model', {}).get('model_path', 'models')
            os.makedirs(model_path, exist_ok=True)
            model_file = os.path.join(model_path, f"{model_type}_model.joblib")
            model.save(model_file)
            
            self.logger.info(f"Model trained and saved to {model_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            return False
    
    def evaluate_model(self, model_type: str = 'random_forest', dataset: Optional[str] = None):
        """Evaluate a model using the specified dataset.
        
        Args:
            model_type: Type of model to evaluate
            dataset: Path to the dataset (optional)
        
        Returns:
            Dictionary of evaluation metrics
        """
        self.logger.info(f"Evaluating {model_type} model")
        
        try:
            # Load dataset
            if dataset:
                X, y = self.dataset_loader.load_dataset(dataset, test=True)
            else:
                X, y = self.dataset_loader.load_dataset(test=True)
            
            self.logger.info(f"Loaded test dataset with {len(X)} samples")
            
            # Preprocess data
            X_processed = self.preprocessing_pipeline.transform(X)
            
            # Get model instance
            model = self.model_factory.get_model(model_type)
            
            # Load model
            model_path = self.config.get('model', {}).get('model_path', 'models')
            model_file = os.path.join(model_path, f"{model_type}_model.joblib")
            model.load(model_file)
            
            # Evaluate model
            metrics = model.evaluate(X_processed, y)
            
            self.logger.info(f"Model evaluation complete: {metrics}")
            return metrics
        
        except Exception as e:
            self.logger.error(f"Error evaluating model: {str(e)}")
            return {}
    
    def predict(self, data, model_type: str = 'random_forest'):
        """Make a prediction using the specified model.
        
        Args:
            data: Data to make a prediction on
            model_type: Type of model to use
        
        Returns:
            Prediction result
        """
        try:
            # Get model instance
            model = self.model_factory.get_model(model_type)
            
            # Load model
            model_path = self.config.get('model', {}).get('model_path', 'models')
            model_file = os.path.join(model_path, f"{model_type}_model.joblib")
            model.load(model_file)
            
            # Extract features if needed
            if hasattr(data, 'get_features'):
                data = data.get_features()
            
            # Preprocess data
            data_processed = self.preprocessing_pipeline.transform(data)
            
            # Make prediction
            prediction = model.predict(data_processed)
            
            return prediction
        
        except Exception as e:
            self.logger.error(f"Error making prediction: {str(e)}")
            return None
    
    def start_monitoring(self, interface: Optional[str] = None):
        """Start monitoring network traffic.
        
        Args:
            interface: Network interface to monitor (optional)
        
        Returns:
            True if monitoring started successfully, False otherwise
        """
        if self.is_running:
            self.logger.warning("Monitoring is already running")
            return False
        
        try:
            # Get interface from config if not specified
            if not interface:
                interface = self.config.get('network', {}).get('interface', None)
            
            # Start packet capture
            if not self.packet_capture.start_capture(interface):
                self.logger.error("Failed to start packet capture")
                return False
            
            # Start monitoring thread
            self.is_running = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            
            self.logger.info(f"Started monitoring on interface {interface}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {str(e)}")
            return False
    
    def stop_monitoring(self):
        """Stop monitoring network traffic.
        
        Returns:
            True if monitoring stopped successfully, False otherwise
        """
        if not self.is_running:
            self.logger.warning("Monitoring is not running")
            return False
        
        try:
            # Stop monitoring thread
            self.is_running = False
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5.0)
            
            # Stop packet capture
            self.packet_capture.stop_capture()
            
            self.logger.info("Stopped monitoring")
            return True
        
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {str(e)}")
            return False
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        self.logger.info("Monitoring loop started")
        
        model_type = self.config.get('model', {}).get('default_model', 'random_forest')
        batch_size = self.config.get('network', {}).get('batch_size', 100)
        processing_interval = self.config.get('network', {}).get('processing_interval', 5.0)
        
        while self.is_running:
            try:
                # Get packets from capture
                packets = self.packet_capture.get_packets(batch_size)
                
                if packets:
                    # Process packets with flow analyzer
                    self.flow_analyzer.process_packets(packets)
                    
                    # Extract features from flows
                    flows = self.flow_analyzer.get_active_flows()
                    for flow_key, flow in flows.items():
                        # Skip flows that have already been analyzed
                        if flow.analyzed:
                            continue
                        
                        # Extract features
                        features = self.feature_extractor.extract_flow_features(flow)
                        
                        # Make prediction
                        prediction = self.predict(features, model_type)
                        
                        # If anomaly detected, create alert
                        if prediction and prediction != 'normal':
                            alert = self._create_alert_from_flow(flow, prediction)
                            self.alert_manager.add_alert(alert)
                            
                            # Mark flow as analyzed
                            flow.analyzed = True
                
                # Clean up old flows
                self.flow_analyzer.cleanup_flows()
                
                # Sleep for a bit
                time.sleep(processing_interval)
            
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(1.0)  # Sleep to avoid tight loop on error
        
        self.logger.info("Monitoring loop stopped")
    
    def _create_alert_from_flow(self, flow, prediction):
        """Create an alert from a network flow.
        
        Args:
            flow: The network flow
            prediction: The prediction result
            
        Returns:
            Alert object
        """
        # Create alert details
        details = {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "packets": flow.packet_count,
            "bytes": flow.byte_count,
            "start_time": flow.start_time.isoformat(),
            "last_time": flow.last_time.isoformat(),
            "duration": flow.duration,
            "flags": flow.get_tcp_flags_summary()
        }
        
        # Create alert
        alert = Alert(
            alert_id=None,  # Will be assigned by AlertManager
            timestamp=time.time(),
            alert_type=prediction,
            severity="medium",  # Default severity, will be updated by AlertManager
            source="SentinelX-IDS",
            message=f"Detected {prediction} from {flow.src_ip}:{flow.src_port} to {flow.dst_ip}:{flow.dst_port}",
            details=details
        )
        
        return alert
    
    def enrich_ip(self, ip_address: str):
        """Enrich an IP address with threat intelligence.
        
        Args:
            ip_address: The IP address to enrich
            
        Returns:
            Dictionary of enrichment data
        """
        try:
            return self.threat_enricher.enrich_ip(ip_address)
        except Exception as e:
            self.logger.error(f"Error enriching IP {ip_address}: {str(e)}")
            return {}
    
    def enrich_domain(self, domain: str):
        """Enrich a domain with threat intelligence.
        
        Args:
            domain: The domain to enrich
            
        Returns:
            Dictionary of enrichment data
        """
        try:
            return self.threat_enricher.enrich_domain(domain)
        except Exception as e:
            self.logger.error(f"Error enriching domain {domain}: {str(e)}")
            return {}
    
    def get_alerts(self, limit: int = 100, offset: int = 0, severity: Optional[str] = None):
        """Get alerts from the alert manager.
        
        Args:
            limit: Maximum number of alerts to return
            offset: Offset for pagination
            severity: Filter by severity
            
        Returns:
            List of alerts
        """
        try:
            return self.alert_manager.get_alerts(limit, offset, severity)
        except Exception as e:
            self.logger.error(f"Error getting alerts: {str(e)}")
            return []
    
    def get_alert(self, alert_id: str):
        """Get a specific alert by ID.
        
        Args:
            alert_id: The alert ID
            
        Returns:
            Alert object or None if not found
        """
        try:
            return self.alert_manager.get_alert(alert_id)
        except Exception as e:
            self.logger.error(f"Error getting alert {alert_id}: {str(e)}")
            return None
    
    def update_alert(self, alert_id: str, status: Optional[str] = None, notes: Optional[str] = None):
        """Update an alert.
        
        Args:
            alert_id: The alert ID
            status: New status (optional)
            notes: Notes to add (optional)
            
        Returns:
            True if update was successful, False otherwise
        """
        try:
            return self.alert_manager.update_alert(alert_id, status, notes)
        except Exception as e:
            self.logger.error(f"Error updating alert {alert_id}: {str(e)}")
            return False
    
    def analyze_alert(self, alert_id: str):
        """Analyze an alert using the threat reasoning engine.
        
        Args:
            alert_id: The alert ID
            
        Returns:
            Dictionary of analysis results
        """
        try:
            # Get alert
            alert = self.alert_manager.get_alert(alert_id)
            if not alert:
                self.logger.error(f"Alert {alert_id} not found")
                return {}
            
            # Analyze alert
            analysis = self.threat_reasoning.analyze_alert(alert)
            
            # Get MITRE ATT&CK context
            mitre_techniques = self.mitre_context.map_alert_to_techniques(alert)
            
            # Get CVE context
            cves = self.cve_context.find_cves_for_alert(alert)
            
            # Combine results
            result = {
                "analysis": analysis,
                "mitre_techniques": mitre_techniques,
                "cves": cves
            }
            
            return result
        
        except Exception as e:
            self.logger.error(f"Error analyzing alert {alert_id}: {str(e)}")
            return {}
    
    def generate_report(self, alert_id: str, format: str = 'json'):
        """Generate a report for an alert.
        
        Args:
            alert_id: The alert ID
            format: Report format ('json', 'html', or 'markdown')
            
        Returns:
            Report data
        """
        try:
            # Get alert
            alert = self.alert_manager.get_alert(alert_id)
            if not alert:
                self.logger.error(f"Alert {alert_id} not found")
                return {}
            
            # Analyze alert
            analysis = self.analyze_alert(alert_id)
            
            # Generate report
            report = self.report_generator.generate_alert_report(
                alert,
                analysis.get('analysis', {}),
                analysis.get('mitre_techniques', []),
                analysis.get('cves', [])
            )
            
            # Save report
            report_path = self.config.get('reasoning', {}).get('report_path', 'reports')
            os.makedirs(report_path, exist_ok=True)
            
            if format == 'json':
                report_file = os.path.join(report_path, f"report_{alert_id}.json")
                self.report_generator.save_report_json(report, report_file)
            elif format == 'html':
                report_file = os.path.join(report_path, f"report_{alert_id}.html")
                self.report_generator.save_report_html(report, report_file)
            elif format == 'markdown':
                report_file = os.path.join(report_path, f"report_{alert_id}.md")
                self.report_generator.save_report_markdown(report, report_file)
            else:
                self.logger.error(f"Unknown report format: {format}")
                return {}
            
            self.logger.info(f"Generated {format} report for alert {alert_id} at {report_file}")
            
            # Return report data
            return {
                "report": report,
                "file": report_file
            }
        
        except Exception as e:
            self.logger.error(f"Error generating report for alert {alert_id}: {str(e)}")
            return {}
    
    def generate_summary_report(self, alert_ids: List[str], format: str = 'json'):
        """Generate a summary report for multiple alerts.
        
        Args:
            alert_ids: List of alert IDs
            format: Report format ('json', 'html', or 'markdown')
            
        Returns:
            Report data
        """
        try:
            # Get alerts
            alerts = []
            for alert_id in alert_ids:
                alert = self.alert_manager.get_alert(alert_id)
                if alert:
                    alerts.append(alert)
                else:
                    self.logger.warning(f"Alert {alert_id} not found")
            
            if not alerts:
                self.logger.error("No valid alerts found")
                return {}
            
            # Analyze alerts
            analyses = []
            mitre_techniques = []
            cves = []
            
            for alert in alerts:
                analysis = self.analyze_alert(alert.alert_id)
                analyses.append(analysis.get('analysis', {}))
                mitre_techniques.extend(analysis.get('mitre_techniques', []))
                cves.extend(analysis.get('cves', []))
            
            # Generate summary report
            report = self.report_generator.generate_summary_report(
                alerts,
                analyses,
                mitre_techniques,
                cves
            )
            
            # Save report
            report_path = self.config.get('reasoning', {}).get('report_path', 'reports')
            os.makedirs(report_path, exist_ok=True)
            
            timestamp = int(time.time())
            if format == 'json':
                report_file = os.path.join(report_path, f"summary_report_{timestamp}.json")
                self.report_generator.save_report_json(report, report_file)
            elif format == 'html':
                report_file = os.path.join(report_path, f"summary_report_{timestamp}.html")
                self.report_generator.save_report_html(report, report_file)
            elif format == 'markdown':
                report_file = os.path.join(report_path, f"summary_report_{timestamp}.md")
                self.report_generator.save_report_markdown(report, report_file)
            else:
                self.logger.error(f"Unknown report format: {format}")
                return {}
            
            self.logger.info(f"Generated {format} summary report for {len(alerts)} alerts at {report_file}")
            
            # Return report data
            return {
                "report": report,
                "file": report_file
            }
        
        except Exception as e:
            self.logger.error(f"Error generating summary report: {str(e)}")
            return {}
    
    def get_network_stats(self):
        """Get network statistics.
        
        Returns:
            Dictionary of network statistics
        """
        try:
            # Get packet capture stats
            packet_stats = self.packet_capture.get_stats()
            
            # Get flow analyzer stats
            flow_stats = {
                "active_flows": len(self.flow_analyzer.get_active_flows()),
                "total_flows": self.flow_analyzer.total_flows,
                "expired_flows": self.flow_analyzer.expired_flows
            }
            
            # Get top talkers
            top_talkers = self.flow_analyzer.get_top_talkers(10)
            
            # Get alert stats
            alert_stats = {
                "total_alerts": self.alert_manager.get_alert_count(),
                "by_severity": {
                    "critical": self.alert_manager.get_alert_count(severity="critical"),
                    "high": self.alert_manager.get_alert_count(severity="high"),
                    "medium": self.alert_manager.get_alert_count(severity="medium"),
                    "low": self.alert_manager.get_alert_count(severity="low")
                }
            }
            
            return {
                "packet_stats": packet_stats,
                "flow_stats": flow_stats,
                "top_talkers": top_talkers,
                "alert_stats": alert_stats,
                "monitoring_active": self.is_running
            }
        
        except Exception as e:
            self.logger.error(f"Error getting network stats: {str(e)}")
            return {}
    
    def get_available_interfaces(self):
        """Get available network interfaces.
        
        Returns:
            List of available interfaces
        """
        try:
            return self.packet_capture.get_available_interfaces()
        except Exception as e:
            self.logger.error(f"Error getting available interfaces: {str(e)}")
            return []
    
    def shutdown(self):
        """Shutdown the SentinelX system."""
        self.logger.info("Shutting down SentinelX")
        
        # Stop monitoring if running
        if self.is_running:
            self.stop_monitoring()
        
        # Close any open resources
        if self.packet_capture:
            self.packet_capture.cleanup()
        
        if self.threat_enricher:
            self.threat_enricher.cleanup()
        
        if self.alert_manager:
            self.alert_manager.save_alerts()
        
        self.logger.info("SentinelX shutdown complete")


def main():
    """Main entry point for the SentinelX system."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="SentinelX - AI-Powered Cyber Threat Intelligence System")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--train", action="store_true", help="Train the model")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate the model")
    parser.add_argument("--monitor", action="store_true", help="Start network monitoring")
    parser.add_argument("--interface", help="Network interface to monitor")
    parser.add_argument("--model", default="random_forest", help="Model type to use")
    parser.add_argument("--dataset", help="Path to dataset")
    args = parser.parse_args()
    
    # Initialize SentinelX
    sentinelx = SentinelX(args.config)
    sentinelx.setup()
    
    # Register signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        print("\nShutting down SentinelX...")
        sentinelx.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Train model if requested
        if args.train:
            print(f"Training {args.model} model...")
            success = sentinelx.train_model(args.model, args.dataset)
            if success:
                print("Model training complete")
            else:
                print("Model training failed")
        
        # Evaluate model if requested
        if args.evaluate:
            print(f"Evaluating {args.model} model...")
            metrics = sentinelx.evaluate_model(args.model, args.dataset)
            print("Evaluation metrics:")
            for metric, value in metrics.items():
                print(f"  {metric}: {value}")
        
        # Start monitoring if requested
        if args.monitor:
            print("Starting network monitoring...")
            success = sentinelx.start_monitoring(args.interface)
            if success:
                print("Monitoring started. Press Ctrl+C to stop.")
                
                # Keep the main thread alive
                while True:
                    time.sleep(1)
            else:
                print("Failed to start monitoring")
        
        # If no action specified, print help
        if not (args.train or args.evaluate or args.monitor):
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\nShutting down SentinelX...")
        sentinelx.shutdown()
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sentinelx.shutdown()


if __name__ == "__main__":
    main()