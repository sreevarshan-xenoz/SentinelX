#!/usr/bin/env python
# SentinelX Visualization CLI Tool

import os
import sys
import argparse
import json
import datetime
from pathlib import Path

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.sentinelx import SentinelX
from src.visualization.visualization_manager import VisualizationManager
from src.visualization.export import VisualizationExporter, ExportFormat


class VisualizationCLI:
    """Command-line interface for SentinelX visualization components."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.parser = argparse.ArgumentParser(
            description="SentinelX Visualization CLI Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.setup_parsers()
        self.sentinelx = None
        self.vis_manager = None
        self.exporter = VisualizationExporter()
    
    def setup_parsers(self):
        """Set up the command-line argument parsers."""
        # Add global arguments
        self.parser.add_argument(
            "--config", "-c",
            help="Path to SentinelX configuration file",
            default=None
        )
        
        # Create subparsers for different commands
        subparsers = self.parser.add_subparsers(dest="command", help="Command to execute")
        
        # Network graph command
        network_parser = subparsers.add_parser("network", help="Generate network graph visualization")
        network_parser.add_argument(
            "--time-window", "-t",
            help="Time window for data (e.g., '1h', '1d', '7d')",
            default="1h"
        )
        network_parser.add_argument(
            "--top", "-n",
            help="Number of top nodes to include",
            type=int,
            default=10
        )
        network_parser.add_argument(
            "--format", "-f",
            help="Output format (json, html, png, svg)",
            choices=["json", "html", "png", "svg"],
            default="json"
        )
        network_parser.add_argument(
            "--output", "-o",
            help="Output file path",
            default=None
        )
        
        # Alert dashboard command
        alert_parser = subparsers.add_parser("alerts", help="Generate alert dashboard visualization")
        alert_parser.add_argument(
            "--time-window", "-t",
            help="Time window for data (e.g., '1h', '1d', '7d')",
            default="1d"
        )
        alert_parser.add_argument(
            "--severity", "-s",
            help="Filter by severity (high, medium, low, all)",
            choices=["high", "medium", "low", "all"],
            default="all"
        )
        alert_parser.add_argument(
            "--format", "-f",
            help="Output format (json, html, pdf)",
            choices=["json", "html", "pdf"],
            default="json"
        )
        alert_parser.add_argument(
            "--output", "-o",
            help="Output file path",
            default=None
        )
        
        # Time series command
        timeseries_parser = subparsers.add_parser("timeseries", help="Generate time series visualization")
        timeseries_parser.add_argument(
            "--metric", "-m",
            help="Metric to plot (packets, bytes, flows)",
            choices=["packets", "bytes", "flows"],
            default="packets"
        )
        timeseries_parser.add_argument(
            "--interval", "-i",
            help="Time interval (minute, hour, day)",
            choices=["minute", "hour", "day"],
            default="hour"
        )
        timeseries_parser.add_argument(
            "--time-window", "-t",
            help="Time window for data (e.g., '1h', '1d', '7d')",
            default="1d"
        )
        timeseries_parser.add_argument(
            "--format", "-f",
            help="Output format (json, csv, png, svg)",
            choices=["json", "csv", "png", "svg"],
            default="json"
        )
        timeseries_parser.add_argument(
            "--output", "-o",
            help="Output file path",
            default=None
        )
        
        # Heatmap command
        heatmap_parser = subparsers.add_parser("heatmap", help="Generate heatmap visualization")
        heatmap_parser.add_argument(
            "--metric", "-m",
            help="Metric to plot (connections, packets, bytes)",
            choices=["connections", "packets", "bytes"],
            default="connections"
        )
        heatmap_parser.add_argument(
            "--x-axis", "-x",
            help="X-axis grouping (source_ip, destination_ip, source_port, destination_port, protocol)",
            choices=["source_ip", "destination_ip", "source_port", "destination_port", "protocol"],
            default="source_ip"
        )
        heatmap_parser.add_argument(
            "--y-axis", "-y",
            help="Y-axis grouping (source_ip, destination_ip, source_port, destination_port, protocol)",
            choices=["source_ip", "destination_ip", "source_port", "destination_port", "protocol"],
            default="destination_port"
        )
        heatmap_parser.add_argument(
            "--format", "-f",
            help="Output format (json, png, svg)",
            choices=["json", "png", "svg"],
            default="json"
        )
        heatmap_parser.add_argument(
            "--output", "-o",
            help="Output file path",
            default=None
        )
        
        # GeoIP map command
        geoip_parser = subparsers.add_parser("geomap", help="Generate geographic IP map visualization")
        geoip_parser.add_argument(
            "--include-internal", "-i",
            help="Include internal IP addresses",
            action="store_true"
        )
        geoip_parser.add_argument(
            "--format", "-f",
            help="Output format (json, html, png)",
            choices=["json", "html", "png"],
            default="json"
        )
        geoip_parser.add_argument(
            "--output", "-o",
            help="Output file path",
            default=None
        )
        
        # Report command
        report_parser = subparsers.add_parser("report", help="Generate comprehensive security report")
        report_parser.add_argument(
            "--type", "-t",
            help="Report type (summary, detailed)",
            choices=["summary", "detailed"],
            default="summary"
        )
        report_parser.add_argument(
            "--period", "-p",
            help="Time period (hour, day, week, month)",
            choices=["hour", "day", "week", "month"],
            default="day"
        )
        report_parser.add_argument(
            "--format", "-f",
            help="Output format (json, html, pdf, md)",
            choices=["json", "html", "pdf", "md"],
            default="html"
        )
        report_parser.add_argument(
            "--output", "-o",
            help="Output file path",
            default=None
        )
        
        # Dashboard command
        dashboard_parser = subparsers.add_parser("dashboard", help="Launch interactive web dashboard")
        dashboard_parser.add_argument(
            "--port", "-p",
            help="Port to run the dashboard on",
            type=int,
            default=8050
        )
        dashboard_parser.add_argument(
            "--debug", "-d",
            help="Run in debug mode",
            action="store_true"
        )
    
    def initialize_sentinelx(self, config_path=None):
        """Initialize the SentinelX instance."""
        if not self.sentinelx:
            self.sentinelx = SentinelX(config_path=config_path)
            self.vis_manager = VisualizationManager(self.sentinelx)
    
    def parse_time_window(self, time_window):
        """Parse a time window string into a dictionary."""
        if not time_window:
            return None
        
        # Get the current time
        now = datetime.datetime.now()
        
        # Parse the time window string
        if time_window.endswith('h'):
            hours = int(time_window[:-1])
            start_time = now - datetime.timedelta(hours=hours)
        elif time_window.endswith('d'):
            days = int(time_window[:-1])
            start_time = now - datetime.timedelta(days=days)
        elif time_window.endswith('w'):
            weeks = int(time_window[:-1])
            start_time = now - datetime.timedelta(weeks=weeks)
        else:
            # Default to 1 day if format is not recognized
            start_time = now - datetime.timedelta(days=1)
        
        return {
            'start': start_time.isoformat(),
            'end': now.isoformat()
        }
    
    def get_output_path(self, args, default_filename):
        """Get the output file path."""
        if args.output:
            return args.output
        
        # Create a default output path
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{default_filename}_{timestamp}.{args.format}"
        return os.path.join(os.getcwd(), filename)
    
    def handle_network_command(self, args):
        """Handle the network graph command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Parse the time window
        time_window = self.parse_time_window(args.time_window)
        
        # Generate the network graph
        graph = self.vis_manager.generate_network_graph(time_window=time_window, top_n=args.top)
        
        # Get the output path
        output_path = self.get_output_path(args, "network_graph")
        
        # Export the graph
        result = self.vis_manager.export_visualization(
            vis_type='network_graph',
            format=args.format,
            file_path=output_path
        )
        
        print(f"Network graph exported to {output_path}")
        
        return result
    
    def handle_alerts_command(self, args):
        """Handle the alert dashboard command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Parse the time window
        time_window = self.parse_time_window(args.time_window)
        
        # Set the severity filter
        severity = None if args.severity == 'all' else args.severity
        
        # Generate the alert dashboard
        dashboard = self.vis_manager.generate_alert_dashboard(time_window=time_window, severity=severity)
        
        # Get the output path
        output_path = self.get_output_path(args, "alert_dashboard")
        
        # Export the dashboard
        result = self.vis_manager.export_visualization(
            vis_type='alert_dashboard',
            format=args.format,
            file_path=output_path
        )
        
        print(f"Alert dashboard exported to {output_path}")
        
        return result
    
    def handle_timeseries_command(self, args):
        """Handle the time series command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Parse the time window
        time_window = self.parse_time_window(args.time_window)
        
        # Generate the time series plot
        plot = self.vis_manager.generate_time_series(
            metric=args.metric,
            interval=args.interval,
            time_window=time_window
        )
        
        # Get the output path
        output_path = self.get_output_path(args, "time_series")
        
        # Export the plot
        result = self.vis_manager.export_visualization(
            vis_type='time_series',
            format=args.format,
            file_path=output_path
        )
        
        print(f"Time series plot exported to {output_path}")
        
        return result
    
    def handle_heatmap_command(self, args):
        """Handle the heatmap command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Generate the heatmap
        heatmap = self.vis_manager.generate_heatmap(
            metric=args.metric,
            groupby_x=args.x_axis,
            groupby_y=args.y_axis
        )
        
        # Get the output path
        output_path = self.get_output_path(args, "heatmap")
        
        # Export the heatmap
        result = self.vis_manager.export_visualization(
            vis_type='heatmap',
            format=args.format,
            file_path=output_path
        )
        
        print(f"Heatmap exported to {output_path}")
        
        return result
    
    def handle_geomap_command(self, args):
        """Handle the GeoIP map command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Generate the GeoIP map
        map_data = self.vis_manager.generate_geoip_map(include_internal=args.include_internal)
        
        # Get the output path
        output_path = self.get_output_path(args, "geoip_map")
        
        # Export the map
        result = self.vis_manager.export_visualization(
            vis_type='geoip_map',
            format=args.format,
            file_path=output_path
        )
        
        print(f"GeoIP map exported to {output_path}")
        
        return result
    
    def handle_report_command(self, args):
        """Handle the report command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Generate the report
        report = self.vis_manager.generate_report(report_type=args.type, time_period=args.period)
        
        # Get the output path
        output_path = self.get_output_path(args, "security_report")
        
        # Export the report
        result = self.vis_manager.export_visualization(
            vis_type='report',
            format=args.format,
            file_path=output_path
        )
        
        print(f"Security report exported to {output_path}")
        
        return result
    
    def handle_dashboard_command(self, args):
        """Handle the dashboard command."""
        # Initialize SentinelX
        self.initialize_sentinelx(args.config)
        
        # Import the dashboard app here to avoid circular imports
        from src.visualization.web_app import DashboardApp
        
        # Create and run the dashboard app
        app = DashboardApp(self.sentinelx, port=args.port, debug=args.debug)
        print(f"Starting dashboard on http://localhost:{args.port}")
        app.run()
        
        return "Dashboard started"
    
    def run(self, args=None):
        """Run the CLI with the given arguments."""
        # Parse arguments
        args = self.parser.parse_args(args)
        
        # Handle the command
        if args.command == "network":
            return self.handle_network_command(args)
        elif args.command == "alerts":
            return self.handle_alerts_command(args)
        elif args.command == "timeseries":
            return self.handle_timeseries_command(args)
        elif args.command == "heatmap":
            return self.handle_heatmap_command(args)
        elif args.command == "geomap":
            return self.handle_geomap_command(args)
        elif args.command == "report":
            return self.handle_report_command(args)
        elif args.command == "dashboard":
            return self.handle_dashboard_command(args)
        else:
            self.parser.print_help()
            return None


def main():
    """Main entry point for the CLI."""
    cli = VisualizationCLI()
    cli.run()


if __name__ == "__main__":
    main()