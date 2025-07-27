#!/usr/bin/env python
# SentinelX Visualization Example

import os
import sys
import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.sentinelx import SentinelX
from src.visualization.visualization_manager import VisualizationManager
from src.visualization.export import VisualizationExporter, ExportFormat


def main():
    """Example of using SentinelX visualization components programmatically."""
    print("SentinelX Visualization Example")
    print("-" * 40)
    
    # Initialize SentinelX
    sentinelx = SentinelX()
    
    # Initialize VisualizationManager
    vis_manager = VisualizationManager(sentinelx)
    
    # Get the current time
    now = datetime.datetime.now()
    
    # Define a time window for the last 24 hours
    time_window = {
        'start': (now - datetime.timedelta(hours=24)).isoformat(),
        'end': now.isoformat()
    }
    
    # Generate a network graph
    print("\nGenerating network graph...")
    network_graph = vis_manager.generate_network_graph(time_window=time_window, top_n=10)
    
    # Export the network graph to HTML
    network_output = "network_graph.html"
    vis_manager.export_visualization(
        vis_type='network_graph',
        format='html',
        file_path=network_output
    )
    print(f"Network graph exported to {network_output}")
    
    # Generate an alert dashboard
    print("\nGenerating alert dashboard...")
    alert_dashboard = vis_manager.generate_alert_dashboard(time_window=time_window)
    
    # Export the alert dashboard to JSON
    alert_output = "alert_dashboard.json"
    vis_manager.export_visualization(
        vis_type='alert_dashboard',
        format='json',
        file_path=alert_output
    )
    print(f"Alert dashboard exported to {alert_output}")
    
    # Generate a time series plot
    print("\nGenerating time series plot...")
    time_series = vis_manager.generate_time_series(
        metric="packets",
        interval="hour",
        time_window=time_window
    )
    
    # Export the time series plot to PNG
    timeseries_output = "time_series.png"
    vis_manager.export_visualization(
        vis_type='time_series',
        format='png',
        file_path=timeseries_output
    )
    print(f"Time series plot exported to {timeseries_output}")
    
    # Generate a heatmap
    print("\nGenerating heatmap...")
    heatmap = vis_manager.generate_heatmap(
        metric="connections",
        groupby_x="source_ip",
        groupby_y="destination_port"
    )
    
    # Export the heatmap to SVG
    heatmap_output = "heatmap.svg"
    vis_manager.export_visualization(
        vis_type='heatmap',
        format='svg',
        file_path=heatmap_output
    )
    print(f"Heatmap exported to {heatmap_output}")
    
    # Generate a GeoIP map
    print("\nGenerating GeoIP map...")
    geoip_map = vis_manager.generate_geoip_map(include_internal=False)
    
    # Export the GeoIP map to HTML
    geoip_output = "geoip_map.html"
    vis_manager.export_visualization(
        vis_type='geoip_map',
        format='html',
        file_path=geoip_output
    )
    print(f"GeoIP map exported to {geoip_output}")
    
    # Generate a security report
    print("\nGenerating security report...")
    report = vis_manager.generate_report(report_type="summary", time_period="day")
    
    # Export the report to PDF
    report_output = "security_report.pdf"
    vis_manager.export_visualization(
        vis_type='report',
        format='pdf',
        file_path=report_output
    )
    print(f"Security report exported to {report_output}")
    
    print("\nAll visualizations generated successfully!")


if __name__ == "__main__":
    main()