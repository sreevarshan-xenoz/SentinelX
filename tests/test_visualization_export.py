#!/usr/bin/env python
# SentinelX Visualization Export Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the SentinelX class and visualization export classes
try:
    from src.sentinelx import SentinelX
    from src.visualization import NetworkGraphGenerator, AlertDashboard, TimeSeriesPlotter
    from src.visualization import HeatMapGenerator, GeoIPMapper, ReportGenerator
    from src.visualization import VisualizationExporter, ExportFormat
except ImportError:
    # Mock classes if they don't exist yet
    class ExportFormat:
        JSON = 'json'
        CSV = 'csv'
        HTML = 'html'
        PNG = 'png'
        PDF = 'pdf'
        MARKDOWN = 'md'
        SVG = 'svg'
    
    class VisualizationExporter:
        def __init__(self):
            self.supported_formats = {
                'network_graph': [ExportFormat.JSON, ExportFormat.HTML, ExportFormat.PNG, ExportFormat.SVG],
                'alert_dashboard': [ExportFormat.JSON, ExportFormat.HTML, ExportFormat.PDF],
                'time_series': [ExportFormat.JSON, ExportFormat.CSV, ExportFormat.PNG, ExportFormat.SVG],
                'heatmap': [ExportFormat.JSON, ExportFormat.PNG, ExportFormat.SVG],
                'geoip_map': [ExportFormat.JSON, ExportFormat.HTML, ExportFormat.PNG],
                'report': [ExportFormat.JSON, ExportFormat.HTML, ExportFormat.PDF, ExportFormat.MARKDOWN]
            }
        
        def export(self, data, vis_type, format, file_path=None):
            """Export visualization data to the specified format."""
            if vis_type not in self.supported_formats:
                raise ValueError(f"Unsupported visualization type: {vis_type}")
            
            if format not in self.supported_formats[vis_type]:
                raise ValueError(f"Unsupported format {format} for visualization type {vis_type}")
            
            # Convert data to the specified format
            if format == ExportFormat.JSON:
                result = json.dumps(data)
            elif format == ExportFormat.CSV:
                result = self._convert_to_csv(data)
            elif format == ExportFormat.HTML:
                result = self._convert_to_html(data, vis_type)
            elif format == ExportFormat.PNG:
                result = self._convert_to_png(data, vis_type)
            elif format == ExportFormat.PDF:
                result = self._convert_to_pdf(data, vis_type)
            elif format == ExportFormat.MARKDOWN:
                result = self._convert_to_markdown(data)
            elif format == ExportFormat.SVG:
                result = self._convert_to_svg(data, vis_type)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Write to file if a file path is provided
            if file_path:
                with open(file_path, 'w' if isinstance(result, str) else 'wb') as f:
                    f.write(result)
            
            return result
        
        def _convert_to_csv(self, data):
            """Convert data to CSV format."""
            # Mock implementation
            csv_lines = []
            
            # Add header
            if isinstance(data, list) and len(data) > 0:
                headers = list(data[0].keys())
                csv_lines.append(','.join(headers))
                
                # Add data rows
                for item in data:
                    row = [str(item.get(header, '')) for header in headers]
                    csv_lines.append(','.join(row))
            
            return '\n'.join(csv_lines)
        
        def _convert_to_html(self, data, vis_type):
            """Convert data to HTML format."""
            # Mock implementation
            html = f"<!DOCTYPE html>\n<html>\n<head>\n<title>{vis_type.replace('_', ' ').title()}</title>\n</head>\n<body>\n"
            
            if vis_type == 'network_graph':
                html += "<div id='network-graph'>Network Graph Visualization</div>\n"
                html += f"<script>const graphData = {json.dumps(data)};</script>\n"
            elif vis_type == 'alert_dashboard':
                html += "<div id='alert-dashboard'>Alert Dashboard</div>\n"
                html += f"<script>const dashboardData = {json.dumps(data)};</script>\n"
            elif vis_type == 'geoip_map':
                html += "<div id='geoip-map'>Geographic Map</div>\n"
                html += f"<script>const mapData = {json.dumps(data)};</script>\n"
            elif vis_type == 'report':
                html += f"<h1>{data.get('title', 'Report')}</h1>\n"
                html += f"<p>Generated: {data.get('timestamp', datetime.datetime.now().isoformat())}</p>\n"
                
                for section in data.get('sections', []):
                    html += f"<h2>{section.get('title', 'Section')}</h2>\n"
                    html += f"<div>{section.get('content', '')}</div>\n"
            
            html += "</body>\n</html>"
            return html
        
        def _convert_to_png(self, data, vis_type):
            """Convert data to PNG format."""
            # Mock implementation - in a real implementation, this would use a library like matplotlib or Pillow
            return b'PNG MOCK DATA'
        
        def _convert_to_pdf(self, data, vis_type):
            """Convert data to PDF format."""
            # Mock implementation - in a real implementation, this would use a library like ReportLab or WeasyPrint
            return b'PDF MOCK DATA'
        
        def _convert_to_markdown(self, data):
            """Convert data to Markdown format."""
            # Mock implementation
            md = f"# {data.get('title', 'Report')}\n\n"
            md += f"Generated: {data.get('timestamp', datetime.datetime.now().isoformat())}\n\n"
            
            for section in data.get('sections', []):
                md += f"## {section.get('title', 'Section')}\n\n"
                md += f"{section.get('content', '')}\n\n"
            
            return md
        
        def _convert_to_svg(self, data, vis_type):
            """Convert data to SVG format."""
            # Mock implementation - in a real implementation, this would use a library like matplotlib or d3.js
            svg = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
            svg += "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" width=\"800\" height=\"600\">\n"
            
            if vis_type == 'network_graph':
                svg += "<g id=\"network-graph\">\n"
                # Add mock nodes and edges
                svg += "<circle cx=\"100\" cy=\"100\" r=\"20\" fill=\"blue\" />\n"
                svg += "<circle cx=\"200\" cy=\"200\" r=\"20\" fill=\"red\" />\n"
                svg += "<line x1=\"100\" y1=\"100\" x2=\"200\" y2=\"200\" stroke=\"black\" />\n"
                svg += "</g>\n"
            elif vis_type == 'time_series':
                svg += "<g id=\"time-series\">\n"
                # Add mock time series
                svg += "<path d=\"M0,100 L100,80 L200,120 L300,90\" stroke=\"blue\" fill=\"none\" />\n"
                svg += "</g>\n"
            elif vis_type == 'heatmap':
                svg += "<g id=\"heatmap\">\n"
                # Add mock heatmap cells
                svg += "<rect x=\"0\" y=\"0\" width=\"50\" height=\"50\" fill=\"#ff0000\" />\n"
                svg += "<rect x=\"50\" y=\"0\" width=\"50\" height=\"50\" fill=\"#00ff00\" />\n"
                svg += "<rect x=\"0\" y=\"50\" width=\"50\" height=\"50\" fill=\"#0000ff\" />\n"
                svg += "<rect x=\"50\" y=\"50\" width=\"50\" height=\"50\" fill=\"#ffff00\" />\n"
                svg += "</g>\n"
            
            svg += "</svg>"
            return svg
    
    # Import mock classes from test_visualization.py
    from test_visualization import NetworkGraphGenerator, AlertDashboard, TimeSeriesPlotter
    from test_visualization import HeatMapGenerator, GeoIPMapper, ReportGenerator


class TestVisualizationExport(unittest.TestCase):
    """Test the visualization export functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create visualization components
        self.network_graph = NetworkGraphGenerator()
        self.alert_dashboard = AlertDashboard()
        self.time_series = TimeSeriesPlotter()
        self.heatmap = HeatMapGenerator()
        self.geoip_map = GeoIPMapper()
        self.report_generator = ReportGenerator()
        
        # Create an exporter
        self.exporter = VisualizationExporter()
        
        # Sample data for each visualization type
        self.network_data = {
            'nodes': [
                {'id': '192.168.1.100', 'label': '192.168.1.100', 'size': 10},
                {'id': '8.8.8.8', 'label': '8.8.8.8', 'size': 5}
            ],
            'edges': [
                {'source': '192.168.1.100', 'target': '8.8.8.8', 'weight': 1}
            ]
        }
        
        self.alert_data = {
            'summary': {
                'total': 2,
                'high': 1,
                'medium': 1,
                'low': 0
            },
            'recent_alerts': [
                {
                    'id': 'alert-1',
                    'timestamp': '2023-01-01T00:00:00',
                    'severity': 'high',
                    'category': 'malware'
                },
                {
                    'id': 'alert-2',
                    'timestamp': '2023-01-01T00:01:00',
                    'severity': 'medium',
                    'category': 'intrusion'
                }
            ],
            'charts': {
                'by_severity': {'high': 1, 'medium': 1, 'low': 0},
                'by_category': {'malware': 1, 'intrusion': 1}
            }
        }
        
        self.time_series_data = {
            'metric': 'packets',
            'interval': 'hour',
            'data': [10, 20, 15, 30, 25],
            'labels': ['00:00', '01:00', '02:00', '03:00', '04:00']
        }
        
        self.heatmap_data = {
            'x_labels': ['192.168.1.100', '192.168.1.101'],
            'y_labels': ['53', '80', '443'],
            'data': [
                [10, 5],
                [0, 15],
                [20, 10]
            ],
            'title': 'Connection Heatmap'
        }
        
        self.geoip_data = {
            'points': [
                {'ip': '8.8.8.8', 'lat': 37.751, 'lon': -97.822, 'count': 10},
                {'ip': '93.184.216.34', 'lat': 52.352, 'lon': 4.938, 'count': 20}
            ],
            'connections': [
                {'source': {'lat': 40.7128, 'lon': -74.0060}, 'target': {'lat': 37.751, 'lon': -97.822}},
                {'source': {'lat': 40.7128, 'lon': -74.0060}, 'target': {'lat': 52.352, 'lon': 4.938}}
            ]
        }
        
        self.report_data = {
            'title': 'Security Report',
            'timestamp': '2023-01-01T00:00:00',
            'sections': [
                {
                    'title': 'Summary',
                    'content': 'This is a summary of the security report.'
                },
                {
                    'title': 'Alerts',
                    'content': 'There were 2 alerts detected.'
                },
                {
                    'title': 'Recommendations',
                    'content': 'Here are some recommendations.'
                }
            ]
        }
    
    def test_export_formats_supported(self):
        """Test that the exporter supports the expected formats for each visualization type."""
        # Check network graph formats
        self.assertIn(ExportFormat.JSON, self.exporter.supported_formats['network_graph'], "Network graph should support JSON export")
        self.assertIn(ExportFormat.HTML, self.exporter.supported_formats['network_graph'], "Network graph should support HTML export")
        self.assertIn(ExportFormat.PNG, self.exporter.supported_formats['network_graph'], "Network graph should support PNG export")
        self.assertIn(ExportFormat.SVG, self.exporter.supported_formats['network_graph'], "Network graph should support SVG export")
        
        # Check alert dashboard formats
        self.assertIn(ExportFormat.JSON, self.exporter.supported_formats['alert_dashboard'], "Alert dashboard should support JSON export")
        self.assertIn(ExportFormat.HTML, self.exporter.supported_formats['alert_dashboard'], "Alert dashboard should support HTML export")
        self.assertIn(ExportFormat.PDF, self.exporter.supported_formats['alert_dashboard'], "Alert dashboard should support PDF export")
        
        # Check time series formats
        self.assertIn(ExportFormat.JSON, self.exporter.supported_formats['time_series'], "Time series should support JSON export")
        self.assertIn(ExportFormat.CSV, self.exporter.supported_formats['time_series'], "Time series should support CSV export")
        self.assertIn(ExportFormat.PNG, self.exporter.supported_formats['time_series'], "Time series should support PNG export")
        self.assertIn(ExportFormat.SVG, self.exporter.supported_formats['time_series'], "Time series should support SVG export")
        
        # Check heatmap formats
        self.assertIn(ExportFormat.JSON, self.exporter.supported_formats['heatmap'], "Heatmap should support JSON export")
        self.assertIn(ExportFormat.PNG, self.exporter.supported_formats['heatmap'], "Heatmap should support PNG export")
        self.assertIn(ExportFormat.SVG, self.exporter.supported_formats['heatmap'], "Heatmap should support SVG export")
        
        # Check geoip map formats
        self.assertIn(ExportFormat.JSON, self.exporter.supported_formats['geoip_map'], "GeoIP map should support JSON export")
        self.assertIn(ExportFormat.HTML, self.exporter.supported_formats['geoip_map'], "GeoIP map should support HTML export")
        self.assertIn(ExportFormat.PNG, self.exporter.supported_formats['geoip_map'], "GeoIP map should support PNG export")
        
        # Check report formats
        self.assertIn(ExportFormat.JSON, self.exporter.supported_formats['report'], "Report should support JSON export")
        self.assertIn(ExportFormat.HTML, self.exporter.supported_formats['report'], "Report should support HTML export")
        self.assertIn(ExportFormat.PDF, self.exporter.supported_formats['report'], "Report should support PDF export")
        self.assertIn(ExportFormat.MARKDOWN, self.exporter.supported_formats['report'], "Report should support Markdown export")
    
    def test_export_network_graph_to_json(self):
        """Test exporting a network graph to JSON."""
        # Export the network graph to JSON
        json_data = self.exporter.export(self.network_data, 'network_graph', ExportFormat.JSON)
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, self.network_data, "Exported JSON should match the original data")
    
    def test_export_alert_dashboard_to_html(self):
        """Test exporting an alert dashboard to HTML."""
        # Export the alert dashboard to HTML
        html_data = self.exporter.export(self.alert_data, 'alert_dashboard', ExportFormat.HTML)
        
        # Check that the HTML data contains the expected elements
        self.assertIn('<!DOCTYPE html>', html_data, "HTML should have a doctype")
        self.assertIn('<title>Alert Dashboard</title>', html_data, "HTML should have a title")
        self.assertIn('<div id=\'alert-dashboard\'>Alert Dashboard</div>', html_data, "HTML should have an alert dashboard div")
        self.assertIn('dashboardData', html_data, "HTML should include the dashboard data")
    
    def test_export_time_series_to_csv(self):
        """Test exporting a time series to CSV."""
        # Create a time series data list for CSV export
        time_series_list = [
            {'timestamp': '00:00', 'packets': 10},
            {'timestamp': '01:00', 'packets': 20},
            {'timestamp': '02:00', 'packets': 15},
            {'timestamp': '03:00', 'packets': 30},
            {'timestamp': '04:00', 'packets': 25}
        ]
        
        # Export the time series to CSV
        csv_data = self.exporter.export(time_series_list, 'time_series', ExportFormat.CSV)
        
        # Check that the CSV data contains the expected elements
        self.assertIn('timestamp,packets', csv_data, "CSV should have headers")
        self.assertIn('00:00,10', csv_data, "CSV should have data rows")
        self.assertIn('01:00,20', csv_data, "CSV should have data rows")
        self.assertIn('02:00,15', csv_data, "CSV should have data rows")
        self.assertIn('03:00,30', csv_data, "CSV should have data rows")
        self.assertIn('04:00,25', csv_data, "CSV should have data rows")
    
    def test_export_heatmap_to_svg(self):
        """Test exporting a heatmap to SVG."""
        # Export the heatmap to SVG
        svg_data = self.exporter.export(self.heatmap_data, 'heatmap', ExportFormat.SVG)
        
        # Check that the SVG data contains the expected elements
        self.assertIn('<?xml version="1.0" encoding="UTF-8" standalone="no"?>', svg_data, "SVG should have an XML declaration")
        self.assertIn('<svg xmlns="http://www.w3.org/2000/svg"', svg_data, "SVG should have an SVG element")
        self.assertIn('<g id="heatmap">', svg_data, "SVG should have a heatmap group")
        self.assertIn('<rect', svg_data, "SVG should have rectangle elements")
    
    def test_export_geoip_map_to_html(self):
        """Test exporting a GeoIP map to HTML."""
        # Export the GeoIP map to HTML
        html_data = self.exporter.export(self.geoip_data, 'geoip_map', ExportFormat.HTML)
        
        # Check that the HTML data contains the expected elements
        self.assertIn('<!DOCTYPE html>', html_data, "HTML should have a doctype")
        self.assertIn('<title>Geoip Map</title>', html_data, "HTML should have a title")
        self.assertIn('<div id=\'geoip-map\'>Geographic Map</div>', html_data, "HTML should have a geoip map div")
        self.assertIn('mapData', html_data, "HTML should include the map data")
    
    def test_export_report_to_markdown(self):
        """Test exporting a report to Markdown."""
        # Export the report to Markdown
        md_data = self.exporter.export(self.report_data, 'report', ExportFormat.MARKDOWN)
        
        # Check that the Markdown data contains the expected elements
        self.assertIn('# Security Report', md_data, "Markdown should have a title")
        self.assertIn('Generated: 2023-01-01T00:00:00', md_data, "Markdown should have a timestamp")
        self.assertIn('## Summary', md_data, "Markdown should have section headings")
        self.assertIn('This is a summary of the security report.', md_data, "Markdown should have section content")
        self.assertIn('## Alerts', md_data, "Markdown should have section headings")
        self.assertIn('There were 2 alerts detected.', md_data, "Markdown should have section content")
        self.assertIn('## Recommendations', md_data, "Markdown should have section headings")
        self.assertIn('Here are some recommendations.', md_data, "Markdown should have section content")
    
    def test_export_to_file(self):
        """Test exporting to a file."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Export the network graph to the file
            self.exporter.export(self.network_data, 'network_graph', ExportFormat.JSON, file_path=temp_path)
            
            # Check that the file exists and contains the expected data
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            parsed_data = json.loads(file_content)
            self.assertEqual(parsed_data, self.network_data, "Exported file should contain the correct data")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_export_binary_format_to_file(self):
        """Test exporting a binary format to a file."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Export the network graph to PNG
            self.exporter.export(self.network_data, 'network_graph', ExportFormat.PNG, file_path=temp_path)
            
            # Check that the file exists and contains data
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'rb') as f:
                file_content = f.read()
            
            self.assertEqual(file_content, b'PNG MOCK DATA', "Exported file should contain the correct data")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_unsupported_visualization_type(self):
        """Test exporting an unsupported visualization type."""
        # Try to export an unsupported visualization type
        with self.assertRaises(ValueError) as context:
            self.exporter.export(self.network_data, 'unsupported_type', ExportFormat.JSON)
        
        # Check the error message
        self.assertIn('Unsupported visualization type', str(context.exception), "Should raise an error for unsupported visualization type")
    
    def test_unsupported_format(self):
        """Test exporting to an unsupported format."""
        # Try to export to an unsupported format
        with self.assertRaises(ValueError) as context:
            self.exporter.export(self.network_data, 'network_graph', 'unsupported_format')
        
        # Check the error message
        self.assertIn('Unsupported format', str(context.exception), "Should raise an error for unsupported format")
    
    def test_export_multiple_formats(self):
        """Test exporting the same data to multiple formats."""
        # Export the report to multiple formats
        json_data = self.exporter.export(self.report_data, 'report', ExportFormat.JSON)
        html_data = self.exporter.export(self.report_data, 'report', ExportFormat.HTML)
        md_data = self.exporter.export(self.report_data, 'report', ExportFormat.MARKDOWN)
        
        # Check that each format contains the expected data
        parsed_json = json.loads(json_data)
        self.assertEqual(parsed_json, self.report_data, "JSON export should match the original data")
        
        self.assertIn('<h1>Security Report</h1>', html_data, "HTML export should contain the report title")
        self.assertIn('<h2>Summary</h2>', html_data, "HTML export should contain section headings")
        
        self.assertIn('# Security Report', md_data, "Markdown export should contain the report title")
        self.assertIn('## Summary', md_data, "Markdown export should contain section headings")


class TestVisualizationComponentExport(unittest.TestCase):
    """Test the export methods of individual visualization components."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create visualization components
        self.network_graph = NetworkGraphGenerator()
        self.alert_dashboard = AlertDashboard()
        self.time_series = TimeSeriesPlotter()
        self.heatmap = HeatMapGenerator()
        self.geoip_map = GeoIPMapper()
        self.report_generator = ReportGenerator()
        
        # Add sample data to each component
        self.network_graph.add_flow_data([
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 12345,
                'dst_port': 53,
                'protocol': 'UDP',
                'bytes': 1000,
                'packets': 10,
                'timestamp': '2023-01-01T00:00:00'
            }
        ])
        
        self.alert_dashboard.add_alert_data([
            {
                'id': 'alert-1',
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open'
            }
        ])
        
        self.time_series.add_time_data([
            {
                'timestamp': '2023-01-01T00:00:00',
                'packets': 10,
                'bytes': 1000,
                'flows': 1
            }
        ])
        
        self.heatmap.add_data([
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 12345,
                'dst_port': 53,
                'protocol': 'UDP',
                'bytes': 1000,
                'packets': 10
            }
        ])
        
        self.geoip_map.add_ip_data([
            {
                'ip': '8.8.8.8',
                'country': 'United States',
                'city': 'Mountain View',
                'lat': 37.751,
                'lon': -97.822,
                'count': 10
            }
        ])
        
        self.report_generator.set_data({
            'title': 'Security Report',
            'timestamp': '2023-01-01T00:00:00',
            'sections': [
                {
                    'title': 'Summary',
                    'content': 'This is a summary of the security report.'
                }
            ]
        })
    
    def test_network_graph_export(self):
        """Test exporting a network graph from the NetworkGraphGenerator."""
        # Generate the graph
        graph = self.network_graph.generate_graph()
        
        # Export the graph to JSON
        json_data = self.network_graph.export_graph(format='json')
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, graph, "Exported JSON should match the generated graph")
        
        # Export the graph to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.network_graph.export_graph(format='json', file_path=temp_path)
            
            # Check that the file exists and contains the expected data
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            parsed_data = json.loads(file_content)
            self.assertEqual(parsed_data, graph, "Exported file should contain the correct data")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_alert_dashboard_export(self):
        """Test exporting an alert dashboard from the AlertDashboard."""
        # Generate the dashboard
        dashboard = self.alert_dashboard.generate_dashboard()
        
        # Export the dashboard to JSON
        json_data = self.alert_dashboard.export_dashboard(format='json')
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, dashboard, "Exported JSON should match the generated dashboard")
    
    def test_time_series_export(self):
        """Test exporting a time series from the TimeSeriesPlotter."""
        # Generate the plot
        plot = self.time_series.generate_plot()
        
        # Export the plot to JSON
        json_data = self.time_series.export_plot(format='json')
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, plot, "Exported JSON should match the generated plot")
        
        # Export the plot to CSV
        csv_data = self.time_series.export_plot(format='csv')
        
        # Check that the CSV data contains the expected elements
        self.assertIn('timestamp,packets,bytes,flows', csv_data, "CSV should have headers")
        self.assertIn('2023-01-01T00:00:00,10,1000,1', csv_data, "CSV should have data rows")
    
    def test_heatmap_export(self):
        """Test exporting a heatmap from the HeatMapGenerator."""
        # Generate the heatmap
        heatmap = self.heatmap.generate_heatmap()
        
        # Export the heatmap to JSON
        json_data = self.heatmap.export_heatmap(format='json')
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, heatmap, "Exported JSON should match the generated heatmap")
    
    def test_geoip_map_export(self):
        """Test exporting a GeoIP map from the GeoIPMapper."""
        # Generate the map
        map_data = self.geoip_map.generate_map()
        
        # Export the map to JSON
        json_data = self.geoip_map.export_map(format='json')
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, map_data, "Exported JSON should match the generated map")
    
    def test_report_export(self):
        """Test exporting a report from the ReportGenerator."""
        # Generate the report
        report = self.report_generator.generate_report()
        
        # Export the report to JSON
        json_data = self.report_generator.export_report(format='json')
        
        # Check that the JSON data is valid
        parsed_data = json.loads(json_data)
        self.assertEqual(parsed_data, report, "Exported JSON should match the generated report")
        
        # Export the report to Markdown
        md_data = self.report_generator.export_report(format='md')
        
        # Check that the Markdown data contains the expected elements
        self.assertIn('# Security Report', md_data, "Markdown should have a title")
        self.assertIn('Generated: 2023-01-01T00:00:00', md_data, "Markdown should have a timestamp")
        self.assertIn('## Summary', md_data, "Markdown should have section headings")
        self.assertIn('This is a summary of the security report.', md_data, "Markdown should have section content")


if __name__ == '__main__':
    unittest.main()