#!/usr/bin/env python
# SentinelX Visualization Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the visualization classes
try:
    from src.visualization import NetworkGraphGenerator, AlertDashboard, TimeSeriesPlotter
    from src.visualization import HeatMapGenerator, GeoIPMapper, ReportGenerator
except ImportError:
    # Mock classes if they don't exist yet
    class NetworkGraphGenerator:
        def __init__(self, flow_data=None):
            self.flow_data = flow_data or []
            self.graph = None
        
        def generate_graph(self, time_window=None, top_n=10, include_ports=True):
            # Mock graph generation
            self.graph = {
                'nodes': [
                    {'id': '192.168.1.1', 'label': '192.168.1.1', 'size': 10, 'type': 'source'},
                    {'id': '8.8.8.8', 'label': '8.8.8.8', 'size': 5, 'type': 'destination'}
                ],
                'edges': [
                    {'source': '192.168.1.1', 'target': '8.8.8.8', 'value': 100, 'label': 'TCP:443'}
                ]
            }
            return self.graph
        
        def add_flow_data(self, flow_data):
            if isinstance(flow_data, list):
                self.flow_data.extend(flow_data)
            else:
                self.flow_data.append(flow_data)
        
        def clear_data(self):
            self.flow_data = []
            self.graph = None
        
        def export_graph(self, format='json', file_path=None):
            if not self.graph:
                self.generate_graph()
            
            if format == 'json':
                data = json.dumps(self.graph)
            elif format == 'graphml':
                data = "<graphml>Mock GraphML data</graphml>"
            elif format == 'gexf':
                data = "<gexf>Mock GEXF data</gexf>"
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)
            
            return data
        
        def highlight_node(self, node_id, color='red', size_multiplier=1.5):
            if not self.graph:
                self.generate_graph()
            
            for node in self.graph['nodes']:
                if node['id'] == node_id:
                    node['color'] = color
                    node['size'] = node['size'] * size_multiplier
            
            return self.graph
        
        def filter_by_protocol(self, protocol):
            if not self.graph:
                self.generate_graph()
            
            filtered_edges = [edge for edge in self.graph['edges'] 
                             if protocol.upper() in edge['label']]
            
            # Create a set of nodes that are connected by the filtered edges
            nodes_in_edges = set()
            for edge in filtered_edges:
                nodes_in_edges.add(edge['source'])
                nodes_in_edges.add(edge['target'])
            
            filtered_nodes = [node for node in self.graph['nodes'] 
                              if node['id'] in nodes_in_edges]
            
            return {
                'nodes': filtered_nodes,
                'edges': filtered_edges
            }
    
    class AlertDashboard:
        def __init__(self, alert_data=None):
            self.alert_data = alert_data or []
            self.dashboard = None
        
        def generate_dashboard(self, time_window=None, severity_filter=None, category_filter=None):
            # Mock dashboard generation
            self.dashboard = {
                'summary': {
                    'total_alerts': len(self.alert_data),
                    'by_severity': {'high': 2, 'medium': 3, 'low': 5},
                    'by_category': {'malware': 3, 'intrusion': 2, 'anomaly': 5},
                    'by_status': {'open': 7, 'closed': 3}
                },
                'recent_alerts': self.alert_data[:5] if len(self.alert_data) > 5 else self.alert_data,
                'charts': {
                    'severity_pie': {'data': [2, 3, 5], 'labels': ['high', 'medium', 'low']},
                    'category_pie': {'data': [3, 2, 5], 'labels': ['malware', 'intrusion', 'anomaly']},
                    'timeline': {'data': [1, 2, 3, 2, 2], 'labels': ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5']}
                }
            }
            return self.dashboard
        
        def add_alert_data(self, alert_data):
            if isinstance(alert_data, list):
                self.alert_data.extend(alert_data)
            else:
                self.alert_data.append(alert_data)
        
        def clear_data(self):
            self.alert_data = []
            self.dashboard = None
        
        def export_dashboard(self, format='json', file_path=None):
            if not self.dashboard:
                self.generate_dashboard()
            
            if format == 'json':
                data = json.dumps(self.dashboard)
            elif format == 'html':
                data = "<html><body>Mock dashboard HTML</body></html>"
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)
            
            return data
        
        def filter_by_severity(self, severity):
            filtered_alerts = [alert for alert in self.alert_data 
                              if alert.get('severity') == severity]
            
            dashboard_copy = AlertDashboard(filtered_alerts)
            return dashboard_copy.generate_dashboard()
        
        def filter_by_category(self, category):
            filtered_alerts = [alert for alert in self.alert_data 
                              if alert.get('category') == category]
            
            dashboard_copy = AlertDashboard(filtered_alerts)
            return dashboard_copy.generate_dashboard()
    
    class TimeSeriesPlotter:
        def __init__(self, time_data=None):
            self.time_data = time_data or []
            self.plot = None
        
        def generate_plot(self, metric='packets', interval='hour', start_time=None, end_time=None):
            # Mock plot generation
            self.plot = {
                'metric': metric,
                'interval': interval,
                'data': [10, 25, 15, 30, 20],
                'labels': ['00:00', '01:00', '02:00', '03:00', '04:00'],
                'title': f"{metric.capitalize()} per {interval}"
            }
            return self.plot
        
        def add_time_data(self, time_data):
            if isinstance(time_data, list):
                self.time_data.extend(time_data)
            else:
                self.time_data.append(time_data)
        
        def clear_data(self):
            self.time_data = []
            self.plot = None
        
        def export_plot(self, format='json', file_path=None):
            if not self.plot:
                self.generate_plot()
            
            if format == 'json':
                data = json.dumps(self.plot)
            elif format == 'png':
                data = b'Mock PNG data'
            elif format == 'svg':
                data = "<svg>Mock SVG data</svg>"
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if file_path:
                mode = 'wb' if format == 'png' else 'w'
                with open(file_path, mode) as f:
                    f.write(data)
            
            return data
        
        def compare_metrics(self, metrics=['packets', 'bytes'], interval='hour'):
            if not self.time_data:
                return {}
            
            result = {}
            for metric in metrics:
                result[metric] = self.generate_plot(metric=metric, interval=interval)
            
            return result
        
        def detect_anomalies(self, threshold=2.0, metric='packets'):
            if not self.plot:
                self.generate_plot(metric=metric)
            
            # Mock anomaly detection
            mean = sum(self.plot['data']) / len(self.plot['data'])
            std_dev = (sum((x - mean) ** 2 for x in self.plot['data']) / len(self.plot['data'])) ** 0.5
            
            anomalies = []
            for i, value in enumerate(self.plot['data']):
                if abs(value - mean) > threshold * std_dev:
                    anomalies.append({
                        'index': i,
                        'time': self.plot['labels'][i],
                        'value': value,
                        'z_score': (value - mean) / std_dev
                    })
            
            return anomalies
    
    class HeatMapGenerator:
        def __init__(self, data=None):
            self.data = data or []
            self.heatmap = None
        
        def generate_heatmap(self, metric='connections', groupby_x='source_ip', groupby_y='destination_port'):
            # Mock heatmap generation
            self.heatmap = {
                'x_labels': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
                'y_labels': ['80', '443', '22', '53'],
                'data': [
                    [10, 5, 2],
                    [15, 8, 3],
                    [1, 0, 5],
                    [7, 3, 1]
                ],
                'title': f"{metric.capitalize()} by {groupby_x} and {groupby_y}"
            }
            return self.heatmap
        
        def add_data(self, data):
            if isinstance(data, list):
                self.data.extend(data)
            else:
                self.data.append(data)
        
        def clear_data(self):
            self.data = []
            self.heatmap = None
        
        def export_heatmap(self, format='json', file_path=None):
            if not self.heatmap:
                self.generate_heatmap()
            
            if format == 'json':
                data = json.dumps(self.heatmap)
            elif format == 'png':
                data = b'Mock PNG data'
            elif format == 'svg':
                data = "<svg>Mock SVG data</svg>"
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if file_path:
                mode = 'wb' if format == 'png' else 'w'
                with open(file_path, mode) as f:
                    f.write(data)
            
            return data
        
        def highlight_cell(self, x_index, y_index, color='red'):
            if not self.heatmap:
                self.generate_heatmap()
            
            # Mock highlighting a cell
            highlighted_heatmap = self.heatmap.copy()
            highlighted_heatmap['highlighted_cells'] = [{'x': x_index, 'y': y_index, 'color': color}]
            
            return highlighted_heatmap
    
    class GeoIPMapper:
        def __init__(self, ip_data=None):
            self.ip_data = ip_data or []
            self.map = None
        
        def generate_map(self, ip_type='all', include_internal=False):
            # Mock map generation
            self.map = {
                'points': [
                    {'ip': '8.8.8.8', 'lat': 37.751, 'lon': -97.822, 'country': 'United States', 'count': 15},
                    {'ip': '93.184.216.34', 'lat': 51.507, 'lon': -0.127, 'country': 'United Kingdom', 'count': 8}
                ],
                'connections': [
                    {'source': {'ip': '192.168.1.1', 'lat': 0, 'lon': 0, 'country': 'Internal'},
                     'destination': {'ip': '8.8.8.8', 'lat': 37.751, 'lon': -97.822, 'country': 'United States'},
                     'count': 10}
                ]
            }
            return self.map
        
        def add_ip_data(self, ip_data):
            if isinstance(ip_data, list):
                self.ip_data.extend(ip_data)
            else:
                self.ip_data.append(ip_data)
        
        def clear_data(self):
            self.ip_data = []
            self.map = None
        
        def export_map(self, format='json', file_path=None):
            if not self.map:
                self.generate_map()
            
            if format == 'json':
                data = json.dumps(self.map)
            elif format == 'html':
                data = "<html><body>Mock map HTML</body></html>"
            elif format == 'kml':
                data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><kml>Mock KML data</kml>"
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(data)
            
            return data
        
        def filter_by_country(self, country):
            if not self.map:
                self.generate_map()
            
            filtered_points = [point for point in self.map['points'] 
                              if point['country'] == country]
            
            filtered_connections = [conn for conn in self.map['connections'] 
                                  if conn['destination']['country'] == country]
            
            return {
                'points': filtered_points,
                'connections': filtered_connections
            }
        
        def get_country_stats(self):
            if not self.map:
                self.generate_map()
            
            country_stats = {}
            for point in self.map['points']:
                country = point['country']
                if country not in country_stats:
                    country_stats[country] = 0
                country_stats[country] += point['count']
            
            return country_stats
    
    class ReportGenerator:
        def __init__(self, data=None):
            self.data = data or {}
            self.report = None
        
        def generate_report(self, report_type='summary', time_period='day'):
            # Mock report generation
            self.report = {
                'title': f"{report_type.capitalize()} Report - {time_period.capitalize()}",
                'timestamp': datetime.datetime.now().isoformat(),
                'sections': [
                    {
                        'title': 'Network Activity Summary',
                        'content': 'Mock network activity summary content',
                        'charts': ['network_graph', 'traffic_timeline']
                    },
                    {
                        'title': 'Alert Summary',
                        'content': 'Mock alert summary content',
                        'charts': ['alert_severity_pie', 'alert_timeline']
                    },
                    {
                        'title': 'Geographic Distribution',
                        'content': 'Mock geographic distribution content',
                        'charts': ['geo_map']
                    }
                ]
            }
            return self.report
        
        def set_data(self, data):
            self.data = data
        
        def clear_data(self):
            self.data = {}
            self.report = None
        
        def export_report(self, format='json', file_path=None):
            if not self.report:
                self.generate_report()
            
            if format == 'json':
                data = json.dumps(self.report)
            elif format == 'html':
                data = "<html><body>Mock report HTML</body></html>"
            elif format == 'pdf':
                data = b'Mock PDF data'
            elif format == 'markdown':
                data = "# Mock Report\n\n## Network Activity Summary\n\nMock network activity summary content\n"
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if file_path:
                mode = 'wb' if format == 'pdf' else 'w'
                with open(file_path, mode) as f:
                    f.write(data)
            
            return data
        
        def add_section(self, title, content, charts=None):
            if not self.report:
                self.generate_report()
            
            self.report['sections'].append({
                'title': title,
                'content': content,
                'charts': charts or []
            })
            
            return self.report
        
        def get_section(self, section_title):
            if not self.report:
                self.generate_report()
            
            for section in self.report['sections']:
                if section['title'] == section_title:
                    return section
            
            return None


class TestNetworkGraphGenerator(unittest.TestCase):
    """Test the NetworkGraphGenerator class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create sample flow data
        self.flow_data = [
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'src_port': 12345,
                'dst_port': 53,
                'protocol': 'UDP',
                'bytes': 1000,
                'packets': 10,
                'timestamp': '2023-01-01T00:00:00'
            },
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '93.184.216.34',
                'src_port': 54321,
                'dst_port': 443,
                'protocol': 'TCP',
                'bytes': 2000,
                'packets': 20,
                'timestamp': '2023-01-01T00:01:00'
            },
            {
                'src_ip': '192.168.1.200',
                'dst_ip': '8.8.8.8',
                'src_port': 23456,
                'dst_port': 53,
                'protocol': 'UDP',
                'bytes': 500,
                'packets': 5,
                'timestamp': '2023-01-01T00:02:00'
            }
        ]
        
        # Create a NetworkGraphGenerator instance
        self.graph_generator = NetworkGraphGenerator(self.flow_data)
    
    def test_generate_graph(self):
        """Test generating a network graph."""
        # Generate the graph
        graph = self.graph_generator.generate_graph()
        
        # Check that the graph has nodes and edges
        self.assertIn('nodes', graph, "Graph should have nodes")
        self.assertIn('edges', graph, "Graph should have edges")
        
        # Check that the graph has the correct number of nodes and edges
        # We expect 3 unique IPs: 192.168.1.100, 192.168.1.200, 8.8.8.8, 93.184.216.34
        self.assertEqual(len(graph['nodes']), 4, "Graph should have 4 nodes")
        
        # We expect 3 edges (one for each flow)
        self.assertEqual(len(graph['edges']), 3, "Graph should have 3 edges")
    
    def test_add_flow_data(self):
        """Test adding flow data to the graph generator."""
        # Create a new graph generator with no initial data
        graph_generator = NetworkGraphGenerator()
        
        # Add a single flow
        graph_generator.add_flow_data(self.flow_data[0])
        
        # Generate the graph and check that it has the correct number of nodes and edges
        graph = graph_generator.generate_graph()
        self.assertEqual(len(graph['nodes']), 2, "Graph should have 2 nodes")
        self.assertEqual(len(graph['edges']), 1, "Graph should have 1 edge")
        
        # Add multiple flows
        graph_generator.add_flow_data(self.flow_data[1:])
        
        # Generate the graph and check that it has the correct number of nodes and edges
        graph = graph_generator.generate_graph()
        self.assertEqual(len(graph['nodes']), 4, "Graph should have 4 nodes")
        self.assertEqual(len(graph['edges']), 3, "Graph should have 3 edges")
    
    def test_clear_data(self):
        """Test clearing the flow data."""
        # Generate a graph first
        self.graph_generator.generate_graph()
        
        # Clear the data
        self.graph_generator.clear_data()
        
        # Check that the flow data and graph are cleared
        self.assertEqual(len(self.graph_generator.flow_data), 0, "Flow data should be empty")
        self.assertIsNone(self.graph_generator.graph, "Graph should be None")
    
    def test_export_graph(self):
        """Test exporting the graph in different formats."""
        # Generate the graph
        self.graph_generator.generate_graph()
        
        # Export as JSON
        json_data = self.graph_generator.export_graph(format='json')
        self.assertIsInstance(json_data, str, "JSON data should be a string")
        
        # Parse the JSON and check that it has the correct structure
        graph = json.loads(json_data)
        self.assertIn('nodes', graph, "Graph should have nodes")
        self.assertIn('edges', graph, "Graph should have edges")
        
        # Export as GraphML
        graphml_data = self.graph_generator.export_graph(format='graphml')
        self.assertIsInstance(graphml_data, str, "GraphML data should be a string")
        self.assertIn('<graphml>', graphml_data, "GraphML data should contain <graphml> tag")
        
        # Export as GEXF
        gexf_data = self.graph_generator.export_graph(format='gexf')
        self.assertIsInstance(gexf_data, str, "GEXF data should be a string")
        self.assertIn('<gexf>', gexf_data, "GEXF data should contain <gexf> tag")
        
        # Export to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.graph_generator.export_graph(format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            graph = json.loads(file_content)
            self.assertIn('nodes', graph, "Graph should have nodes")
            self.assertIn('edges', graph, "Graph should have edges")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_highlight_node(self):
        """Test highlighting a node in the graph."""
        # Generate the graph
        self.graph_generator.generate_graph()
        
        # Highlight a node
        highlighted_graph = self.graph_generator.highlight_node('8.8.8.8', color='red', size_multiplier=2.0)
        
        # Check that the node is highlighted
        highlighted_node = None
        for node in highlighted_graph['nodes']:
            if node['id'] == '8.8.8.8':
                highlighted_node = node
                break
        
        self.assertIsNotNone(highlighted_node, "Highlighted node should exist")
        self.assertEqual(highlighted_node['color'], 'red', "Highlighted node should have the correct color")
        self.assertGreater(highlighted_node['size'], 5, "Highlighted node should have increased size")
    
    def test_filter_by_protocol(self):
        """Test filtering the graph by protocol."""
        # Generate the graph
        self.graph_generator.generate_graph()
        
        # Filter by UDP protocol
        filtered_graph = self.graph_generator.filter_by_protocol('UDP')
        
        # Check that the filtered graph only contains UDP edges
        self.assertGreater(len(filtered_graph['edges']), 0, "Filtered graph should have edges")
        for edge in filtered_graph['edges']:
            self.assertIn('UDP', edge['label'], "Edge should be UDP")
        
        # Check that the filtered graph only contains nodes connected by UDP edges
        node_ids = [node['id'] for node in filtered_graph['nodes']]
        for edge in filtered_graph['edges']:
            self.assertIn(edge['source'], node_ids, "Edge source should be in nodes")
            self.assertIn(edge['target'], node_ids, "Edge target should be in nodes")


class TestAlertDashboard(unittest.TestCase):
    """Test the AlertDashboard class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create sample alert data
        self.alert_data = [
            {
                'id': 'alert-1',
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open'
            },
            {
                'id': 'alert-2',
                'timestamp': '2023-01-01T00:01:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '93.184.216.34',
                'severity': 'medium',
                'category': 'intrusion',
                'status': 'open'
            },
            {
                'id': 'alert-3',
                'timestamp': '2023-01-01T00:02:00',
                'source_ip': '192.168.1.200',
                'destination_ip': '8.8.8.8',
                'severity': 'low',
                'category': 'anomaly',
                'status': 'closed'
            }
        ]
        
        # Create an AlertDashboard instance
        self.dashboard = AlertDashboard(self.alert_data)
    
    def test_generate_dashboard(self):
        """Test generating an alert dashboard."""
        # Generate the dashboard
        dashboard = self.dashboard.generate_dashboard()
        
        # Check that the dashboard has the correct structure
        self.assertIn('summary', dashboard, "Dashboard should have a summary")
        self.assertIn('recent_alerts', dashboard, "Dashboard should have recent alerts")
        self.assertIn('charts', dashboard, "Dashboard should have charts")
        
        # Check the summary
        self.assertEqual(dashboard['summary']['total_alerts'], 3, "Total alerts should be 3")
        self.assertIn('by_severity', dashboard['summary'], "Summary should have severity breakdown")
        self.assertIn('by_category', dashboard['summary'], "Summary should have category breakdown")
        self.assertIn('by_status', dashboard['summary'], "Summary should have status breakdown")
        
        # Check the recent alerts
        self.assertEqual(len(dashboard['recent_alerts']), 3, "Should have 3 recent alerts")
        
        # Check the charts
        self.assertIn('severity_pie', dashboard['charts'], "Charts should include severity pie")
        self.assertIn('category_pie', dashboard['charts'], "Charts should include category pie")
        self.assertIn('timeline', dashboard['charts'], "Charts should include timeline")
    
    def test_add_alert_data(self):
        """Test adding alert data to the dashboard."""
        # Create a new dashboard with no initial data
        dashboard = AlertDashboard()
        
        # Add a single alert
        dashboard.add_alert_data(self.alert_data[0])
        
        # Generate the dashboard and check that it has the correct data
        dash = dashboard.generate_dashboard()
        self.assertEqual(dash['summary']['total_alerts'], 1, "Total alerts should be 1")
        
        # Add multiple alerts
        dashboard.add_alert_data(self.alert_data[1:])
        
        # Generate the dashboard and check that it has the correct data
        dash = dashboard.generate_dashboard()
        self.assertEqual(dash['summary']['total_alerts'], 3, "Total alerts should be 3")
    
    def test_clear_data(self):
        """Test clearing the alert data."""
        # Generate a dashboard first
        self.dashboard.generate_dashboard()
        
        # Clear the data
        self.dashboard.clear_data()
        
        # Check that the alert data and dashboard are cleared
        self.assertEqual(len(self.dashboard.alert_data), 0, "Alert data should be empty")
        self.assertIsNone(self.dashboard.dashboard, "Dashboard should be None")
    
    def test_export_dashboard(self):
        """Test exporting the dashboard in different formats."""
        # Generate the dashboard
        self.dashboard.generate_dashboard()
        
        # Export as JSON
        json_data = self.dashboard.export_dashboard(format='json')
        self.assertIsInstance(json_data, str, "JSON data should be a string")
        
        # Parse the JSON and check that it has the correct structure
        dashboard = json.loads(json_data)
        self.assertIn('summary', dashboard, "Dashboard should have a summary")
        self.assertIn('recent_alerts', dashboard, "Dashboard should have recent alerts")
        self.assertIn('charts', dashboard, "Dashboard should have charts")
        
        # Export as HTML
        html_data = self.dashboard.export_dashboard(format='html')
        self.assertIsInstance(html_data, str, "HTML data should be a string")
        self.assertIn('<html>', html_data, "HTML data should contain <html> tag")
        
        # Export to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.dashboard.export_dashboard(format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            dashboard = json.loads(file_content)
            self.assertIn('summary', dashboard, "Dashboard should have a summary")
            self.assertIn('recent_alerts', dashboard, "Dashboard should have recent alerts")
            self.assertIn('charts', dashboard, "Dashboard should have charts")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_filter_by_severity(self):
        """Test filtering the dashboard by severity."""
        # Generate the dashboard
        self.dashboard.generate_dashboard()
        
        # Filter by high severity
        filtered_dashboard = self.dashboard.filter_by_severity('high')
        
        # Check that the filtered dashboard only contains high severity alerts
        self.assertEqual(filtered_dashboard['summary']['total_alerts'], 1, "Should have 1 high severity alert")
        self.assertEqual(filtered_dashboard['summary']['by_severity']['high'], 1, "Should have 1 high severity alert")
        
        # Filter by medium severity
        filtered_dashboard = self.dashboard.filter_by_severity('medium')
        
        # Check that the filtered dashboard only contains medium severity alerts
        self.assertEqual(filtered_dashboard['summary']['total_alerts'], 1, "Should have 1 medium severity alert")
        self.assertEqual(filtered_dashboard['summary']['by_severity']['medium'], 1, "Should have 1 medium severity alert")
    
    def test_filter_by_category(self):
        """Test filtering the dashboard by category."""
        # Generate the dashboard
        self.dashboard.generate_dashboard()
        
        # Filter by malware category
        filtered_dashboard = self.dashboard.filter_by_category('malware')
        
        # Check that the filtered dashboard only contains malware category alerts
        self.assertEqual(filtered_dashboard['summary']['total_alerts'], 1, "Should have 1 malware category alert")
        self.assertEqual(filtered_dashboard['summary']['by_category']['malware'], 1, "Should have 1 malware category alert")
        
        # Filter by intrusion category
        filtered_dashboard = self.dashboard.filter_by_category('intrusion')
        
        # Check that the filtered dashboard only contains intrusion category alerts
        self.assertEqual(filtered_dashboard['summary']['total_alerts'], 1, "Should have 1 intrusion category alert")
        self.assertEqual(filtered_dashboard['summary']['by_category']['intrusion'], 1, "Should have 1 intrusion category alert")


class TestTimeSeriesPlotter(unittest.TestCase):
    """Test the TimeSeriesPlotter class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create sample time series data
        self.time_data = [
            {
                'timestamp': '2023-01-01T00:00:00',
                'packets': 100,
                'bytes': 10000,
                'flows': 10
            },
            {
                'timestamp': '2023-01-01T01:00:00',
                'packets': 200,
                'bytes': 20000,
                'flows': 20
            },
            {
                'timestamp': '2023-01-01T02:00:00',
                'packets': 150,
                'bytes': 15000,
                'flows': 15
            },
            {
                'timestamp': '2023-01-01T03:00:00',
                'packets': 300,
                'bytes': 30000,
                'flows': 30
            },
            {
                'timestamp': '2023-01-01T04:00:00',
                'packets': 250,
                'bytes': 25000,
                'flows': 25
            }
        ]
        
        # Create a TimeSeriesPlotter instance
        self.plotter = TimeSeriesPlotter(self.time_data)
    
    def test_generate_plot(self):
        """Test generating a time series plot."""
        # Generate the plot for packets
        plot = self.plotter.generate_plot(metric='packets', interval='hour')
        
        # Check that the plot has the correct structure
        self.assertEqual(plot['metric'], 'packets', "Plot metric should be packets")
        self.assertEqual(plot['interval'], 'hour', "Plot interval should be hour")
        self.assertIn('data', plot, "Plot should have data")
        self.assertIn('labels', plot, "Plot should have labels")
        self.assertIn('title', plot, "Plot should have a title")
        
        # Check that the plot has the correct number of data points
        self.assertEqual(len(plot['data']), 5, "Plot should have 5 data points")
        self.assertEqual(len(plot['labels']), 5, "Plot should have 5 labels")
        
        # Generate the plot for bytes
        plot = self.plotter.generate_plot(metric='bytes', interval='hour')
        
        # Check that the plot has the correct metric
        self.assertEqual(plot['metric'], 'bytes', "Plot metric should be bytes")
    
    def test_add_time_data(self):
        """Test adding time data to the plotter."""
        # Create a new plotter with no initial data
        plotter = TimeSeriesPlotter()
        
        # Add a single time point
        plotter.add_time_data(self.time_data[0])
        
        # Generate the plot and check that it has the correct data
        plot = plotter.generate_plot(metric='packets')
        self.assertEqual(len(plot['data']), 1, "Plot should have 1 data point")
        
        # Add multiple time points
        plotter.add_time_data(self.time_data[1:])
        
        # Generate the plot and check that it has the correct data
        plot = plotter.generate_plot(metric='packets')
        self.assertEqual(len(plot['data']), 5, "Plot should have 5 data points")
    
    def test_clear_data(self):
        """Test clearing the time data."""
        # Generate a plot first
        self.plotter.generate_plot()
        
        # Clear the data
        self.plotter.clear_data()
        
        # Check that the time data and plot are cleared
        self.assertEqual(len(self.plotter.time_data), 0, "Time data should be empty")
        self.assertIsNone(self.plotter.plot, "Plot should be None")
    
    def test_export_plot(self):
        """Test exporting the plot in different formats."""
        # Generate the plot
        self.plotter.generate_plot()
        
        # Export as JSON
        json_data = self.plotter.export_plot(format='json')
        self.assertIsInstance(json_data, str, "JSON data should be a string")
        
        # Parse the JSON and check that it has the correct structure
        plot = json.loads(json_data)
        self.assertIn('data', plot, "Plot should have data")
        self.assertIn('labels', plot, "Plot should have labels")
        
        # Export as PNG
        png_data = self.plotter.export_plot(format='png')
        self.assertIsInstance(png_data, bytes, "PNG data should be bytes")
        
        # Export as SVG
        svg_data = self.plotter.export_plot(format='svg')
        self.assertIsInstance(svg_data, str, "SVG data should be a string")
        self.assertIn('<svg>', svg_data, "SVG data should contain <svg> tag")
        
        # Export to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.plotter.export_plot(format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            plot = json.loads(file_content)
            self.assertIn('data', plot, "Plot should have data")
            self.assertIn('labels', plot, "Plot should have labels")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_compare_metrics(self):
        """Test comparing multiple metrics."""
        # Compare packets and bytes
        comparison = self.plotter.compare_metrics(metrics=['packets', 'bytes'])
        
        # Check that the comparison has the correct metrics
        self.assertIn('packets', comparison, "Comparison should have packets metric")
        self.assertIn('bytes', comparison, "Comparison should have bytes metric")
        
        # Check that each metric has the correct structure
        self.assertEqual(comparison['packets']['metric'], 'packets', "Packets plot metric should be packets")
        self.assertEqual(comparison['bytes']['metric'], 'bytes', "Bytes plot metric should be bytes")
    
    def test_detect_anomalies(self):
        """Test detecting anomalies in the time series."""
        # Generate the plot
        self.plotter.generate_plot(metric='packets')
        
        # Detect anomalies with a threshold of 2.0 standard deviations
        anomalies = self.plotter.detect_anomalies(threshold=2.0, metric='packets')
        
        # Check that anomalies are detected correctly
        self.assertIsInstance(anomalies, list, "Anomalies should be a list")
        
        # Each anomaly should have index, time, value, and z_score
        if anomalies:
            anomaly = anomalies[0]
            self.assertIn('index', anomaly, "Anomaly should have an index")
            self.assertIn('time', anomaly, "Anomaly should have a time")
            self.assertIn('value', anomaly, "Anomaly should have a value")
            self.assertIn('z_score', anomaly, "Anomaly should have a z_score")


class TestHeatMapGenerator(unittest.TestCase):
    """Test the HeatMapGenerator class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create sample data for the heatmap
        self.data = [
            {
                'source_ip': '192.168.1.1',
                'destination_ip': '8.8.8.8',
                'source_port': 12345,
                'destination_port': 53,
                'protocol': 'UDP',
                'connections': 10,
                'bytes': 1000,
                'packets': 100
            },
            {
                'source_ip': '192.168.1.1',
                'destination_ip': '93.184.216.34',
                'source_port': 54321,
                'destination_port': 443,
                'protocol': 'TCP',
                'connections': 5,
                'bytes': 2000,
                'packets': 20
            },
            {
                'source_ip': '192.168.1.2',
                'destination_ip': '8.8.8.8',
                'source_port': 23456,
                'destination_port': 53,
                'protocol': 'UDP',
                'connections': 8,
                'bytes': 800,
                'packets': 80
            },
            {
                'source_ip': '192.168.1.2',
                'destination_ip': '93.184.216.34',
                'source_port': 65432,
                'destination_port': 80,
                'protocol': 'TCP',
                'connections': 3,
                'bytes': 300,
                'packets': 30
            },
            {
                'source_ip': '192.168.1.3',
                'destination_ip': '8.8.8.8',
                'source_port': 34567,
                'destination_port': 53,
                'protocol': 'UDP',
                'connections': 2,
                'bytes': 200,
                'packets': 20
            },
            {
                'source_ip': '192.168.1.3',
                'destination_ip': '93.184.216.34',
                'source_port': 76543,
                'destination_port': 22,
                'protocol': 'TCP',
                'connections': 5,
                'bytes': 500,
                'packets': 50
            }
        ]
        
        # Create a HeatMapGenerator instance
        self.heatmap_generator = HeatMapGenerator(self.data)
    
    def test_generate_heatmap(self):
        """Test generating a heatmap."""
        # Generate the heatmap for connections by source_ip and destination_port
        heatmap = self.heatmap_generator.generate_heatmap(
            metric='connections',
            groupby_x='source_ip',
            groupby_y='destination_port'
        )
        
        # Check that the heatmap has the correct structure
        self.assertIn('x_labels', heatmap, "Heatmap should have x_labels")
        self.assertIn('y_labels', heatmap, "Heatmap should have y_labels")
        self.assertIn('data', heatmap, "Heatmap should have data")
        self.assertIn('title', heatmap, "Heatmap should have a title")
        
        # Check that the heatmap has the correct dimensions
        self.assertEqual(len(heatmap['x_labels']), 3, "Heatmap should have 3 x_labels")
        self.assertEqual(len(heatmap['y_labels']), 4, "Heatmap should have 4 y_labels")
        self.assertEqual(len(heatmap['data']), 4, "Heatmap should have 4 rows of data")
        self.assertEqual(len(heatmap['data'][0]), 3, "Each row should have 3 columns of data")
    
    def test_add_data(self):
        """Test adding data to the heatmap generator."""
        # Create a new heatmap generator with no initial data
        heatmap_generator = HeatMapGenerator()
        
        # Add a single data point
        heatmap_generator.add_data(self.data[0])
        
        # Generate the heatmap and check that it has the correct data
        heatmap = heatmap_generator.generate_heatmap()
        self.assertEqual(len(heatmap['x_labels']), 1, "Heatmap should have 1 x_label")
        
        # Add multiple data points
        heatmap_generator.add_data(self.data[1:])
        
        # Generate the heatmap and check that it has the correct data
        heatmap = heatmap_generator.generate_heatmap()
        self.assertEqual(len(heatmap['x_labels']), 3, "Heatmap should have 3 x_labels")
    
    def test_clear_data(self):
        """Test clearing the data."""
        # Generate a heatmap first
        self.heatmap_generator.generate_heatmap()
        
        # Clear the data
        self.heatmap_generator.clear_data()
        
        # Check that the data and heatmap are cleared
        self.assertEqual(len(self.heatmap_generator.data), 0, "Data should be empty")
        self.assertIsNone(self.heatmap_generator.heatmap, "Heatmap should be None")
    
    def test_export_heatmap(self):
        """Test exporting the heatmap in different formats."""
        # Generate the heatmap
        self.heatmap_generator.generate_heatmap()
        
        # Export as JSON
        json_data = self.heatmap_generator.export_heatmap(format='json')
        self.assertIsInstance(json_data, str, "JSON data should be a string")
        
        # Parse the JSON and check that it has the correct structure
        heatmap = json.loads(json_data)
        self.assertIn('x_labels', heatmap, "Heatmap should have x_labels")
        self.assertIn('y_labels', heatmap, "Heatmap should have y_labels")
        self.assertIn('data', heatmap, "Heatmap should have data")
        
        # Export as PNG
        png_data = self.heatmap_generator.export_heatmap(format='png')
        self.assertIsInstance(png_data, bytes, "PNG data should be bytes")
        
        # Export as SVG
        svg_data = self.heatmap_generator.export_heatmap(format='svg')
        self.assertIsInstance(svg_data, str, "SVG data should be a string")
        self.assertIn('<svg>', svg_data, "SVG data should contain <svg> tag")
        
        # Export to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.heatmap_generator.export_heatmap(format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            heatmap = json.loads(file_content)
            self.assertIn('x_labels', heatmap, "Heatmap should have x_labels")
            self.assertIn('y_labels', heatmap, "Heatmap should have y_labels")
            self.assertIn('data', heatmap, "Heatmap should have data")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_highlight_cell(self):
        """Test highlighting a cell in the heatmap."""
        # Generate the heatmap
        self.heatmap_generator.generate_heatmap()
        
        # Highlight a cell
        highlighted_heatmap = self.heatmap_generator.highlight_cell(1, 2, color='red')
        
        # Check that the cell is highlighted
        self.assertIn('highlighted_cells', highlighted_heatmap, "Heatmap should have highlighted_cells")
        self.assertEqual(len(highlighted_heatmap['highlighted_cells']), 1, "Heatmap should have 1 highlighted cell")
        self.assertEqual(highlighted_heatmap['highlighted_cells'][0]['x'], 1, "Highlighted cell should have x=1")
        self.assertEqual(highlighted_heatmap['highlighted_cells'][0]['y'], 2, "Highlighted cell should have y=2")
        self.assertEqual(highlighted_heatmap['highlighted_cells'][0]['color'], 'red', "Highlighted cell should have color=red")


class TestGeoIPMapper(unittest.TestCase):
    """Test the GeoIPMapper class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create sample IP data
        self.ip_data = [
            {
                'ip': '8.8.8.8',
                'country': 'United States',
                'city': 'Mountain View',
                'lat': 37.751,
                'lon': -97.822,
                'count': 15
            },
            {
                'ip': '93.184.216.34',
                'country': 'United Kingdom',
                'city': 'London',
                'lat': 51.507,
                'lon': -0.127,
                'count': 8
            },
            {
                'ip': '192.168.1.1',
                'country': 'Internal',
                'city': 'Internal',
                'lat': 0,
                'lon': 0,
                'count': 10
            }
        ]
        
        # Create connection data
        self.connection_data = [
            {
                'source': {'ip': '192.168.1.1', 'lat': 0, 'lon': 0, 'country': 'Internal'},
                'destination': {'ip': '8.8.8.8', 'lat': 37.751, 'lon': -97.822, 'country': 'United States'},
                'count': 10
            },
            {
                'source': {'ip': '192.168.1.1', 'lat': 0, 'lon': 0, 'country': 'Internal'},
                'destination': {'ip': '93.184.216.34', 'lat': 51.507, 'lon': -0.127, 'country': 'United Kingdom'},
                'count': 5
            }
        ]
        
        # Create a GeoIPMapper instance
        self.mapper = GeoIPMapper(self.ip_data)
    
    def test_generate_map(self):
        """Test generating a geo IP map."""
        # Generate the map
        map_data = self.mapper.generate_map()
        
        # Check that the map has the correct structure
        self.assertIn('points', map_data, "Map should have points")
        self.assertIn('connections', map_data, "Map should have connections")
        
        # Check that the map has the correct number of points and connections
        self.assertEqual(len(map_data['points']), 2, "Map should have 2 points (excluding internal)")
        self.assertEqual(len(map_data['connections']), 2, "Map should have 2 connections")
        
        # Generate the map with internal IPs included
        map_data = self.mapper.generate_map(include_internal=True)
        
        # Check that the map has the correct number of points
        self.assertEqual(len(map_data['points']), 3, "Map should have 3 points (including internal)")
    
    def test_add_ip_data(self):
        """Test adding IP data to the mapper."""
        # Create a new mapper with no initial data
        mapper = GeoIPMapper()
        
        # Add a single IP
        mapper.add_ip_data(self.ip_data[0])
        
        # Generate the map and check that it has the correct data
        map_data = mapper.generate_map()
        self.assertEqual(len(map_data['points']), 1, "Map should have 1 point")
        
        # Add multiple IPs
        mapper.add_ip_data(self.ip_data[1:])
        
        # Generate the map and check that it has the correct data
        map_data = mapper.generate_map()
        self.assertEqual(len(map_data['points']), 2, "Map should have 2 points (excluding internal)")
    
    def test_clear_data(self):
        """Test clearing the IP data."""
        # Generate a map first
        self.mapper.generate_map()
        
        # Clear the data
        self.mapper.clear_data()
        
        # Check that the IP data and map are cleared
        self.assertEqual(len(self.mapper.ip_data), 0, "IP data should be empty")
        self.assertIsNone(self.mapper.map, "Map should be None")
    
    def test_export_map(self):
        """Test exporting the map in different formats."""
        # Generate the map
        self.mapper.generate_map()
        
        # Export as JSON
        json_data = self.mapper.export_map(format='json')
        self.assertIsInstance(json_data, str, "JSON data should be a string")
        
        # Parse the JSON and check that it has the correct structure
        map_data = json.loads(json_data)
        self.assertIn('points', map_data, "Map should have points")
        self.assertIn('connections', map_data, "Map should have connections")
        
        # Export as HTML
        html_data = self.mapper.export_map(format='html')
        self.assertIsInstance(html_data, str, "HTML data should be a string")
        self.assertIn('<html>', html_data, "HTML data should contain <html> tag")
        
        # Export as KML
        kml_data = self.mapper.export_map(format='kml')
        self.assertIsInstance(kml_data, str, "KML data should be a string")
        self.assertIn('<kml>', kml_data, "KML data should contain <kml> tag")
        
        # Export to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.mapper.export_map(format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            map_data = json.loads(file_content)
            self.assertIn('points', map_data, "Map should have points")
            self.assertIn('connections', map_data, "Map should have connections")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_filter_by_country(self):
        """Test filtering the map by country."""
        # Generate the map
        self.mapper.generate_map()
        
        # Filter by United States
        filtered_map = self.mapper.filter_by_country('United States')
        
        # Check that the filtered map only contains United States points and connections
        self.assertEqual(len(filtered_map['points']), 1, "Filtered map should have 1 point")
        self.assertEqual(filtered_map['points'][0]['country'], 'United States', "Point should be in United States")
        
        self.assertEqual(len(filtered_map['connections']), 1, "Filtered map should have 1 connection")
        self.assertEqual(filtered_map['connections'][0]['destination']['country'], 'United States', "Connection destination should be in United States")
    
    def test_get_country_stats(self):
        """Test getting country statistics from the map."""
        # Generate the map
        self.mapper.generate_map()
        
        # Get country statistics
        country_stats = self.mapper.get_country_stats()
        
        # Check that the country statistics have the correct structure
        self.assertIn('United States', country_stats, "Country stats should include United States")
        self.assertIn('United Kingdom', country_stats, "Country stats should include United Kingdom")
        
        # Check that the country statistics have the correct values
        self.assertEqual(country_stats['United States'], 15, "United States should have 15 connections")
        self.assertEqual(country_stats['United Kingdom'], 8, "United Kingdom should have 8 connections")


class TestReportGenerator(unittest.TestCase):
    """Test the ReportGenerator class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create sample data for the report
        self.data = {
            'network_graph': {
                'nodes': [
                    {'id': '192.168.1.1', 'label': '192.168.1.1', 'size': 10, 'type': 'source'},
                    {'id': '8.8.8.8', 'label': '8.8.8.8', 'size': 5, 'type': 'destination'}
                ],
                'edges': [
                    {'source': '192.168.1.1', 'target': '8.8.8.8', 'value': 100, 'label': 'TCP:443'}
                ]
            },
            'alert_dashboard': {
                'summary': {
                    'total_alerts': 10,
                    'by_severity': {'high': 2, 'medium': 3, 'low': 5},
                    'by_category': {'malware': 3, 'intrusion': 2, 'anomaly': 5},
                    'by_status': {'open': 7, 'closed': 3}
                }
            },
            'time_series': {
                'packets': {
                    'data': [100, 200, 150, 300, 250],
                    'labels': ['00:00', '01:00', '02:00', '03:00', '04:00']
                }
            },
            'geo_map': {
                'points': [
                    {'ip': '8.8.8.8', 'lat': 37.751, 'lon': -97.822, 'country': 'United States', 'count': 15},
                    {'ip': '93.184.216.34', 'lat': 51.507, 'lon': -0.127, 'country': 'United Kingdom', 'count': 8}
                ]
            }
        }
        
        # Create a ReportGenerator instance
        self.report_generator = ReportGenerator(self.data)
    
    def test_generate_report(self):
        """Test generating a report."""
        # Generate a summary report for the day
        report = self.report_generator.generate_report(report_type='summary', time_period='day')
        
        # Check that the report has the correct structure
        self.assertIn('title', report, "Report should have a title")
        self.assertIn('timestamp', report, "Report should have a timestamp")
        self.assertIn('sections', report, "Report should have sections")
        
        # Check that the report has the correct title
        self.assertEqual(report['title'], "Summary Report - Day", "Report should have the correct title")
        
        # Check that the report has the correct number of sections
        self.assertEqual(len(report['sections']), 3, "Report should have 3 sections")
        
        # Generate a detailed report for the week
        report = self.report_generator.generate_report(report_type='detailed', time_period='week')
        
        # Check that the report has the correct title
        self.assertEqual(report['title'], "Detailed Report - Week", "Report should have the correct title")
    
    def test_set_data(self):
        """Test setting the data for the report generator."""
        # Create a new report generator with no initial data
        report_generator = ReportGenerator()
        
        # Set the data
        report_generator.set_data(self.data)
        
        # Generate a report and check that it has the correct data
        report = report_generator.generate_report()
        self.assertEqual(len(report['sections']), 3, "Report should have 3 sections")
    
    def test_clear_data(self):
        """Test clearing the data."""
        # Generate a report first
        self.report_generator.generate_report()
        
        # Clear the data
        self.report_generator.clear_data()
        
        # Check that the data and report are cleared
        self.assertEqual(len(self.report_generator.data), 0, "Data should be empty")
        self.assertIsNone(self.report_generator.report, "Report should be None")
    
    def test_export_report(self):
        """Test exporting the report in different formats."""
        # Generate the report
        self.report_generator.generate_report()
        
        # Export as JSON
        json_data = self.report_generator.export_report(format='json')
        self.assertIsInstance(json_data, str, "JSON data should be a string")
        
        # Parse the JSON and check that it has the correct structure
        report = json.loads(json_data)
        self.assertIn('title', report, "Report should have a title")
        self.assertIn('timestamp', report, "Report should have a timestamp")
        self.assertIn('sections', report, "Report should have sections")
        
        # Export as HTML
        html_data = self.report_generator.export_report(format='html')
        self.assertIsInstance(html_data, str, "HTML data should be a string")
        self.assertIn('<html>', html_data, "HTML data should contain <html> tag")
        
        # Export as PDF
        pdf_data = self.report_generator.export_report(format='pdf')
        self.assertIsInstance(pdf_data, bytes, "PDF data should be bytes")
        
        # Export as Markdown
        markdown_data = self.report_generator.export_report(format='markdown')
        self.assertIsInstance(markdown_data, str, "Markdown data should be a string")
        self.assertIn('# Mock Report', markdown_data, "Markdown data should contain # Mock Report")
        
        # Export to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.report_generator.export_report(format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            report = json.loads(file_content)
            self.assertIn('title', report, "Report should have a title")
            self.assertIn('timestamp', report, "Report should have a timestamp")
            self.assertIn('sections', report, "Report should have sections")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_add_section(self):
        """Test adding a section to the report."""
        # Generate the report
        self.report_generator.generate_report()
        
        # Add a section
        updated_report = self.report_generator.add_section(
            title="Test Section",
            content="This is a test section",
            charts=["test_chart"]
        )
        
        # Check that the section was added
        self.assertEqual(len(updated_report['sections']), 4, "Report should have 4 sections")
        
        # Check that the section has the correct content
        section = updated_report['sections'][-1]
        self.assertEqual(section['title'], "Test Section", "Section should have the correct title")
        self.assertEqual(section['content'], "This is a test section", "Section should have the correct content")
        self.assertEqual(section['charts'], ["test_chart"], "Section should have the correct charts")
    
    def test_get_section(self):
        """Test getting a section from the report."""
        # Generate the report
        self.report_generator.generate_report()
        
        # Get a section
        section = self.report_generator.get_section("Network Activity Summary")
        
        # Check that the section was found
        self.assertIsNotNone(section, "Section should be found")
        self.assertEqual(section['title'], "Network Activity Summary", "Section should have the correct title")
        
        # Get a non-existent section
        section = self.report_generator.get_section("Non-existent Section")
        
        # Check that the section was not found
        self.assertIsNone(section, "Section should not be found")


if __name__ == '__main__':
    unittest.main()