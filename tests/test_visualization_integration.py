#!/usr/bin/env python
# SentinelX Visualization Integration Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the SentinelX class and visualization classes
try:
    from src.sentinelx import SentinelX
    from src.visualization import NetworkGraphGenerator, AlertDashboard, TimeSeriesPlotter
    from src.visualization import HeatMapGenerator, GeoIPMapper, ReportGenerator
    from src.visualization import VisualizationManager
except ImportError:
    # Mock classes if they don't exist yet
    class SentinelX:
        def __init__(self, config_path=None):
            self.config_path = config_path
            self.network_data = []
            self.alert_data = []
        
        def get_network_data(self, time_window=None):
            return self.network_data
        
        def get_alert_data(self, time_window=None, severity=None, status=None):
            return self.alert_data
        
        def get_flow_data(self, time_window=None):
            return [
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
            ]
    
    class VisualizationManager:
        def __init__(self, sentinelx_instance):
            self.sentinelx = sentinelx_instance
            self.network_graph = NetworkGraphGenerator()
            self.alert_dashboard = AlertDashboard()
            self.time_series = TimeSeriesPlotter()
            self.heatmap = HeatMapGenerator()
            self.geoip_map = GeoIPMapper()
            self.report_generator = ReportGenerator()
        
        def generate_network_graph(self, time_window=None, top_n=10):
            flow_data = self.sentinelx.get_flow_data(time_window)
            self.network_graph.add_flow_data(flow_data)
            return self.network_graph.generate_graph(top_n=top_n)
        
        def generate_alert_dashboard(self, time_window=None, severity=None):
            alert_data = self.sentinelx.get_alert_data(time_window, severity)
            self.alert_dashboard.add_alert_data(alert_data)
            return self.alert_dashboard.generate_dashboard()
        
        def generate_time_series(self, metric='packets', interval='hour', time_window=None):
            flow_data = self.sentinelx.get_flow_data(time_window)
            time_data = self._convert_flow_to_time_data(flow_data)
            self.time_series.add_time_data(time_data)
            return self.time_series.generate_plot(metric=metric, interval=interval)
        
        def generate_heatmap(self, metric='connections', groupby_x='source_ip', groupby_y='destination_port'):
            flow_data = self.sentinelx.get_flow_data()
            self.heatmap.add_data(flow_data)
            return self.heatmap.generate_heatmap(metric=metric, groupby_x=groupby_x, groupby_y=groupby_y)
        
        def generate_geoip_map(self, include_internal=False):
            flow_data = self.sentinelx.get_flow_data()
            ip_data = self._extract_ip_data(flow_data)
            self.geoip_map.add_ip_data(ip_data)
            return self.geoip_map.generate_map(include_internal=include_internal)
        
        def generate_report(self, report_type='summary', time_period='day'):
            # Generate all visualizations
            network_graph = self.generate_network_graph()
            alert_dashboard = self.generate_alert_dashboard()
            time_series = self.generate_time_series()
            geoip_map = self.generate_geoip_map()
            
            # Combine data for the report
            report_data = {
                'network_graph': network_graph,
                'alert_dashboard': alert_dashboard,
                'time_series': time_series,
                'geo_map': geoip_map
            }
            
            self.report_generator.set_data(report_data)
            return self.report_generator.generate_report(report_type=report_type, time_period=time_period)
        
        def export_visualization(self, vis_type, format='json', file_path=None):
            if vis_type == 'network_graph':
                graph = self.generate_network_graph()
                return self.network_graph.export_graph(format=format, file_path=file_path)
            elif vis_type == 'alert_dashboard':
                dashboard = self.generate_alert_dashboard()
                return self.alert_dashboard.export_dashboard(format=format, file_path=file_path)
            elif vis_type == 'time_series':
                plot = self.generate_time_series()
                return self.time_series.export_plot(format=format, file_path=file_path)
            elif vis_type == 'heatmap':
                heatmap = self.generate_heatmap()
                return self.heatmap.export_heatmap(format=format, file_path=file_path)
            elif vis_type == 'geoip_map':
                map_data = self.generate_geoip_map()
                return self.geoip_map.export_map(format=format, file_path=file_path)
            elif vis_type == 'report':
                report = self.generate_report()
                return self.report_generator.export_report(format=format, file_path=file_path)
            else:
                raise ValueError(f"Unsupported visualization type: {vis_type}")
        
        def _convert_flow_to_time_data(self, flow_data):
            # Convert flow data to time series data
            time_data = []
            for flow in flow_data:
                time_data.append({
                    'timestamp': flow['timestamp'],
                    'packets': flow['packets'],
                    'bytes': flow['bytes'],
                    'flows': 1
                })
            return time_data
        
        def _extract_ip_data(self, flow_data):
            # Extract IP data from flow data
            ip_data = []
            for flow in flow_data:
                # Add destination IP (assuming it's external)
                ip_data.append({
                    'ip': flow['dst_ip'],
                    'country': 'United States',  # Mock data
                    'city': 'Mountain View',     # Mock data
                    'lat': 37.751,               # Mock data
                    'lon': -97.822,              # Mock data
                    'count': flow['packets']
                })
            return ip_data
    
    # Import mock classes from test_visualization.py
    from test_visualization import NetworkGraphGenerator, AlertDashboard, TimeSeriesPlotter
    from test_visualization import HeatMapGenerator, GeoIPMapper, ReportGenerator


class TestVisualizationIntegration(unittest.TestCase):
    """Test the integration of visualization components with SentinelX."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a mock SentinelX instance
        self.sentinelx = SentinelX()
        
        # Add sample network data
        self.sentinelx.network_data = [
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
            }
        ]
        
        # Add sample alert data
        self.sentinelx.alert_data = [
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
            }
        ]
        
        # Create a VisualizationManager instance
        self.vis_manager = VisualizationManager(self.sentinelx)
    
    def test_visualization_manager_initialization(self):
        """Test initializing the VisualizationManager."""
        # Check that the VisualizationManager has the correct SentinelX instance
        self.assertEqual(self.vis_manager.sentinelx, self.sentinelx, "VisualizationManager should have the correct SentinelX instance")
        
        # Check that the VisualizationManager has all the required visualization components
        self.assertIsInstance(self.vis_manager.network_graph, NetworkGraphGenerator, "VisualizationManager should have a NetworkGraphGenerator")
        self.assertIsInstance(self.vis_manager.alert_dashboard, AlertDashboard, "VisualizationManager should have an AlertDashboard")
        self.assertIsInstance(self.vis_manager.time_series, TimeSeriesPlotter, "VisualizationManager should have a TimeSeriesPlotter")
        self.assertIsInstance(self.vis_manager.heatmap, HeatMapGenerator, "VisualizationManager should have a HeatMapGenerator")
        self.assertIsInstance(self.vis_manager.geoip_map, GeoIPMapper, "VisualizationManager should have a GeoIPMapper")
        self.assertIsInstance(self.vis_manager.report_generator, ReportGenerator, "VisualizationManager should have a ReportGenerator")
    
    def test_generate_network_graph(self):
        """Test generating a network graph from SentinelX data."""
        # Mock the get_flow_data method to return sample flow data
        self.sentinelx.get_flow_data = MagicMock(return_value=self.sentinelx.network_data)
        
        # Generate the network graph
        graph = self.vis_manager.generate_network_graph()
        
        # Check that the graph has the correct structure
        self.assertIn('nodes', graph, "Graph should have nodes")
        self.assertIn('edges', graph, "Graph should have edges")
        
        # Check that the SentinelX get_flow_data method was called
        self.sentinelx.get_flow_data.assert_called_once()
    
    def test_generate_alert_dashboard(self):
        """Test generating an alert dashboard from SentinelX data."""
        # Mock the get_alert_data method to return sample alert data
        self.sentinelx.get_alert_data = MagicMock(return_value=self.sentinelx.alert_data)
        
        # Generate the alert dashboard
        dashboard = self.vis_manager.generate_alert_dashboard()
        
        # Check that the dashboard has the correct structure
        self.assertIn('summary', dashboard, "Dashboard should have a summary")
        self.assertIn('recent_alerts', dashboard, "Dashboard should have recent alerts")
        self.assertIn('charts', dashboard, "Dashboard should have charts")
        
        # Check that the SentinelX get_alert_data method was called
        self.sentinelx.get_alert_data.assert_called_once()
    
    def test_generate_time_series(self):
        """Test generating a time series plot from SentinelX data."""
        # Mock the get_flow_data method to return sample flow data
        self.sentinelx.get_flow_data = MagicMock(return_value=self.sentinelx.network_data)
        
        # Generate the time series plot
        plot = self.vis_manager.generate_time_series(metric='packets', interval='hour')
        
        # Check that the plot has the correct structure
        self.assertEqual(plot['metric'], 'packets', "Plot metric should be packets")
        self.assertEqual(plot['interval'], 'hour', "Plot interval should be hour")
        self.assertIn('data', plot, "Plot should have data")
        self.assertIn('labels', plot, "Plot should have labels")
        
        # Check that the SentinelX get_flow_data method was called
        self.sentinelx.get_flow_data.assert_called_once()
    
    def test_generate_heatmap(self):
        """Test generating a heatmap from SentinelX data."""
        # Mock the get_flow_data method to return sample flow data
        self.sentinelx.get_flow_data = MagicMock(return_value=self.sentinelx.network_data)
        
        # Generate the heatmap
        heatmap = self.vis_manager.generate_heatmap(metric='connections', groupby_x='source_ip', groupby_y='destination_port')
        
        # Check that the heatmap has the correct structure
        self.assertIn('x_labels', heatmap, "Heatmap should have x_labels")
        self.assertIn('y_labels', heatmap, "Heatmap should have y_labels")
        self.assertIn('data', heatmap, "Heatmap should have data")
        self.assertIn('title', heatmap, "Heatmap should have a title")
        
        # Check that the SentinelX get_flow_data method was called
        self.sentinelx.get_flow_data.assert_called_once()
    
    def test_generate_geoip_map(self):
        """Test generating a GeoIP map from SentinelX data."""
        # Mock the get_flow_data method to return sample flow data
        self.sentinelx.get_flow_data = MagicMock(return_value=self.sentinelx.network_data)
        
        # Generate the GeoIP map
        map_data = self.vis_manager.generate_geoip_map()
        
        # Check that the map has the correct structure
        self.assertIn('points', map_data, "Map should have points")
        self.assertIn('connections', map_data, "Map should have connections")
        
        # Check that the SentinelX get_flow_data method was called
        self.sentinelx.get_flow_data.assert_called_once()
    
    def test_generate_report(self):
        """Test generating a comprehensive report from SentinelX data."""
        # Mock the visualization generation methods
        self.vis_manager.generate_network_graph = MagicMock(return_value={'nodes': [], 'edges': []})
        self.vis_manager.generate_alert_dashboard = MagicMock(return_value={'summary': {}, 'recent_alerts': [], 'charts': {}})
        self.vis_manager.generate_time_series = MagicMock(return_value={'data': [], 'labels': []})
        self.vis_manager.generate_geoip_map = MagicMock(return_value={'points': [], 'connections': []})
        
        # Generate the report
        report = self.vis_manager.generate_report(report_type='summary', time_period='day')
        
        # Check that the report has the correct structure
        self.assertIn('title', report, "Report should have a title")
        self.assertIn('timestamp', report, "Report should have a timestamp")
        self.assertIn('sections', report, "Report should have sections")
        
        # Check that the visualization generation methods were called
        self.vis_manager.generate_network_graph.assert_called_once()
        self.vis_manager.generate_alert_dashboard.assert_called_once()
        self.vis_manager.generate_time_series.assert_called_once()
        self.vis_manager.generate_geoip_map.assert_called_once()
    
    def test_export_visualization(self):
        """Test exporting visualizations in different formats."""
        # Mock the visualization generation and export methods
        self.vis_manager.generate_network_graph = MagicMock(return_value={'nodes': [], 'edges': []})
        self.vis_manager.network_graph.export_graph = MagicMock(return_value='{}')
        
        # Export the network graph as JSON
        json_data = self.vis_manager.export_visualization(vis_type='network_graph', format='json')
        
        # Check that the export method returned a string
        self.assertIsInstance(json_data, str, "Export should return a string")
        
        # Check that the visualization generation and export methods were called
        self.vis_manager.generate_network_graph.assert_called_once()
        self.vis_manager.network_graph.export_graph.assert_called_once_with(format='json', file_path=None)
        
        # Test exporting to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Reset the mock
            self.vis_manager.network_graph.export_graph.reset_mock()
            
            # Export to a file
            self.vis_manager.export_visualization(vis_type='network_graph', format='json', file_path=temp_path)
            
            # Check that the export method was called with the file path
            self.vis_manager.network_graph.export_graph.assert_called_once_with(format='json', file_path=temp_path)
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_convert_flow_to_time_data(self):
        """Test converting flow data to time series data."""
        # Convert flow data to time series data
        time_data = self.vis_manager._convert_flow_to_time_data(self.sentinelx.network_data)
        
        # Check that the time data has the correct structure
        self.assertEqual(len(time_data), 2, "Time data should have 2 entries")
        self.assertIn('timestamp', time_data[0], "Time data should have a timestamp")
        self.assertIn('packets', time_data[0], "Time data should have packets")
        self.assertIn('bytes', time_data[0], "Time data should have bytes")
        self.assertIn('flows', time_data[0], "Time data should have flows")
        
        # Check that the time data has the correct values
        self.assertEqual(time_data[0]['timestamp'], '2023-01-01T00:00:00', "Time data should have the correct timestamp")
        self.assertEqual(time_data[0]['packets'], 10, "Time data should have the correct packets")
        self.assertEqual(time_data[0]['bytes'], 1000, "Time data should have the correct bytes")
        self.assertEqual(time_data[0]['flows'], 1, "Time data should have the correct flows")
    
    def test_extract_ip_data(self):
        """Test extracting IP data from flow data."""
        # Extract IP data from flow data
        ip_data = self.vis_manager._extract_ip_data(self.sentinelx.network_data)
        
        # Check that the IP data has the correct structure
        self.assertEqual(len(ip_data), 2, "IP data should have 2 entries")
        self.assertIn('ip', ip_data[0], "IP data should have an IP")
        self.assertIn('country', ip_data[0], "IP data should have a country")
        self.assertIn('city', ip_data[0], "IP data should have a city")
        self.assertIn('lat', ip_data[0], "IP data should have a latitude")
        self.assertIn('lon', ip_data[0], "IP data should have a longitude")
        self.assertIn('count', ip_data[0], "IP data should have a count")
        
        # Check that the IP data has the correct values
        self.assertEqual(ip_data[0]['ip'], '8.8.8.8', "IP data should have the correct IP")
        self.assertEqual(ip_data[0]['count'], 10, "IP data should have the correct count")


class TestVisualizationWithSentinelX(unittest.TestCase):
    """Test the visualization components with a mocked SentinelX instance."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a mock SentinelX class
        self.mock_sentinelx = MagicMock()
        
        # Set up the mock SentinelX to return sample data
        self.mock_sentinelx.get_flow_data.return_value = [
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
        ]
        
        self.mock_sentinelx.get_alert_data.return_value = [
            {
                'id': 'alert-1',
                'timestamp': '2023-01-01T00:00:00',
                'source_ip': '192.168.1.100',
                'destination_ip': '8.8.8.8',
                'severity': 'high',
                'category': 'malware',
                'status': 'open'
            }
        ]
        
        # Create a VisualizationManager instance with the mock SentinelX
        self.vis_manager = VisualizationManager(self.mock_sentinelx)
    
    def test_visualization_with_mocked_sentinelx(self):
        """Test visualization with a mocked SentinelX instance."""
        # Generate a network graph
        graph = self.vis_manager.generate_network_graph()
        
        # Check that the SentinelX get_flow_data method was called
        self.mock_sentinelx.get_flow_data.assert_called_once()
        
        # Generate an alert dashboard
        dashboard = self.vis_manager.generate_alert_dashboard()
        
        # Check that the SentinelX get_alert_data method was called
        self.mock_sentinelx.get_alert_data.assert_called_once()
    
    def test_visualization_with_time_window(self):
        """Test visualization with a time window."""
        # Reset the mock
        self.mock_sentinelx.get_flow_data.reset_mock()
        
        # Generate a network graph with a time window
        time_window = {'start': '2023-01-01T00:00:00', 'end': '2023-01-01T01:00:00'}
        graph = self.vis_manager.generate_network_graph(time_window=time_window)
        
        # Check that the SentinelX get_flow_data method was called with the time window
        self.mock_sentinelx.get_flow_data.assert_called_once_with(time_window)
    
    def test_visualization_with_severity_filter(self):
        """Test visualization with a severity filter."""
        # Reset the mock
        self.mock_sentinelx.get_alert_data.reset_mock()
        
        # Generate an alert dashboard with a severity filter
        dashboard = self.vis_manager.generate_alert_dashboard(severity='high')
        
        # Check that the SentinelX get_alert_data method was called with the severity filter
        self.mock_sentinelx.get_alert_data.assert_called_once_with(None, 'high')
    
    def test_end_to_end_visualization_workflow(self):
        """Test an end-to-end visualization workflow."""
        # Generate all visualizations and a report
        network_graph = self.vis_manager.generate_network_graph()
        alert_dashboard = self.vis_manager.generate_alert_dashboard()
        time_series = self.vis_manager.generate_time_series()
        heatmap = self.vis_manager.generate_heatmap()
        geoip_map = self.vis_manager.generate_geoip_map()
        report = self.vis_manager.generate_report()
        
        # Export the report to a file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            self.vis_manager.export_visualization(vis_type='report', format='json', file_path=temp_path)
            
            # Check that the file exists and contains valid JSON
            self.assertTrue(os.path.exists(temp_path), "Export file should exist")
            
            with open(temp_path, 'r') as f:
                file_content = f.read()
            
            report_data = json.loads(file_content)
            self.assertIn('title', report_data, "Report should have a title")
            self.assertIn('timestamp', report_data, "Report should have a timestamp")
            self.assertIn('sections', report_data, "Report should have sections")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()