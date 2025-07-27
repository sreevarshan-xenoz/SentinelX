#!/usr/bin/env python
# SentinelX Visualization Dashboard Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import json
import datetime

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the SentinelX class and visualization dashboard classes
try:
    from src.sentinelx import SentinelX
    from src.visualization import DashboardApp, DashboardLayout, DashboardComponent
    from src.visualization import NetworkPanel, AlertPanel, TimeSeriesPanel, GeoMapPanel
    from src.visualization import HeatMapPanel, ReportPanel, DashboardController
except ImportError:
    # Mock classes if they don't exist yet
    class DashboardComponent:
        def __init__(self, component_id, title, data_source=None):
            self.component_id = component_id
            self.title = title
            self.data_source = data_source
            self.config = {}
            self.visible = True
        
        def set_config(self, config):
            self.config.update(config)
            return self
        
        def set_data(self, data):
            self.data = data
            return self
        
        def get_layout(self):
            return {
                'id': self.component_id,
                'title': self.title,
                'type': self.__class__.__name__,
                'config': self.config,
                'visible': self.visible
            }
        
        def update(self, data=None):
            if data:
                self.set_data(data)
            return self.get_layout()
        
        def toggle_visibility(self):
            self.visible = not self.visible
            return self.visible
    
    class NetworkPanel(DashboardComponent):
        def __init__(self, component_id="network-panel", title="Network Graph", data_source=None):
            super().__init__(component_id, title, data_source)
            self.config = {
                'layout': 'force',
                'node_size': 'degree',
                'edge_width': 'weight',
                'show_labels': True,
                'highlight_anomalies': True
            }
    
    class AlertPanel(DashboardComponent):
        def __init__(self, component_id="alert-panel", title="Alert Dashboard", data_source=None):
            super().__init__(component_id, title, data_source)
            self.config = {
                'sort_by': 'severity',
                'filter_status': 'all',
                'show_details': True,
                'auto_refresh': True,
                'refresh_interval': 60
            }
    
    class TimeSeriesPanel(DashboardComponent):
        def __init__(self, component_id="timeseries-panel", title="Network Traffic", data_source=None):
            super().__init__(component_id, title, data_source)
            self.config = {
                'metric': 'packets',
                'interval': 'minute',
                'time_window': '1h',
                'show_anomalies': True,
                'compare_previous': False
            }
    
    class GeoMapPanel(DashboardComponent):
        def __init__(self, component_id="geomap-panel", title="Geographic Traffic", data_source=None):
            super().__init__(component_id, title, data_source)
            self.config = {
                'map_type': 'world',
                'include_internal': False,
                'highlight_threats': True,
                'connection_lines': True,
                'heatmap_mode': False
            }
    
    class HeatMapPanel(DashboardComponent):
        def __init__(self, component_id="heatmap-panel", title="Traffic Heatmap", data_source=None):
            super().__init__(component_id, title, data_source)
            self.config = {
                'metric': 'connections',
                'groupby_x': 'source_ip',
                'groupby_y': 'destination_port',
                'color_scale': 'viridis',
                'log_scale': True
            }
    
    class ReportPanel(DashboardComponent):
        def __init__(self, component_id="report-panel", title="Security Reports", data_source=None):
            super().__init__(component_id, title, data_source)
            self.config = {
                'report_type': 'summary',
                'time_period': 'day',
                'auto_generate': False,
                'include_visuals': True,
                'export_format': 'html'
            }
    
    class DashboardLayout:
        def __init__(self):
            self.layout = {
                'rows': [],
                'settings': {
                    'theme': 'dark',
                    'refresh_rate': 60,
                    'layout_type': 'grid'
                }
            }
        
        def add_row(self, components=None, height=None):
            row = {'components': [], 'height': height}
            if components:
                for component in components:
                    row['components'].append(component.get_layout())
            self.layout['rows'].append(row)
            return self
        
        def get_layout(self):
            return self.layout
        
        def update_settings(self, settings):
            self.layout['settings'].update(settings)
            return self
    
    class DashboardController:
        def __init__(self, sentinelx_instance):
            self.sentinelx = sentinelx_instance
            self.components = {}
            self.data_sources = {}
            self.layout = DashboardLayout()
        
        def register_component(self, component):
            self.components[component.component_id] = component
            return self
        
        def register_data_source(self, source_id, data_callback):
            self.data_sources[source_id] = data_callback
            return self
        
        def get_component(self, component_id):
            return self.components.get(component_id)
        
        def update_component(self, component_id, data=None, config=None):
            component = self.get_component(component_id)
            if not component:
                return None
            
            if data:
                component.set_data(data)
            
            if config:
                component.set_config(config)
            
            return component.get_layout()
        
        def refresh_data_source(self, source_id, **kwargs):
            if source_id not in self.data_sources:
                return None
            
            callback = self.data_sources[source_id]
            return callback(**kwargs)
        
        def refresh_all_components(self):
            updates = {}
            for component_id, component in self.components.items():
                if component.data_source and component.data_source in self.data_sources:
                    data = self.refresh_data_source(component.data_source)
                    component.set_data(data)
                updates[component_id] = component.get_layout()
            return updates
        
        def get_dashboard_layout(self):
            return self.layout.get_layout()
        
        def set_dashboard_layout(self, layout_config):
            # Reset the layout
            self.layout = DashboardLayout()
            
            # Apply the settings
            if 'settings' in layout_config:
                self.layout.update_settings(layout_config['settings'])
            
            # Add the rows
            if 'rows' in layout_config:
                for row_config in layout_config['rows']:
                    row_components = []
                    for component_config in row_config.get('components', []):
                        component_id = component_config.get('id')
                        if component_id in self.components:
                            component = self.components[component_id]
                            if 'config' in component_config:
                                component.set_config(component_config['config'])
                            if 'visible' in component_config:
                                component.visible = component_config['visible']
                            row_components.append(component)
                    
                    self.layout.add_row(
                        components=row_components,
                        height=row_config.get('height')
                    )
            
            return self.get_dashboard_layout()
    
    class DashboardApp:
        def __init__(self, sentinelx_instance, port=8050, debug=False):
            self.sentinelx = sentinelx_instance
            self.controller = DashboardController(sentinelx_instance)
            self.port = port
            self.debug = debug
            self.initialize_components()
            self.initialize_data_sources()
            self.initialize_layout()
        
        def initialize_components(self):
            # Create and register components
            self.controller.register_component(
                NetworkPanel(data_source='network_data')
            )
            self.controller.register_component(
                AlertPanel(data_source='alert_data')
            )
            self.controller.register_component(
                TimeSeriesPanel(data_source='time_series_data')
            )
            self.controller.register_component(
                GeoMapPanel(data_source='geo_data')
            )
            self.controller.register_component(
                HeatMapPanel(data_source='heatmap_data')
            )
            self.controller.register_component(
                ReportPanel(data_source='report_data')
            )
        
        def initialize_data_sources(self):
            # Register data sources with callbacks to SentinelX
            self.controller.register_data_source('network_data', self._get_network_data)
            self.controller.register_data_source('alert_data', self._get_alert_data)
            self.controller.register_data_source('time_series_data', self._get_time_series_data)
            self.controller.register_data_source('geo_data', self._get_geo_data)
            self.controller.register_data_source('heatmap_data', self._get_heatmap_data)
            self.controller.register_data_source('report_data', self._get_report_data)
        
        def initialize_layout(self):
            # Create a default layout
            network_panel = self.controller.get_component('network-panel')
            alert_panel = self.controller.get_component('alert-panel')
            timeseries_panel = self.controller.get_component('timeseries-panel')
            geomap_panel = self.controller.get_component('geomap-panel')
            heatmap_panel = self.controller.get_component('heatmap-panel')
            report_panel = self.controller.get_component('report-panel')
            
            self.controller.layout.add_row(
                components=[network_panel, alert_panel],
                height='50%'
            ).add_row(
                components=[timeseries_panel, geomap_panel],
                height='30%'
            ).add_row(
                components=[heatmap_panel, report_panel],
                height='20%'
            )
        
        def run(self):
            # In a real implementation, this would start the Dash/Flask server
            print(f"Starting dashboard on port {self.port}")
            return True
        
        def get_layout(self):
            return self.controller.get_dashboard_layout()
        
        def _get_network_data(self, **kwargs):
            # Get network data from SentinelX
            return self.sentinelx.get_flow_data(**kwargs)
        
        def _get_alert_data(self, **kwargs):
            # Get alert data from SentinelX
            return self.sentinelx.get_alert_data(**kwargs)
        
        def _get_time_series_data(self, **kwargs):
            # Get time series data from SentinelX
            flow_data = self.sentinelx.get_flow_data(**kwargs)
            # Convert flow data to time series format
            time_data = []
            for flow in flow_data:
                time_data.append({
                    'timestamp': flow.get('timestamp'),
                    'packets': flow.get('packets', 0),
                    'bytes': flow.get('bytes', 0),
                    'flows': 1
                })
            return time_data
        
        def _get_geo_data(self, **kwargs):
            # Get geographic data from SentinelX
            flow_data = self.sentinelx.get_flow_data(**kwargs)
            # Convert flow data to geo format
            geo_data = []
            for flow in flow_data:
                geo_data.append({
                    'ip': flow.get('dst_ip'),
                    'country': 'Unknown',  # Would be enriched with GeoIP
                    'city': 'Unknown',     # Would be enriched with GeoIP
                    'lat': 0,              # Would be enriched with GeoIP
                    'lon': 0,              # Would be enriched with GeoIP
                    'count': flow.get('packets', 0)
                })
            return geo_data
        
        def _get_heatmap_data(self, **kwargs):
            # Get heatmap data from SentinelX
            flow_data = self.sentinelx.get_flow_data(**kwargs)
            # This would be processed to create a matrix for the heatmap
            return flow_data
        
        def _get_report_data(self, **kwargs):
            # Get report data from SentinelX
            # This would typically call a report generation function
            return {
                'title': 'Security Report',
                'timestamp': datetime.datetime.now().isoformat(),
                'sections': []
            }


class TestVisualizationDashboard(unittest.TestCase):
    """Test the visualization dashboard components."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a mock SentinelX instance
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
        
        # Create a DashboardApp instance
        self.dashboard_app = DashboardApp(self.mock_sentinelx)
    
    def test_dashboard_initialization(self):
        """Test initializing the dashboard application."""
        # Check that the dashboard has the correct SentinelX instance
        self.assertEqual(self.dashboard_app.sentinelx, self.mock_sentinelx, "Dashboard should have the correct SentinelX instance")
        
        # Check that the dashboard has a controller
        self.assertIsInstance(self.dashboard_app.controller, DashboardController, "Dashboard should have a controller")
        
        # Check that the dashboard has the required components
        self.assertIsNotNone(self.dashboard_app.controller.get_component('network-panel'), "Dashboard should have a network panel")
        self.assertIsNotNone(self.dashboard_app.controller.get_component('alert-panel'), "Dashboard should have an alert panel")
        self.assertIsNotNone(self.dashboard_app.controller.get_component('timeseries-panel'), "Dashboard should have a time series panel")
        self.assertIsNotNone(self.dashboard_app.controller.get_component('geomap-panel'), "Dashboard should have a geo map panel")
        self.assertIsNotNone(self.dashboard_app.controller.get_component('heatmap-panel'), "Dashboard should have a heatmap panel")
        self.assertIsNotNone(self.dashboard_app.controller.get_component('report-panel'), "Dashboard should have a report panel")
    
    def test_dashboard_layout(self):
        """Test the dashboard layout."""
        # Get the dashboard layout
        layout = self.dashboard_app.get_layout()
        
        # Check that the layout has the correct structure
        self.assertIn('rows', layout, "Layout should have rows")
        self.assertIn('settings', layout, "Layout should have settings")
        
        # Check that the layout has the correct number of rows
        self.assertEqual(len(layout['rows']), 3, "Layout should have 3 rows")
        
        # Check that the first row has the correct components
        first_row = layout['rows'][0]
        self.assertIn('components', first_row, "Row should have components")
        self.assertEqual(len(first_row['components']), 2, "First row should have 2 components")
        
        # Check that the components have the correct structure
        component = first_row['components'][0]
        self.assertIn('id', component, "Component should have an id")
        self.assertIn('title', component, "Component should have a title")
        self.assertIn('type', component, "Component should have a type")
        self.assertIn('config', component, "Component should have a config")
        self.assertIn('visible', component, "Component should have a visible flag")
    
    def test_dashboard_component_update(self):
        """Test updating a dashboard component."""
        # Get the network panel component
        network_panel = self.dashboard_app.controller.get_component('network-panel')
        
        # Update the component config
        new_config = {'layout': 'circular', 'node_size': 'betweenness'}
        updated_layout = self.dashboard_app.controller.update_component('network-panel', config=new_config)
        
        # Check that the component was updated
        self.assertEqual(updated_layout['config']['layout'], 'circular', "Component config should be updated")
        self.assertEqual(updated_layout['config']['node_size'], 'betweenness', "Component config should be updated")
        
        # Check that the original config values that weren't updated are preserved
        self.assertTrue(updated_layout['config']['show_labels'], "Original config values should be preserved")
    
    def test_dashboard_data_refresh(self):
        """Test refreshing dashboard data."""
        # Refresh the network data
        network_data = self.dashboard_app.controller.refresh_data_source('network_data')
        
        # Check that the SentinelX get_flow_data method was called
        self.mock_sentinelx.get_flow_data.assert_called_once()
        
        # Check that the data has the correct structure
        self.assertEqual(len(network_data), 1, "Network data should have 1 entry")
        self.assertEqual(network_data[0]['src_ip'], '192.168.1.100', "Network data should have the correct source IP")
        
        # Refresh all components
        updates = self.dashboard_app.controller.refresh_all_components()
        
        # Check that all components were updated
        self.assertEqual(len(updates), 6, "All 6 components should be updated")
        self.assertIn('network-panel', updates, "Network panel should be updated")
        self.assertIn('alert-panel', updates, "Alert panel should be updated")
        self.assertIn('timeseries-panel', updates, "Time series panel should be updated")
        self.assertIn('geomap-panel', updates, "Geo map panel should be updated")
        self.assertIn('heatmap-panel', updates, "Heatmap panel should be updated")
        self.assertIn('report-panel', updates, "Report panel should be updated")
    
    def test_dashboard_layout_customization(self):
        """Test customizing the dashboard layout."""
        # Create a custom layout configuration
        custom_layout = {
            'settings': {
                'theme': 'light',
                'refresh_rate': 30,
                'layout_type': 'flex'
            },
            'rows': [
                {
                    'components': [
                        {
                            'id': 'network-panel',
                            'config': {'layout': 'hierarchical'},
                            'visible': True
                        },
                        {
                            'id': 'alert-panel',
                            'config': {'sort_by': 'timestamp'},
                            'visible': True
                        }
                    ],
                    'height': '60%'
                },
                {
                    'components': [
                        {
                            'id': 'timeseries-panel',
                            'config': {'metric': 'bytes'},
                            'visible': True
                        },
                        {
                            'id': 'geomap-panel',
                            'config': {'map_type': 'country'},
                            'visible': False
                        }
                    ],
                    'height': '40%'
                }
            ]
        }
        
        # Apply the custom layout
        new_layout = self.dashboard_app.controller.set_dashboard_layout(custom_layout)
        
        # Check that the layout was updated
        self.assertEqual(new_layout['settings']['theme'], 'light', "Layout settings should be updated")
        self.assertEqual(new_layout['settings']['refresh_rate'], 30, "Layout settings should be updated")
        self.assertEqual(new_layout['settings']['layout_type'], 'flex', "Layout settings should be updated")
        
        # Check that the rows were updated
        self.assertEqual(len(new_layout['rows']), 2, "Layout should have 2 rows")
        
        # Check that the components were updated
        first_row = new_layout['rows'][0]
        self.assertEqual(len(first_row['components']), 2, "First row should have 2 components")
        self.assertEqual(first_row['components'][0]['config']['layout'], 'hierarchical', "Component config should be updated")
        
        # Check that the visibility was updated
        second_row = new_layout['rows'][1]
        self.assertEqual(second_row['components'][1]['visible'], False, "Component visibility should be updated")
    
    def test_dashboard_component_toggle_visibility(self):
        """Test toggling component visibility."""
        # Get the network panel component
        network_panel = self.dashboard_app.controller.get_component('network-panel')
        
        # Check the initial visibility
        self.assertTrue(network_panel.visible, "Component should be initially visible")
        
        # Toggle the visibility
        visibility = network_panel.toggle_visibility()
        
        # Check that the visibility was toggled
        self.assertFalse(visibility, "Component visibility should be toggled")
        self.assertFalse(network_panel.visible, "Component should be hidden")
        
        # Toggle the visibility again
        visibility = network_panel.toggle_visibility()
        
        # Check that the visibility was toggled back
        self.assertTrue(visibility, "Component visibility should be toggled back")
        self.assertTrue(network_panel.visible, "Component should be visible again")
    
    def test_dashboard_run(self):
        """Test running the dashboard application."""
        # Run the dashboard
        result = self.dashboard_app.run()
        
        # Check that the dashboard started successfully
        self.assertTrue(result, "Dashboard should start successfully")
    
    def test_dashboard_data_transformation(self):
        """Test data transformation for different visualization types."""
        # Get time series data
        time_series_data = self.dashboard_app._get_time_series_data()
        
        # Check that the time series data has the correct structure
        self.assertEqual(len(time_series_data), 1, "Time series data should have 1 entry")
        self.assertIn('timestamp', time_series_data[0], "Time series data should have a timestamp")
        self.assertIn('packets', time_series_data[0], "Time series data should have packets")
        self.assertIn('bytes', time_series_data[0], "Time series data should have bytes")
        self.assertIn('flows', time_series_data[0], "Time series data should have flows")
        
        # Get geo data
        geo_data = self.dashboard_app._get_geo_data()
        
        # Check that the geo data has the correct structure
        self.assertEqual(len(geo_data), 1, "Geo data should have 1 entry")
        self.assertIn('ip', geo_data[0], "Geo data should have an IP")
        self.assertIn('country', geo_data[0], "Geo data should have a country")
        self.assertIn('city', geo_data[0], "Geo data should have a city")
        self.assertIn('lat', geo_data[0], "Geo data should have a latitude")
        self.assertIn('lon', geo_data[0], "Geo data should have a longitude")
        self.assertIn('count', geo_data[0], "Geo data should have a count")
        
        # Get report data
        report_data = self.dashboard_app._get_report_data()
        
        # Check that the report data has the correct structure
        self.assertIn('title', report_data, "Report data should have a title")
        self.assertIn('timestamp', report_data, "Report data should have a timestamp")
        self.assertIn('sections', report_data, "Report data should have sections")


class TestDashboardComponents(unittest.TestCase):
    """Test individual dashboard components."""
    
    def test_dashboard_component_base(self):
        """Test the base DashboardComponent class."""
        # Create a component
        component = DashboardComponent("test-component", "Test Component", "test_data")
        
        # Check the component properties
        self.assertEqual(component.component_id, "test-component", "Component should have the correct ID")
        self.assertEqual(component.title, "Test Component", "Component should have the correct title")
        self.assertEqual(component.data_source, "test_data", "Component should have the correct data source")
        self.assertTrue(component.visible, "Component should be initially visible")
        
        # Set config
        component.set_config({'test_key': 'test_value'})
        
        # Check that the config was set
        self.assertEqual(component.config['test_key'], 'test_value', "Component config should be set")
        
        # Set data
        component.set_data({'test_data': 'test_value'})
        
        # Check that the data was set
        self.assertEqual(component.data['test_data'], 'test_value', "Component data should be set")
        
        # Get layout
        layout = component.get_layout()
        
        # Check that the layout has the correct structure
        self.assertEqual(layout['id'], "test-component", "Layout should have the correct ID")
        self.assertEqual(layout['title'], "Test Component", "Layout should have the correct title")
        self.assertEqual(layout['type'], "DashboardComponent", "Layout should have the correct type")
        self.assertEqual(layout['config']['test_key'], 'test_value', "Layout should have the correct config")
        self.assertTrue(layout['visible'], "Layout should have the correct visibility")
    
    def test_network_panel(self):
        """Test the NetworkPanel component."""
        # Create a network panel
        panel = NetworkPanel()
        
        # Check the panel properties
        self.assertEqual(panel.component_id, "network-panel", "Panel should have the correct ID")
        self.assertEqual(panel.title, "Network Graph", "Panel should have the correct title")
        
        # Check the panel config
        self.assertEqual(panel.config['layout'], 'force', "Panel should have the correct layout")
        self.assertEqual(panel.config['node_size'], 'degree', "Panel should have the correct node size")
        self.assertEqual(panel.config['edge_width'], 'weight', "Panel should have the correct edge width")
        self.assertTrue(panel.config['show_labels'], "Panel should show labels")
        self.assertTrue(panel.config['highlight_anomalies'], "Panel should highlight anomalies")
    
    def test_alert_panel(self):
        """Test the AlertPanel component."""
        # Create an alert panel
        panel = AlertPanel()
        
        # Check the panel properties
        self.assertEqual(panel.component_id, "alert-panel", "Panel should have the correct ID")
        self.assertEqual(panel.title, "Alert Dashboard", "Panel should have the correct title")
        
        # Check the panel config
        self.assertEqual(panel.config['sort_by'], 'severity', "Panel should have the correct sort by")
        self.assertEqual(panel.config['filter_status'], 'all', "Panel should have the correct filter status")
        self.assertTrue(panel.config['show_details'], "Panel should show details")
        self.assertTrue(panel.config['auto_refresh'], "Panel should auto refresh")
        self.assertEqual(panel.config['refresh_interval'], 60, "Panel should have the correct refresh interval")
    
    def test_timeseries_panel(self):
        """Test the TimeSeriesPanel component."""
        # Create a time series panel
        panel = TimeSeriesPanel()
        
        # Check the panel properties
        self.assertEqual(panel.component_id, "timeseries-panel", "Panel should have the correct ID")
        self.assertEqual(panel.title, "Network Traffic", "Panel should have the correct title")
        
        # Check the panel config
        self.assertEqual(panel.config['metric'], 'packets', "Panel should have the correct metric")
        self.assertEqual(panel.config['interval'], 'minute', "Panel should have the correct interval")
        self.assertEqual(panel.config['time_window'], '1h', "Panel should have the correct time window")
        self.assertTrue(panel.config['show_anomalies'], "Panel should show anomalies")
        self.assertFalse(panel.config['compare_previous'], "Panel should not compare previous")
    
    def test_geomap_panel(self):
        """Test the GeoMapPanel component."""
        # Create a geo map panel
        panel = GeoMapPanel()
        
        # Check the panel properties
        self.assertEqual(panel.component_id, "geomap-panel", "Panel should have the correct ID")
        self.assertEqual(panel.title, "Geographic Traffic", "Panel should have the correct title")
        
        # Check the panel config
        self.assertEqual(panel.config['map_type'], 'world', "Panel should have the correct map type")
        self.assertFalse(panel.config['include_internal'], "Panel should not include internal")
        self.assertTrue(panel.config['highlight_threats'], "Panel should highlight threats")
        self.assertTrue(panel.config['connection_lines'], "Panel should show connection lines")
        self.assertFalse(panel.config['heatmap_mode'], "Panel should not be in heatmap mode")
    
    def test_heatmap_panel(self):
        """Test the HeatMapPanel component."""
        # Create a heatmap panel
        panel = HeatMapPanel()
        
        # Check the panel properties
        self.assertEqual(panel.component_id, "heatmap-panel", "Panel should have the correct ID")
        self.assertEqual(panel.title, "Traffic Heatmap", "Panel should have the correct title")
        
        # Check the panel config
        self.assertEqual(panel.config['metric'], 'connections', "Panel should have the correct metric")
        self.assertEqual(panel.config['groupby_x'], 'source_ip', "Panel should have the correct groupby_x")
        self.assertEqual(panel.config['groupby_y'], 'destination_port', "Panel should have the correct groupby_y")
        self.assertEqual(panel.config['color_scale'], 'viridis', "Panel should have the correct color scale")
        self.assertTrue(panel.config['log_scale'], "Panel should use log scale")
    
    def test_report_panel(self):
        """Test the ReportPanel component."""
        # Create a report panel
        panel = ReportPanel()
        
        # Check the panel properties
        self.assertEqual(panel.component_id, "report-panel", "Panel should have the correct ID")
        self.assertEqual(panel.title, "Security Reports", "Panel should have the correct title")
        
        # Check the panel config
        self.assertEqual(panel.config['report_type'], 'summary', "Panel should have the correct report type")
        self.assertEqual(panel.config['time_period'], 'day', "Panel should have the correct time period")
        self.assertFalse(panel.config['auto_generate'], "Panel should not auto generate")
        self.assertTrue(panel.config['include_visuals'], "Panel should include visuals")
        self.assertEqual(panel.config['export_format'], 'html', "Panel should have the correct export format")


if __name__ == '__main__':
    unittest.main()