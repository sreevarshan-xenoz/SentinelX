#!/usr/bin/env python
# SentinelX Visualization Web Application

import os
import sys
import json
import datetime
import threading
import time
from pathlib import Path

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import Dash and related libraries
import dash
from dash import dcc, html, Input, Output, State, callback
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from flask import Flask, request, redirect, session

# Import SentinelX modules
from src.sentinelx import SentinelX
from src.visualization.visualization_manager import VisualizationManager
from src.visualization.export import VisualizationExporter, ExportFormat
from src.config.config_manager import ConfigManager
from src.logging.logging_manager import LoggingManager


class DashboardApp:
    """Web-based dashboard application for SentinelX visualization components."""
    
    def __init__(self, sentinelx=None, port=8050, debug=False):
        """Initialize the dashboard application.
        
        Args:
            sentinelx: SentinelX instance. If None, a new instance will be created.
            port: Port to run the dashboard on.
            debug: Whether to run in debug mode.
        """
        # Initialize SentinelX if not provided
        self.sentinelx = sentinelx if sentinelx else SentinelX()
        self.vis_manager = VisualizationManager(self.sentinelx)
        self.exporter = VisualizationExporter()
        self.port = port
        self.debug = debug
        
        # Initialize logging
        self.logger = LoggingManager().get_logger("dashboard")
        
        # Initialize Flask server with authentication
        self.server = Flask(__name__)
        self.server.secret_key = os.urandom(24)
        
        # Initialize Dash app
        self.app = dash.Dash(
            __name__,
            server=self.server,
            external_stylesheets=[dbc.themes.DARKLY],
            suppress_callback_exceptions=True,
            title="SentinelX Dashboard"
        )
        
        # Set up authentication
        self.setup_authentication()
        
        # Set up the layout
        self.setup_layout()
        
        # Set up callbacks
        self.setup_callbacks()
        
        # Data refresh thread
        self.refresh_interval = 60  # seconds
        self.stop_refresh_thread = threading.Event()
        self.refresh_thread = None
    
    def setup_authentication(self):
        """Set up authentication for the dashboard."""
        # Get authentication settings from config
        config = ConfigManager().get_config()
        self.auth_enabled = config.get("dashboard", {}).get("auth_enabled", True)
        self.username = config.get("dashboard", {}).get("username", "admin")
        self.password = config.get("dashboard", {}).get("password", "sentinelx")
        
        # Add authentication routes
        @self.server.route('/login', methods=['GET', 'POST'])
        def login():
            if not self.auth_enabled:
                session['authenticated'] = True
                return redirect('/')
            
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                if username == self.username and password == self.password:
                    session['authenticated'] = True
                    return redirect('/')
                else:
                    return """
                    <html>
                        <head>
                            <title>SentinelX - Login Failed</title>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #1e1e1e; color: #fff; }
                                .login-container { background-color: #2a2a2a; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.5); width: 300px; }
                                h1 { text-align: center; color: #00bcd4; }
                                input { width: 100%; padding: 10px; margin: 10px 0; border: none; border-radius: 3px; }
                                button { width: 100%; padding: 10px; background-color: #00bcd4; color: white; border: none; border-radius: 3px; cursor: pointer; }
                                button:hover { background-color: #008ba3; }
                                .error { color: #ff5252; text-align: center; margin-bottom: 15px; }
                            </style>
                        </head>
                        <body>
                            <div class="login-container">
                                <h1>SentinelX</h1>
                                <div class="error">Invalid username or password</div>
                                <form method="post">
                                    <input type="text" name="username" placeholder="Username" required>
                                    <input type="password" name="password" placeholder="Password" required>
                                    <button type="submit">Login</button>
                                </form>
                            </div>
                        </body>
                    </html>
                    """
            
            return """
            <html>
                <head>
                    <title>SentinelX - Login</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #1e1e1e; color: #fff; }
                        .login-container { background-color: #2a2a2a; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.5); width: 300px; }
                        h1 { text-align: center; color: #00bcd4; }
                        input { width: 100%; padding: 10px; margin: 10px 0; border: none; border-radius: 3px; }
                        button { width: 100%; padding: 10px; background-color: #00bcd4; color: white; border: none; border-radius: 3px; cursor: pointer; }
                        button:hover { background-color: #008ba3; }
                    </style>
                </head>
                <body>
                    <div class="login-container">
                        <h1>SentinelX</h1>
                        <form method="post">
                            <input type="text" name="username" placeholder="Username" required>
                            <input type="password" name="password" placeholder="Password" required>
                            <button type="submit">Login</button>
                        </form>
                    </div>
                </body>
            </html>
            """
        
        @self.server.route('/logout')
        def logout():
            session.pop('authenticated', None)
            return redirect('/login')
        
        @self.server.before_request
        def check_authentication():
            if not self.auth_enabled:
                return
            
            if request.path == '/login':
                return
            
            if not session.get('authenticated'):
                return redirect('/login')
    
    def setup_layout(self):
        """Set up the dashboard layout."""
        # Create the navbar
        navbar = dbc.Navbar(
            dbc.Container(
                [
                    html.A(
                        dbc.Row(
                            [
                                dbc.Col(html.Img(src="/assets/logo.png", height="30px"), width="auto"),
                                dbc.Col(dbc.NavbarBrand("SentinelX Dashboard", className="ms-2")),
                            ],
                            align="center",
                            className="g-0",
                        ),
                        href="/",
                        style={"textDecoration": "none"},
                    ),
                    dbc.NavbarToggler(id="navbar-toggler"),
                    dbc.Collapse(
                        dbc.Nav(
                            [
                                dbc.NavItem(dbc.NavLink("Dashboard", href="/")),
                                dbc.NavItem(dbc.NavLink("Network", href="/network")),
                                dbc.NavItem(dbc.NavLink("Alerts", href="/alerts")),
                                dbc.NavItem(dbc.NavLink("Time Series", href="/timeseries")),
                                dbc.NavItem(dbc.NavLink("Heatmap", href="/heatmap")),
                                dbc.NavItem(dbc.NavLink("GeoIP Map", href="/geomap")),
                                dbc.NavItem(dbc.NavLink("Reports", href="/reports")),
                                dbc.NavItem(dbc.NavLink("System Info", href="/system")),
                                dbc.NavItem(dbc.NavLink("Logout", href="/logout")),
                            ],
                            className="ms-auto",
                            navbar=True,
                        ),
                        id="navbar-collapse",
                        navbar=True,
                    ),
                ]
            ),
            color="dark",
            dark=True,
        )
        
        # Create the content area
        content = html.Div(id="page-content", className="container mt-4")
        
        # Set the app layout
        self.app.layout = html.Div([
            dcc.Location(id="url", refresh=False),
            navbar,
            content,
            dcc.Interval(
                id='interval-component',
                interval=self.refresh_interval * 1000,  # in milliseconds
                n_intervals=0
            ),
            # Store components for data
            dcc.Store(id='network-data-store'),
            dcc.Store(id='alerts-data-store'),
            dcc.Store(id='timeseries-data-store'),
            dcc.Store(id='heatmap-data-store'),
            dcc.Store(id='geoip-data-store'),
            dcc.Store(id='system-data-store'),
        ])
    
    def setup_callbacks(self):
        """Set up the dashboard callbacks."""
        # URL routing callback
        @self.app.callback(
            Output("page-content", "children"),
            [Input("url", "pathname")]
        )
        def render_page_content(pathname):
            if pathname == "/" or pathname == "/dashboard":
                return self.render_dashboard_page()
            elif pathname == "/network":
                return self.render_network_page()
            elif pathname == "/alerts":
                return self.render_alerts_page()
            elif pathname == "/timeseries":
                return self.render_timeseries_page()
            elif pathname == "/heatmap":
                return self.render_heatmap_page()
            elif pathname == "/geomap":
                return self.render_geomap_page()
            elif pathname == "/reports":
                return self.render_reports_page()
            elif pathname == "/system":
                return self.render_system_page()
            else:
                # 404 page
                return dbc.Container(
                    [
                        html.H1("404: Not found", className="text-danger"),
                        html.Hr(),
                        html.P(f"The pathname {pathname} was not recognized..."),
                    ],
                    className="p-5",
                )
        
        # Data refresh callbacks
        @self.app.callback(
            [
                Output("network-data-store", "data"),
                Output("alerts-data-store", "data"),
                Output("timeseries-data-store", "data"),
                Output("heatmap-data-store", "data"),
                Output("geoip-data-store", "data"),
                Output("system-data-store", "data"),
            ],
            [Input("interval-component", "n_intervals")]
        )
        def update_data(n_intervals):
            # Get the current time
            now = datetime.datetime.now()
            
            # Time window for the last 24 hours
            time_window = {
                'start': (now - datetime.timedelta(hours=24)).isoformat(),
                'end': now.isoformat()
            }
            
            # Get network data
            try:
                network_data = self.vis_manager.generate_network_graph(time_window=time_window, top_n=10)
                network_data = network_data.to_json() if hasattr(network_data, 'to_json') else json.dumps(network_data)
            except Exception as e:
                self.logger.error(f"Error generating network data: {e}")
                network_data = json.dumps({"error": str(e)})
            
            # Get alerts data
            try:
                alerts_data = self.vis_manager.generate_alert_dashboard(time_window=time_window)
                alerts_data = alerts_data.to_json() if hasattr(alerts_data, 'to_json') else json.dumps(alerts_data)
            except Exception as e:
                self.logger.error(f"Error generating alerts data: {e}")
                alerts_data = json.dumps({"error": str(e)})
            
            # Get time series data
            try:
                timeseries_data = self.vis_manager.generate_time_series(metric="packets", interval="hour", time_window=time_window)
                timeseries_data = timeseries_data.to_json() if hasattr(timeseries_data, 'to_json') else json.dumps(timeseries_data)
            except Exception as e:
                self.logger.error(f"Error generating time series data: {e}")
                timeseries_data = json.dumps({"error": str(e)})
            
            # Get heatmap data
            try:
                heatmap_data = self.vis_manager.generate_heatmap(metric="connections", groupby_x="source_ip", groupby_y="destination_port")
                heatmap_data = heatmap_data.to_json() if hasattr(heatmap_data, 'to_json') else json.dumps(heatmap_data)
            except Exception as e:
                self.logger.error(f"Error generating heatmap data: {e}")
                heatmap_data = json.dumps({"error": str(e)})
            
            # Get GeoIP data
            try:
                geoip_data = self.vis_manager.generate_geoip_map(include_internal=False)
                geoip_data = geoip_data.to_json() if hasattr(geoip_data, 'to_json') else json.dumps(geoip_data)
            except Exception as e:
                self.logger.error(f"Error generating GeoIP data: {e}")
                geoip_data = json.dumps({"error": str(e)})
            
            # Get system data
            try:
                system_data = self.sentinelx.get_system_info()
                system_data = json.dumps(system_data)
            except Exception as e:
                self.logger.error(f"Error getting system info: {e}")
                system_data = json.dumps({"error": str(e)})
            
            return network_data, alerts_data, timeseries_data, heatmap_data, geoip_data, system_data
        
        # Add more callbacks for specific page interactions
        # ...
    
    def render_dashboard_page(self):
        """Render the main dashboard page."""
        return dbc.Container([
            html.H1("SentinelX Security Dashboard"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Activity"),
                        dbc.CardBody([
                            dcc.Graph(id="dashboard-network-graph"),
                        ]),
                    ]),
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Summary"),
                        dbc.CardBody([
                            dcc.Graph(id="dashboard-alerts-graph"),
                        ]),
                    ]),
                ], width=6),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Traffic Over Time"),
                        dbc.CardBody([
                            dcc.Graph(id="dashboard-timeseries-graph"),
                        ]),
                    ]),
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Geographic Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id="dashboard-geoip-graph"),
                        ]),
                    ]),
                ], width=6),
            ]),
        ])
    
    def render_network_page(self):
        """Render the network visualization page."""
        return dbc.Container([
            html.H1("Network Graph"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Filters"),
                        dbc.CardBody([
                            dbc.Form([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Time Window"),
                                        dcc.Dropdown(
                                            id="network-time-window",
                                            options=[
                                                {"label": "Last Hour", "value": "1h"},
                                                {"label": "Last 6 Hours", "value": "6h"},
                                                {"label": "Last 24 Hours", "value": "24h"},
                                                {"label": "Last 7 Days", "value": "7d"},
                                            ],
                                            value="24h",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Top Nodes"),
                                        dcc.Slider(
                                            id="network-top-nodes",
                                            min=5,
                                            max=50,
                                            step=5,
                                            value=10,
                                            marks={i: str(i) for i in range(5, 51, 5)},
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Protocol"),
                                        dcc.Dropdown(
                                            id="network-protocol",
                                            options=[
                                                {"label": "All", "value": "all"},
                                                {"label": "TCP", "value": "tcp"},
                                                {"label": "UDP", "value": "udp"},
                                                {"label": "ICMP", "value": "icmp"},
                                            ],
                                            value="all",
                                        ),
                                    ], width=4),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button("Apply Filters", id="network-apply-filters", color="primary", className="mt-3"),
                                        dbc.Button("Export", id="network-export", color="secondary", className="mt-3 ms-2"),
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Graph"),
                        dbc.CardBody([
                            dcc.Graph(id="network-graph", style={"height": "600px"}),
                        ]),
                    ]),
                ], width=12),
            ]),
        ])
    
    def render_alerts_page(self):
        """Render the alerts visualization page."""
        return dbc.Container([
            html.H1("Alert Dashboard"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Filters"),
                        dbc.CardBody([
                            dbc.Form([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Time Window"),
                                        dcc.Dropdown(
                                            id="alerts-time-window",
                                            options=[
                                                {"label": "Last Hour", "value": "1h"},
                                                {"label": "Last 6 Hours", "value": "6h"},
                                                {"label": "Last 24 Hours", "value": "24h"},
                                                {"label": "Last 7 Days", "value": "7d"},
                                            ],
                                            value="24h",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Severity"),
                                        dcc.Dropdown(
                                            id="alerts-severity",
                                            options=[
                                                {"label": "All", "value": "all"},
                                                {"label": "High", "value": "high"},
                                                {"label": "Medium", "value": "medium"},
                                                {"label": "Low", "value": "low"},
                                            ],
                                            value="all",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Category"),
                                        dcc.Dropdown(
                                            id="alerts-category",
                                            options=[
                                                {"label": "All", "value": "all"},
                                                {"label": "Malware", "value": "malware"},
                                                {"label": "Intrusion", "value": "intrusion"},
                                                {"label": "DDoS", "value": "ddos"},
                                                {"label": "Reconnaissance", "value": "recon"},
                                                {"label": "Other", "value": "other"},
                                            ],
                                            value="all",
                                        ),
                                    ], width=4),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button("Apply Filters", id="alerts-apply-filters", color="primary", className="mt-3"),
                                        dbc.Button("Export", id="alerts-export", color="secondary", className="mt-3 ms-2"),
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Summary"),
                        dbc.CardBody([
                            dcc.Graph(id="alerts-summary-graph"),
                        ]),
                    ]),
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Timeline"),
                        dbc.CardBody([
                            dcc.Graph(id="alerts-timeline-graph"),
                        ]),
                    ]),
                ], width=6),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Details"),
                        dbc.CardBody([
                            html.Div(id="alerts-table"),
                        ]),
                    ]),
                ], width=12),
            ]),
        ])
    
    def render_timeseries_page(self):
        """Render the time series visualization page."""
        return dbc.Container([
            html.H1("Time Series Analysis"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Filters"),
                        dbc.CardBody([
                            dbc.Form([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Metric"),
                                        dcc.Dropdown(
                                            id="timeseries-metric",
                                            options=[
                                                {"label": "Packets", "value": "packets"},
                                                {"label": "Bytes", "value": "bytes"},
                                                {"label": "Flows", "value": "flows"},
                                            ],
                                            value="packets",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Interval"),
                                        dcc.Dropdown(
                                            id="timeseries-interval",
                                            options=[
                                                {"label": "Minute", "value": "minute"},
                                                {"label": "Hour", "value": "hour"},
                                                {"label": "Day", "value": "day"},
                                            ],
                                            value="hour",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Time Window"),
                                        dcc.Dropdown(
                                            id="timeseries-time-window",
                                            options=[
                                                {"label": "Last Hour", "value": "1h"},
                                                {"label": "Last 6 Hours", "value": "6h"},
                                                {"label": "Last 24 Hours", "value": "24h"},
                                                {"label": "Last 7 Days", "value": "7d"},
                                            ],
                                            value="24h",
                                        ),
                                    ], width=4),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button("Apply Filters", id="timeseries-apply-filters", color="primary", className="mt-3"),
                                        dbc.Button("Export", id="timeseries-export", color="secondary", className="mt-3 ms-2"),
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Time Series Plot"),
                        dbc.CardBody([
                            dcc.Graph(id="timeseries-graph", style={"height": "400px"}),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Anomaly Detection"),
                        dbc.CardBody([
                            dcc.Graph(id="timeseries-anomaly-graph", style={"height": "400px"}),
                        ]),
                    ]),
                ], width=12),
            ]),
        ])
    
    def render_heatmap_page(self):
        """Render the heatmap visualization page."""
        return dbc.Container([
            html.H1("Heatmap Analysis"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Filters"),
                        dbc.CardBody([
                            dbc.Form([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Metric"),
                                        dcc.Dropdown(
                                            id="heatmap-metric",
                                            options=[
                                                {"label": "Connections", "value": "connections"},
                                                {"label": "Packets", "value": "packets"},
                                                {"label": "Bytes", "value": "bytes"},
                                            ],
                                            value="connections",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("X-Axis"),
                                        dcc.Dropdown(
                                            id="heatmap-x-axis",
                                            options=[
                                                {"label": "Source IP", "value": "source_ip"},
                                                {"label": "Destination IP", "value": "destination_ip"},
                                                {"label": "Source Port", "value": "source_port"},
                                                {"label": "Destination Port", "value": "destination_port"},
                                                {"label": "Protocol", "value": "protocol"},
                                            ],
                                            value="source_ip",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Y-Axis"),
                                        dcc.Dropdown(
                                            id="heatmap-y-axis",
                                            options=[
                                                {"label": "Source IP", "value": "source_ip"},
                                                {"label": "Destination IP", "value": "destination_ip"},
                                                {"label": "Source Port", "value": "source_port"},
                                                {"label": "Destination Port", "value": "destination_port"},
                                                {"label": "Protocol", "value": "protocol"},
                                            ],
                                            value="destination_port",
                                        ),
                                    ], width=4),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button("Apply Filters", id="heatmap-apply-filters", color="primary", className="mt-3"),
                                        dbc.Button("Export", id="heatmap-export", color="secondary", className="mt-3 ms-2"),
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Heatmap"),
                        dbc.CardBody([
                            dcc.Graph(id="heatmap-graph", style={"height": "600px"}),
                        ]),
                    ]),
                ], width=12),
            ]),
        ])
    
    def render_geomap_page(self):
        """Render the GeoIP map visualization page."""
        return dbc.Container([
            html.H1("Geographic IP Map"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Filters"),
                        dbc.CardBody([
                            dbc.Form([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Include Internal IPs"),
                                        dbc.Checklist(
                                            id="geomap-include-internal",
                                            options=[
                                                {"label": "Include Internal IPs", "value": 1},
                                            ],
                                            value=[],
                                            switch=True,
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Filter by Country"),
                                        dcc.Dropdown(
                                            id="geomap-country",
                                            options=[
                                                {"label": "All Countries", "value": "all"},
                                                # This will be populated dynamically
                                            ],
                                            value="all",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Direction"),
                                        dcc.Dropdown(
                                            id="geomap-direction",
                                            options=[
                                                {"label": "Both", "value": "both"},
                                                {"label": "Inbound", "value": "inbound"},
                                                {"label": "Outbound", "value": "outbound"},
                                            ],
                                            value="both",
                                        ),
                                    ], width=4),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button("Apply Filters", id="geomap-apply-filters", color="primary", className="mt-3"),
                                        dbc.Button("Export", id="geomap-export", color="secondary", className="mt-3 ms-2"),
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Geographic IP Map"),
                        dbc.CardBody([
                            dcc.Graph(id="geomap-graph", style={"height": "600px"}),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Country Statistics"),
                        dbc.CardBody([
                            html.Div(id="geomap-stats"),
                        ]),
                    ]),
                ], width=12),
            ]),
        ])
    
    def render_reports_page(self):
        """Render the reports page."""
        return dbc.Container([
            html.H1("Security Reports"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Generate Report"),
                        dbc.CardBody([
                            dbc.Form([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Report Type"),
                                        dcc.Dropdown(
                                            id="report-type",
                                            options=[
                                                {"label": "Summary", "value": "summary"},
                                                {"label": "Detailed", "value": "detailed"},
                                            ],
                                            value="summary",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Time Period"),
                                        dcc.Dropdown(
                                            id="report-period",
                                            options=[
                                                {"label": "Last Hour", "value": "hour"},
                                                {"label": "Last Day", "value": "day"},
                                                {"label": "Last Week", "value": "week"},
                                                {"label": "Last Month", "value": "month"},
                                            ],
                                            value="day",
                                        ),
                                    ], width=4),
                                    dbc.Col([
                                        dbc.Label("Format"),
                                        dcc.Dropdown(
                                            id="report-format",
                                            options=[
                                                {"label": "HTML", "value": "html"},
                                                {"label": "PDF", "value": "pdf"},
                                                {"label": "Markdown", "value": "md"},
                                                {"label": "JSON", "value": "json"},
                                            ],
                                            value="html",
                                        ),
                                    ], width=4),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button("Generate Report", id="report-generate", color="primary", className="mt-3"),
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Recent Reports"),
                        dbc.CardBody([
                            html.Div(id="reports-list"),
                        ]),
                    ]),
                ], width=12),
            ]),
        ])
    
    def render_system_page(self):
        """Render the system information page."""
        return dbc.Container([
            html.H1("System Information"),
            html.Hr(),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("System Overview"),
                        dbc.CardBody([
                            html.Div(id="system-overview"),
                        ]),
                    ]),
                ], width=12),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("CPU Usage"),
                        dbc.CardBody([
                            dcc.Graph(id="system-cpu-graph"),
                        ]),
                    ]),
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Memory Usage"),
                        dbc.CardBody([
                            dcc.Graph(id="system-memory-graph"),
                        ]),
                    ]),
                ], width=6),
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Disk Usage"),
                        dbc.CardBody([
                            dcc.Graph(id="system-disk-graph"),
                        ]),
                    ]),
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Usage"),
                        dbc.CardBody([
                            dcc.Graph(id="system-network-graph"),
                        ]),
                    ]),
                ], width=6),
            ]),
        ])
    
    def start_refresh_thread(self):
        """Start the data refresh thread."""
        if self.refresh_thread is None or not self.refresh_thread.is_alive():
            self.stop_refresh_thread.clear()
            self.refresh_thread = threading.Thread(target=self.refresh_data_thread)
            self.refresh_thread.daemon = True
            self.refresh_thread.start()
    
    def refresh_data_thread(self):
        """Thread function to refresh data periodically."""
        while not self.stop_refresh_thread.is_set():
            try:
                # Refresh data here
                pass
            except Exception as e:
                self.logger.error(f"Error refreshing data: {e}")
            
            # Sleep for the refresh interval
            time.sleep(self.refresh_interval)
    
    def stop_refresh_thread(self):
        """Stop the data refresh thread."""
        if self.refresh_thread and self.refresh_thread.is_alive():
            self.stop_refresh_thread.set()
            self.refresh_thread.join()
    
    def run(self):
        """Run the dashboard application."""
        # Start the data refresh thread
        self.start_refresh_thread()
        
        try:
            # Run the Dash app
            self.app.run_server(port=self.port, debug=self.debug)
        finally:
            # Stop the data refresh thread
            self.stop_refresh_thread()


def main():
    """Main entry point for the web application."""
    app = DashboardApp(port=8050, debug=True)
    app.run()


if __name__ == "__main__":
    main()