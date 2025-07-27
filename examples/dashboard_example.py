#!/usr/bin/env python
# SentinelX Dashboard Example

import os
import sys
import datetime
import json

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Dash and related libraries
import dash
from dash import dcc, html, Input, Output, callback
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go

# Import SentinelX modules
from src.sentinelx import SentinelX
from src.visualization.visualization_manager import VisualizationManager


# Initialize SentinelX and VisualizationManager
sentinelx = SentinelX()
vis_manager = VisualizationManager(sentinelx)

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    title="SentinelX Simple Dashboard"
)

# Define the app layout
app.layout = dbc.Container([
    html.H1("SentinelX Simple Dashboard", className="my-4"),
    
    # Time window selector
    dbc.Row([
        dbc.Col([
            html.Label("Time Window"),
            dcc.Dropdown(
                id="time-window",
                options=[
                    {"label": "Last Hour", "value": "1h"},
                    {"label": "Last 6 Hours", "value": "6h"},
                    {"label": "Last 24 Hours", "value": "24h"},
                    {"label": "Last 7 Days", "value": "7d"},
                ],
                value="24h",
            ),
        ], width=3),
        dbc.Col([
            html.Label("Refresh Interval"),
            dcc.Dropdown(
                id="refresh-interval",
                options=[
                    {"label": "No Refresh", "value": 0},
                    {"label": "30 Seconds", "value": 30},
                    {"label": "1 Minute", "value": 60},
                    {"label": "5 Minutes", "value": 300},
                ],
                value=60,
            ),
        ], width=3),
        dbc.Col([
            html.Button(
                "Refresh Now",
                id="refresh-button",
                className="btn btn-primary mt-4"
            ),
        ], width=3),
    ], className="mb-4"),
    
    # Network and Alerts row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Network Activity"),
                dbc.CardBody([
                    dcc.Loading(
                        id="loading-network",
                        type="circle",
                        children=dcc.Graph(id="network-graph"),
                    ),
                ]),
            ]),
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Alert Summary"),
                dbc.CardBody([
                    dcc.Loading(
                        id="loading-alerts",
                        type="circle",
                        children=dcc.Graph(id="alerts-graph"),
                    ),
                ]),
            ]),
        ], width=6),
    ], className="mb-4"),
    
    # Time Series and GeoIP row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Over Time"),
                dbc.CardBody([
                    dcc.Loading(
                        id="loading-timeseries",
                        type="circle",
                        children=dcc.Graph(id="timeseries-graph"),
                    ),
                ]),
            ]),
        ], width=6),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Geographic Distribution"),
                dbc.CardBody([
                    dcc.Loading(
                        id="loading-geoip",
                        type="circle",
                        children=dcc.Graph(id="geoip-graph"),
                    ),
                ]),
            ]),
        ], width=6),
    ]),
    
    # Refresh interval component
    dcc.Interval(
        id="interval-component",
        interval=60 * 1000,  # in milliseconds
        n_intervals=0
    ),
])


# Helper function to parse time window
def parse_time_window(time_window):
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


# Update refresh interval callback
@callback(
    Output("interval-component", "interval"),
    Input("refresh-interval", "value")
)
def update_refresh_interval(value):
    """Update the refresh interval."""
    if value == 0:
        # Disable refresh (set to a very large value)
        return 1000 * 60 * 60 * 24  # 24 hours
    else:
        return value * 1000  # Convert seconds to milliseconds


# Update graphs callback
@callback(
    [
        Output("network-graph", "figure"),
        Output("alerts-graph", "figure"),
        Output("timeseries-graph", "figure"),
        Output("geoip-graph", "figure"),
    ],
    [
        Input("interval-component", "n_intervals"),
        Input("refresh-button", "n_clicks"),
        Input("time-window", "value"),
    ]
)
def update_graphs(n_intervals, n_clicks, time_window):
    """Update all graphs."""
    # Parse the time window
    time_window_dict = parse_time_window(time_window)
    
    # Generate network graph
    try:
        network_data = vis_manager.generate_network_graph(time_window=time_window_dict, top_n=10)
        # Convert to Plotly figure
        network_fig = go.Figure(data=go.Scatter(
            x=[0, 1, 2, 3, 4, 5],
            y=[0, 1, 4, 9, 16, 25],
            mode='markers',
            marker=dict(size=20, color='blue'),
        ))
        network_fig.update_layout(
            title="Network Graph (Placeholder)",
            xaxis_title="X",
            yaxis_title="Y",
            template="plotly_dark"
        )
    except Exception as e:
        print(f"Error generating network graph: {e}")
        network_fig = go.Figure().add_annotation(
            text=f"Error generating network graph: {e}",
            showarrow=False,
            font=dict(color="red")
        )
    
    # Generate alerts graph
    try:
        alerts_data = vis_manager.generate_alert_dashboard(time_window=time_window_dict)
        # Create a placeholder bar chart
        alerts_fig = go.Figure(data=[
            go.Bar(name='High', x=['Malware', 'Intrusion', 'DDoS', 'Recon'], y=[4, 2, 1, 3]),
            go.Bar(name='Medium', x=['Malware', 'Intrusion', 'DDoS', 'Recon'], y=[2, 5, 3, 2]),
            go.Bar(name='Low', x=['Malware', 'Intrusion', 'DDoS', 'Recon'], y=[1, 3, 7, 5])
        ])
        alerts_fig.update_layout(
            title="Alert Summary by Category and Severity (Placeholder)",
            xaxis_title="Category",
            yaxis_title="Count",
            barmode='stack',
            template="plotly_dark"
        )
    except Exception as e:
        print(f"Error generating alerts graph: {e}")
        alerts_fig = go.Figure().add_annotation(
            text=f"Error generating alerts graph: {e}",
            showarrow=False,
            font=dict(color="red")
        )
    
    # Generate time series graph
    try:
        timeseries_data = vis_manager.generate_time_series(
            metric="packets",
            interval="hour",
            time_window=time_window_dict
        )
        # Create a placeholder line chart
        x = [datetime.datetime.now() - datetime.timedelta(hours=i) for i in range(24, 0, -1)]
        y = [100 + i**2 for i in range(24)]
        timeseries_fig = go.Figure(data=go.Scatter(x=x, y=y, mode='lines+markers'))
        timeseries_fig.update_layout(
            title="Packets Over Time (Placeholder)",
            xaxis_title="Time",
            yaxis_title="Packets",
            template="plotly_dark"
        )
    except Exception as e:
        print(f"Error generating time series graph: {e}")
        timeseries_fig = go.Figure().add_annotation(
            text=f"Error generating time series graph: {e}",
            showarrow=False,
            font=dict(color="red")
        )
    
    # Generate GeoIP graph
    try:
        geoip_data = vis_manager.generate_geoip_map(include_internal=False)
        # Create a placeholder choropleth map
        geoip_fig = go.Figure(data=go.Choropleth(
            locations=['USA', 'CAN', 'MEX', 'RUS', 'CHN', 'GBR', 'DEU', 'FRA', 'IND'],
            z=[10, 5, 3, 8, 12, 6, 7, 4, 9],
            locationmode='country names',
            colorscale='Viridis',
            colorbar_title="Connection Count",
        ))
        geoip_fig.update_layout(
            title="Geographic IP Distribution (Placeholder)",
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='equirectangular'
            ),
            template="plotly_dark"
        )
    except Exception as e:
        print(f"Error generating GeoIP graph: {e}")
        geoip_fig = go.Figure().add_annotation(
            text=f"Error generating GeoIP graph: {e}",
            showarrow=False,
            font=dict(color="red")
        )
    
    return network_fig, alerts_fig, timeseries_fig, geoip_fig


# Run the app
if __name__ == "__main__":
    print("Starting SentinelX Dashboard Example...")
    print("Open your browser and navigate to http://localhost:8050")
    app.run_server(debug=True, port=8050)