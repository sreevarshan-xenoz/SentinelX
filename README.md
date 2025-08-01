# SentinelX

## AI-Powered Cyber Threat Intelligence System

SentinelX is an intelligent system that uses machine learning and AI to detect, enrich, and defend against cyber threats in real-time.

### Key Features

- 🧠 **AI-Powered Detection**: Uses machine learning models trained on IDS datasets to identify various attack types
- 🌐 **Threat Intelligence Integration**: Enriches alerts with data from sources like AlienVault OTX, AbuseIPDB, and VirusTotal
- 📡 **Real-Time Network Monitoring**: Captures and analyzes network traffic using scapy/pyshark
- 🔍 **Advanced Threat Analysis**: Utilizes LLMs to provide human-readable explanations and context for alerts
- 🛡️ **Automated Response**: Supports automated actions like IP blocking and security event logging
- 🔔 **Alert Management**: Comprehensive system for generating, storing, and managing security alerts
- 🌍 **MITRE ATT&CK Integration**: Maps alerts to MITRE ATT&CK techniques for better threat context
- 📊 **CVE Correlation**: Identifies relevant CVEs for detected threats
- 📱 **RESTful API**: Provides a comprehensive API for system interaction
- 💻 **Command-Line Interface**: Easy-to-use CLI for all system functions
- 📊 **Visualization Tools**: Advanced visualization components for network graphs, alerts, time series, heatmaps, and geographic maps
- 🌐 **Web Dashboard**: Interactive web-based dashboard for real-time monitoring and analysis

### Project Structure

```
SentinelX/
├── data/                  # Datasets and processed data
├── src/                   # Source code
│   ├── core/              # Core framework components
│   ├── data_layer/        # Data processing and feature extraction
│   ├── model_layer/       # ML models for threat detection
│   ├── threat_enrichment/ # Threat intelligence integration
│   ├── network/           # Live network integration
│   ├── api/               # API/CLI interface
│   ├── reasoning/         # GPT/LLM integration for smart reasoning
│   └── visualization/     # Visualization components and dashboard
├── tests/                 # Unit and integration tests
├── config/                # Configuration files
├── docs/                  # Documentation
└── scripts/               # Utility scripts
```

### Development Phases

1. ✅ **Core Framework Setup** - Configuration and logging management
2. ✅ **Data Layer + Preprocessing** - Dataset loading, preprocessing, and feature extraction
3. ✅ **Model Layer** - Machine learning models for intrusion detection
4. ✅ **Threat Enrichment Layer** - Integration with threat intelligence sources
5. ✅ **Live Network Integration** - Real-time packet capture and flow analysis
6. ✅ **API / CLI Interface** - RESTful API and command-line interface
7. ✅ **Smart Reasoning with GPT** - LLM-based threat analysis and contextualization
8. 🔄 **Containerization + Deployment** - Docker containerization and deployment

### Getting Started

#### Prerequisites

- Python 3.8+
- pip (Python package manager)
- Network interface for packet capture
- (Optional) API keys for threat intelligence services

#### Installation

1. Clone the repository:

```bash
git clone https://github.com/sreevarshan-xenoz/SentinelX.git
cd SentinelX
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure the system:

```bash
# Edit the configuration file with your settings
# (API keys, network interfaces, etc.)
```

#### Usage

##### Command-Line Interface

SentinelX provides a comprehensive CLI for all system functions:

```bash
# Train a model
python scripts/sentinelx_cli.py train --model random_forest

# Start network monitoring
python scripts/sentinelx_cli.py monitor --interface eth0

# List available network interfaces
python scripts/sentinelx_cli.py interfaces

# Show network statistics
python scripts/sentinelx_cli.py stats

# List alerts
python scripts/sentinelx_cli.py alerts list
```

##### Visualization CLI

SentinelX includes a dedicated visualization CLI for generating various visualizations:

```bash
# Show help
python -m src.visualization cli --help

# Generate a network graph
python -m src.visualization cli network --time-window 1h --format html --output network_graph.html

# Generate an alert dashboard
python -m src.visualization cli alerts --severity high --format json --output alerts.json

# Generate a time series plot
python -m src.visualization cli timeseries --metric packets --interval hour --format png --output traffic.png

# Generate a heatmap
python -m src.visualization cli heatmap --metric connections --x-axis source_ip --y-axis destination_port --format svg

# Generate a geographic IP map
python -m src.visualization cli geomap --format html --output geomap.html

# Generate a security report
python -m src.visualization cli report --type detailed --period day --format pdf --output security_report.pdf
```

##### Web Dashboard

SentinelX also provides an interactive web dashboard for real-time monitoring and analysis:

```bash
# Start the web dashboard
python -m src.visualization web --port 8050
```

Then open your browser and navigate to `http://localhost:8050`.

# Show details of a specific alert
python scripts/sentinelx_cli.py alert ALERT_ID

# Analyze an alert with LLM
python scripts/sentinelx_cli.py analyze ALERT_ID

# Generate a report for an alert
python scripts/sentinelx_cli.py report ALERT_ID --format markdown

# Enrich an IP address with threat intelligence
python scripts/sentinelx_cli.py enrich-ip 8.8.8.8
```

##### RESTful API

SentinelX also provides a RESTful API for integration with other systems:

```bash
# Start the API server
python src/api/api_server.py
```

The API will be available at `http://localhost:8000` by default. API documentation is available at `http://localhost:8000/docs`.

### License

MIT