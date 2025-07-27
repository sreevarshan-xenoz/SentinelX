# SentinelX Configuration

This directory contains configuration files for the SentinelX application.

## Configuration Files

- `config.json`: Main configuration file for SentinelX
- `config.json.template`: Template configuration file with default values

## Setup

To set up your configuration:

1. Copy the template file to create your configuration:
   ```
   cp config.json.template config.json
   ```

2. Edit the `config.json` file to customize settings for your environment:
   - Update network interfaces
   - Configure storage settings
   - Set up alert notifications
   - Customize visualization settings
   - Add API authentication
   - Configure integrations

## Configuration Sections

### General

Basic application settings including logging and data directories.

### Network

Settings for network capture, including interfaces and capture options.

### Storage

Database configuration and data retention policies.

### Analysis

Settings for traffic analysis, AI models, and detection thresholds.

### Alerts

Notification settings for email, webhooks, and syslog.

### API

API server configuration, authentication, and access control.

### Visualization

Settings for the web dashboard and visualization components.

### Integrations

Configuration for external integrations like MITRE ATT&CK and threat intelligence feeds.

## Security Notes

- Never commit `config.json` with sensitive information to version control
- Change default passwords and JWT secrets
- Use environment variables for sensitive values in production
- Restrict API access to trusted networks