#!/usr/bin/env python3
"""
SentinelX Configuration Generator

This script generates a default configuration file for SentinelX based on the template.
It allows customization of key settings through command-line arguments.
"""

import os
import sys
import json
import argparse
import secrets
import hashlib
import getpass
from pathlib import Path

# Add the parent directory to the path so we can import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def generate_password_hash(password):
    """
    Generate a simple password hash using SHA-256.
    In a production environment, use a more secure method like bcrypt.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def generate_jwt_secret():
    """
    Generate a random JWT secret.
    """
    return secrets.token_hex(32)

def load_template(template_path):
    """
    Load the configuration template.
    """
    try:
        with open(template_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Template file is not valid JSON")
        sys.exit(1)

def save_config(config, output_path):
    """
    Save the configuration to a file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    try:
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to {output_path}")
    except Exception as e:
        print(f"Error saving configuration: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Generate SentinelX configuration')
    parser.add_argument('--template', default='config/config.json.template',
                        help='Path to the configuration template')
    parser.add_argument('--output', default='config/config.json',
                        help='Path to save the generated configuration')
    parser.add_argument('--interface', default='eth0',
                        help='Network interface to capture')
    parser.add_argument('--db-path', default='data/sentinelx.db',
                        help='Path to the database file')
    parser.add_argument('--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Logging level')
    parser.add_argument('--api-host', default='127.0.0.1',
                        help='API server host')
    parser.add_argument('--api-port', type=int, default=5000,
                        help='API server port')
    parser.add_argument('--dashboard-host', default='127.0.0.1',
                        help='Web dashboard host')
    parser.add_argument('--dashboard-port', type=int, default=8050,
                        help='Web dashboard port')
    parser.add_argument('--create-admin', action='store_true',
                        help='Create an admin user')
    parser.add_argument('--admin-username', default='admin',
                        help='Admin username')
    parser.add_argument('--company-name', default='Your Company',
                        help='Company name for reports')
    
    args = parser.parse_args()
    
    # Load the template
    template_path = Path(args.template).resolve()
    config = load_template(template_path)
    
    # Update configuration with command-line arguments
    config['general']['log_level'] = args.log_level
    config['network']['interfaces'] = [args.interface]
    config['storage']['db_path'] = args.db_path
    config['api']['host'] = args.api_host
    config['api']['port'] = args.api_port
    config['visualization']['web_dashboard']['host'] = args.dashboard_host
    config['visualization']['web_dashboard']['port'] = args.dashboard_port
    config['visualization']['reports']['company_name'] = args.company_name
    
    # Generate a JWT secret
    config['api']['auth']['jwt_secret'] = generate_jwt_secret()
    
    # Create admin user if requested
    if args.create_admin:
        admin_password = getpass.getpass("Enter admin password: ")
        config['api']['auth']['users'][0]['username'] = args.admin_username
        config['api']['auth']['users'][0]['password_hash'] = generate_password_hash(admin_password)
    
    # Save the configuration
    output_path = Path(args.output).resolve()
    save_config(config, output_path)
    
    print("\nConfiguration generated successfully!")
    print("\nNext steps:")
    print("1. Review the configuration file and make any additional changes")
    print("2. Start SentinelX with the new configuration")
    print("   - Web Dashboard: python -m src.visualization web")
    print("   - CLI Tool: python -m src.visualization cli")
    print("   - Docker: docker-compose up -d")

if __name__ == '__main__':
    main()