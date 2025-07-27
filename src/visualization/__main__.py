#!/usr/bin/env python
# SentinelX Visualization Main Entry Point

import os
import sys
import argparse

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


def main():
    """Main entry point for SentinelX visualization tools."""
    parser = argparse.ArgumentParser(
        description="SentinelX Visualization Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add global arguments
    parser.add_argument(
        "--config", "-c",
        help="Path to SentinelX configuration file",
        default=None
    )
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Mode to run")
    
    # CLI mode
    cli_parser = subparsers.add_parser("cli", help="Run in CLI mode")
    cli_parser.add_argument(
        "cli_args",
        nargs="*",
        help="Arguments to pass to the CLI"
    )
    
    # Web mode
    web_parser = subparsers.add_parser("web", help="Run in web mode")
    web_parser.add_argument(
        "--port", "-p",
        help="Port to run the web server on",
        type=int,
        default=8050
    )
    web_parser.add_argument(
        "--debug", "-d",
        help="Run in debug mode",
        action="store_true"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle the mode
    if args.mode == "cli":
        # Import and run the CLI
        from src.visualization.cli import VisualizationCLI
        cli = VisualizationCLI()
        cli.run(args.cli_args)
    elif args.mode == "web":
        # Import and run the web app
        from src.visualization.web_app import DashboardApp
        app = DashboardApp(port=args.port, debug=args.debug)
        app.run()
    else:
        # Default to showing help
        parser.print_help()


if __name__ == "__main__":
    main()