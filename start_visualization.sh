#!/bin/bash

echo "SentinelX Visualization Tools"
echo "============================"
echo ""

while true; do
    echo "Choose an option:"
    echo "1. Start Web Dashboard"
    echo "2. Run CLI Tool"
    echo "3. Exit"
    echo ""
    
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1)
            echo ""
            echo "Starting SentinelX Web Dashboard..."
            echo ""
            echo "The dashboard will be available at http://localhost:8050"
            echo "Press Ctrl+C to stop the server."
            echo ""
            python -m src.visualization web
            break
            ;;
        2)
            while true; do
                echo ""
                echo "SentinelX CLI Tool"
                echo ""
                echo "Available commands:"
                echo "- network: Generate network graph visualization"
                echo "- alerts: Generate alert dashboard visualization"
                echo "- timeseries: Generate time series visualization"
                echo "- heatmap: Generate heatmap visualization"
                echo "- geomap: Generate geographic IP map visualization"
                echo "- report: Generate comprehensive security report"
                echo "- dashboard: Launch interactive web dashboard"
                echo ""
                echo "Example: network --time-window 1h --format html --output network_graph.html"
                echo ""
                read -p "Enter command (or 'back' to return to menu): " cmd
                
                if [ "$cmd" = "back" ]; then
                    break
                fi
                
                python -m src.visualization cli $cmd
                echo ""
                read -p "Press Enter to continue..."
            done
            ;;
        3)
            echo ""
            echo "Thank you for using SentinelX Visualization Tools."
            echo ""
            break
            ;;
        *)
            echo "Invalid choice. Please try again."
            echo ""
            ;;
    esac
done