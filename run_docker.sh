#!/bin/bash

echo "SentinelX Docker Deployment"
echo "============================"
echo ""

while true; do
    echo "Choose an option:"
    echo "1. Start All Services"
    echo "2. Start Web Dashboard Only"
    echo "3. Start Monitor Only"
    echo "4. Start API Only"
    echo "5. Stop All Services"
    echo "6. View Logs"
    echo "7. Exit"
    echo ""
    
    read -p "Enter your choice (1-7): " choice
    
    case $choice in
        1)
            echo ""
            echo "Starting all SentinelX services..."
            docker-compose up -d
            echo ""
            echo "Services started. Web dashboard available at http://localhost:8050"
            echo "API available at http://localhost:5000"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        2)
            echo ""
            echo "Starting SentinelX Web Dashboard..."
            docker-compose up -d sentinelx-web
            echo ""
            echo "Web dashboard started. Available at http://localhost:8050"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        3)
            echo ""
            echo "Starting SentinelX Monitor..."
            docker-compose up -d sentinelx-monitor
            echo ""
            echo "Monitor service started."
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        4)
            echo ""
            echo "Starting SentinelX API..."
            docker-compose up -d sentinelx-api
            echo ""
            echo "API service started. Available at http://localhost:5000"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        5)
            echo ""
            echo "Stopping all SentinelX services..."
            docker-compose down
            echo ""
            echo "All services stopped."
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        6)
            echo ""
            echo "Viewing SentinelX logs (press Ctrl+C to exit)..."
            echo ""
            docker-compose logs -f
            ;;
        7)
            echo ""
            echo "Thank you for using SentinelX."
            echo ""
            break
            ;;
        *)
            echo "Invalid choice. Please try again."
            echo ""
            ;;
    esac
done