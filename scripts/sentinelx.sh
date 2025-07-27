#!/bin/bash
# SentinelX Shell Script
# This script provides shortcuts for common SentinelX operations

# Set the root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

# Change to the root directory
cd "$ROOT_DIR"

# Define functions for each command
show_help() {
    echo "SentinelX - AI-Powered Cyber Threat Intelligence System"
    echo ""
    echo "Usage: ./scripts/sentinelx.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  setup         Install dependencies and set up the environment"
    echo "  train         Train a model"
    echo "  evaluate      Evaluate a model"
    echo "  monitor       Start network monitoring"
    echo "  api           Start the API server"
    echo "  docker-build  Build the Docker image"
    echo "  docker-run    Run the Docker container"
    echo "  docker-stop   Stop the Docker container"
    echo "  help          Show this help message"
    echo ""
    echo "For more information, run: ./scripts/sentinelx.sh [command] --help"
}

setup() {
    echo "Setting up SentinelX..."
    
    # Check if Python is installed
    if command -v python3 &>/dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &>/dev/null; then
        PYTHON_CMD="python"
    else
        echo "Error: Python not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    echo "Found $($PYTHON_CMD --version)"
    
    # Install dependencies
    echo "Installing dependencies..."
    $PYTHON_CMD -m pip install -r requirements.txt
    
    # Create necessary directories
    mkdir -p "$ROOT_DIR/data"
    mkdir -p "$ROOT_DIR/logs"
    
    echo "Setup complete!"
}

train() {
    MODEL_TYPE="random_forest"
    DATASET=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --model)
                MODEL_TYPE="$2"
                shift 2
                ;;
            --dataset)
                DATASET="$2"
                shift 2
                ;;
            --help)
                echo "Usage: ./scripts/sentinelx.sh train [options]"
                echo ""
                echo "Options:"
                echo "  --model MODEL    Model type to use (default: random_forest)"
                echo "  --dataset PATH   Path to dataset (optional)"
                echo "  --help           Show this help message"
                return
                ;;
            *)
                shift
                ;;
        esac
    done
    
    echo "Training $MODEL_TYPE model..."
    
    TRAIN_ARGS="train --model $MODEL_TYPE"
    if [[ -n "$DATASET" ]]; then
        TRAIN_ARGS="$TRAIN_ARGS --dataset $DATASET"
    fi
    
    python "$ROOT_DIR/scripts/sentinelx_cli.py" $TRAIN_ARGS
}

evaluate() {
    MODEL_TYPE="random_forest"
    DATASET=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --model)
                MODEL_TYPE="$2"
                shift 2
                ;;
            --dataset)
                DATASET="$2"
                shift 2
                ;;
            --help)
                echo "Usage: ./scripts/sentinelx.sh evaluate [options]"
                echo ""
                echo "Options:"
                echo "  --model MODEL    Model type to use (default: random_forest)"
                echo "  --dataset PATH   Path to dataset (optional)"
                echo "  --help           Show this help message"
                return
                ;;
            *)
                shift
                ;;
        esac
    done
    
    echo "Evaluating $MODEL_TYPE model..."
    
    EVAL_ARGS="evaluate --model $MODEL_TYPE"
    if [[ -n "$DATASET" ]]; then
        EVAL_ARGS="$EVAL_ARGS --dataset $DATASET"
    fi
    
    python "$ROOT_DIR/scripts/sentinelx_cli.py" $EVAL_ARGS
}

monitor() {
    INTERFACE=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface)
                INTERFACE="$2"
                shift 2
                ;;
            --help)
                echo "Usage: ./scripts/sentinelx.sh monitor [options]"
                echo ""
                echo "Options:"
                echo "  --interface INTERFACE   Network interface to monitor"
                echo "  --help                  Show this help message"
                return
                ;;
            *)
                shift
                ;;
        esac
    done
    
    MONITOR_ARGS="monitor"
    if [[ -n "$INTERFACE" ]]; then
        MONITOR_ARGS="$MONITOR_ARGS --interface $INTERFACE"
    fi
    
    python "$ROOT_DIR/scripts/sentinelx_cli.py" $MONITOR_ARGS
}

start_api() {
    PORT=8000
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                PORT="$2"
                shift 2
                ;;
            --help)
                echo "Usage: ./scripts/sentinelx.sh api [options]"
                echo ""
                echo "Options:"
                echo "  --port PORT   Port to run the API server on (default: 8000)"
                echo "  --help        Show this help message"
                return
                ;;
            *)
                shift
                ;;
        esac
    done
    
    echo "Starting API server on port $PORT..."
    
    # Set environment variables
    export PORT=$PORT
    
    # Start the API server
    python "$ROOT_DIR/src/api/api_server.py"
}

docker_build() {
    echo "Building Docker image..."
    docker build -t sentinelx .
}

docker_run() {
    PORT=8000
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                PORT="$2"
                shift 2
                ;;
            --help)
                echo "Usage: ./scripts/sentinelx.sh docker-run [options]"
                echo ""
                echo "Options:"
                echo "  --port PORT   Port to map the API server to (default: 8000)"
                echo "  --help        Show this help message"
                return
                ;;
            *)
                shift
                ;;
        esac
    done
    
    echo "Running Docker container on port $PORT..."
    docker run -d --name sentinelx -p ${PORT}:8000 \
        -v "${ROOT_DIR}/config:/app/config" \
        -v "${ROOT_DIR}/data:/app/data" \
        -v "${ROOT_DIR}/logs:/app/logs" \
        sentinelx
}

docker_stop() {
    echo "Stopping Docker container..."
    docker stop sentinelx
    docker rm sentinelx
}

# Execute the command
COMMAND="$1"
shift

case "$COMMAND" in
    setup)
        setup
        ;;
    train)
        train "$@"
        ;;
    evaluate)
        evaluate "$@"
        ;;
    monitor)
        monitor "$@"
        ;;
    api)
        start_api "$@"
        ;;
    docker-build)
        docker_build
        ;;
    docker-run)
        docker_run "$@"
        ;;
    docker-stop)
        docker_stop
        ;;
    help)
        show_help
        ;;
    "")
        show_help
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Run './scripts/sentinelx.sh help' for usage information."
        exit 1
        ;;
esac