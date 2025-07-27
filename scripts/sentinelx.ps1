# SentinelX PowerShell Script
# This script provides shortcuts for common SentinelX operations

param (
    [Parameter(Position=0)]
    [string]$Command,
    
    [Parameter(Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

# Set the root directory
$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Change to the root directory
Set-Location $RootDir

# Define functions for each command
function Show-Help {
    Write-Host "SentinelX - AI-Powered Cyber Threat Intelligence System"
    Write-Host ""
    Write-Host "Usage: .\scripts\sentinelx.ps1 [command] [options]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  setup         Install dependencies and set up the environment"
    Write-Host "  train         Train a model"
    Write-Host "  evaluate      Evaluate a model"
    Write-Host "  monitor       Start network monitoring"
    Write-Host "  api           Start the API server"
    Write-Host "  docker-build  Build the Docker image"
    Write-Host "  docker-run    Run the Docker container"
    Write-Host "  docker-stop   Stop the Docker container"
    Write-Host "  help          Show this help message"
    Write-Host ""
    Write-Host "For more information, run: .\scripts\sentinelx.ps1 [command] --help"
}

function Setup {
    Write-Host "Setting up SentinelX..."
    
    # Check if Python is installed
    try {
        $pythonVersion = python --version
        Write-Host "Found $pythonVersion"
    } catch {
        Write-Host "Error: Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
        exit 1
    }
    
    # Install dependencies
    Write-Host "Installing dependencies..."
    pip install -r requirements.txt
    
    # Create necessary directories
    if (-not (Test-Path "$RootDir\data")) {
        New-Item -ItemType Directory -Path "$RootDir\data" | Out-Null
    }
    
    if (-not (Test-Path "$RootDir\logs")) {
        New-Item -ItemType Directory -Path "$RootDir\logs" | Out-Null
    }
    
    Write-Host "Setup complete!" -ForegroundColor Green
}

function Train {
    $modelType = "random_forest"
    $dataset = $null
    
    # Parse arguments
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -eq "--model" -and $i+1 -lt $Arguments.Count) {
            $modelType = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--dataset" -and $i+1 -lt $Arguments.Count) {
            $dataset = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--help") {
            Write-Host "Usage: .\scripts\sentinelx.ps1 train [options]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --model MODEL    Model type to use (default: random_forest)"
            Write-Host "  --dataset PATH   Path to dataset (optional)"
            Write-Host "  --help           Show this help message"
            return
        }
    }
    
    Write-Host "Training $modelType model..."
    
    $trainArgs = "train --model $modelType"
    if ($dataset) {
        $trainArgs += " --dataset $dataset"
    }
    
    python "$RootDir\scripts\sentinelx_cli.py" $trainArgs.Split(" ")
}

function Evaluate {
    $modelType = "random_forest"
    $dataset = $null
    
    # Parse arguments
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -eq "--model" -and $i+1 -lt $Arguments.Count) {
            $modelType = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--dataset" -and $i+1 -lt $Arguments.Count) {
            $dataset = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--help") {
            Write-Host "Usage: .\scripts\sentinelx.ps1 evaluate [options]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --model MODEL    Model type to use (default: random_forest)"
            Write-Host "  --dataset PATH   Path to dataset (optional)"
            Write-Host "  --help           Show this help message"
            return
        }
    }
    
    Write-Host "Evaluating $modelType model..."
    
    $evalArgs = "evaluate --model $modelType"
    if ($dataset) {
        $evalArgs += " --dataset $dataset"
    }
    
    python "$RootDir\scripts\sentinelx_cli.py" $evalArgs.Split(" ")
}

function Monitor {
    $interface = $null
    
    # Parse arguments
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -eq "--interface" -and $i+1 -lt $Arguments.Count) {
            $interface = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--help") {
            Write-Host "Usage: .\scripts\sentinelx.ps1 monitor [options]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --interface INTERFACE   Network interface to monitor"
            Write-Host "  --help                  Show this help message"
            return
        }
    }
    
    $monitorArgs = "monitor"
    if ($interface) {
        $monitorArgs += " --interface $interface"
    }
    
    python "$RootDir\scripts\sentinelx_cli.py" $monitorArgs.Split(" ")
}

function StartAPI {
    $port = 8000
    
    # Parse arguments
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -eq "--port" -and $i+1 -lt $Arguments.Count) {
            $port = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--help") {
            Write-Host "Usage: .\scripts\sentinelx.ps1 api [options]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --port PORT   Port to run the API server on (default: 8000)"
            Write-Host "  --help        Show this help message"
            return
        }
    }
    
    Write-Host "Starting API server on port $port..."
    
    # Set environment variables
    $env:PORT = $port
    
    # Start the API server
    python "$RootDir\src\api\api_server.py"
}

function DockerBuild {
    Write-Host "Building Docker image..."
    docker build -t sentinelx .
}

function DockerRun {
    $port = 8000
    
    # Parse arguments
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        if ($Arguments[$i] -eq "--port" -and $i+1 -lt $Arguments.Count) {
            $port = $Arguments[$i+1]
            $i++
        } elseif ($Arguments[$i] -eq "--help") {
            Write-Host "Usage: .\scripts\sentinelx.ps1 docker-run [options]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "  --port PORT   Port to map the API server to (default: 8000)"
            Write-Host "  --help        Show this help message"
            return
        }
    }
    
    Write-Host "Running Docker container on port $port..."
    docker run -d --name sentinelx -p ${port}:8000 -v "${RootDir}\config:/app/config" -v "${RootDir}\data:/app/data" -v "${RootDir}\logs:/app/logs" sentinelx
}

function DockerStop {
    Write-Host "Stopping Docker container..."
    docker stop sentinelx
    docker rm sentinelx
}

# Execute the command
switch ($Command) {
    "setup" { Setup }
    "train" { Train }
    "evaluate" { Evaluate }
    "monitor" { Monitor }
    "api" { StartAPI }
    "docker-build" { DockerBuild }
    "docker-run" { DockerRun }
    "docker-stop" { DockerStop }
    "help" { Show-Help }
    "" { Show-Help }
    default { 
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Write-Host "Run '.\scripts\sentinelx.ps1 help' for usage information."
    }
}