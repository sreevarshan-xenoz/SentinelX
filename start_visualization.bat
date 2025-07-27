@echo off
echo SentinelX Visualization Tools
echo ============================
echo.

:menu
echo Choose an option:
echo 1. Start Web Dashboard
echo 2. Run CLI Tool
echo 3. Exit
echo.

set /p choice=Enter your choice (1-3): 

if "%choice%"=="1" goto web
if "%choice%"=="2" goto cli
if "%choice%"=="3" goto end

echo Invalid choice. Please try again.
echo.
goto menu

:web
echo.
echo Starting SentinelX Web Dashboard...
echo.
echo The dashboard will be available at http://localhost:8050
echo Press Ctrl+C to stop the server.
echo.
python -m src.visualization web
goto end

:cli
echo.
echo SentinelX CLI Tool
echo.
echo Available commands:
echo - network: Generate network graph visualization
echo - alerts: Generate alert dashboard visualization
echo - timeseries: Generate time series visualization
echo - heatmap: Generate heatmap visualization
echo - geomap: Generate geographic IP map visualization
echo - report: Generate comprehensive security report
echo - dashboard: Launch interactive web dashboard
echo.
echo Example: network --time-window 1h --format html --output network_graph.html
echo.
set /p cmd=Enter command (or 'back' to return to menu): 

if "%cmd%"=="back" goto menu

python -m src.visualization cli %cmd%
echo.
echo Press any key to continue...
pause > nul
goto cli

:end
echo.
echo Thank you for using SentinelX Visualization Tools.
echo.