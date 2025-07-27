@echo off
echo SentinelX Docker Deployment
echo ============================
echo.

:menu
echo Choose an option:
echo 1. Start All Services
echo 2. Start Web Dashboard Only
echo 3. Start Monitor Only
echo 4. Start API Only
echo 5. Stop All Services
echo 6. View Logs
echo 7. Exit
echo.

set /p choice=Enter your choice (1-7): 

if "%choice%"=="1" goto start_all
if "%choice%"=="2" goto start_web
if "%choice%"=="3" goto start_monitor
if "%choice%"=="4" goto start_api
if "%choice%"=="5" goto stop_all
if "%choice%"=="6" goto view_logs
if "%choice%"=="7" goto end

echo Invalid choice. Please try again.
echo.
goto menu

:start_all
echo.
echo Starting all SentinelX services...
docker-compose up -d
echo.
echo Services started. Web dashboard available at http://localhost:8050
echo API available at http://localhost:5000
echo.
echo Press any key to return to menu...
pause > nul
goto menu

:start_web
echo.
echo Starting SentinelX Web Dashboard...
docker-compose up -d sentinelx-web
echo.
echo Web dashboard started. Available at http://localhost:8050
echo.
echo Press any key to return to menu...
pause > nul
goto menu

:start_monitor
echo.
echo Starting SentinelX Monitor...
docker-compose up -d sentinelx-monitor
echo.
echo Monitor service started.
echo.
echo Press any key to return to menu...
pause > nul
goto menu

:start_api
echo.
echo Starting SentinelX API...
docker-compose up -d sentinelx-api
echo.
echo API service started. Available at http://localhost:5000
echo.
echo Press any key to return to menu...
pause > nul
goto menu

:stop_all
echo.
echo Stopping all SentinelX services...
docker-compose down
echo.
echo All services stopped.
echo.
echo Press any key to return to menu...
pause > nul
goto menu

:view_logs
echo.
echo Viewing SentinelX logs (press Ctrl+C to exit)...
echo.
docker-compose logs -f
goto menu

:end
echo.
echo Thank you for using SentinelX.
echo.