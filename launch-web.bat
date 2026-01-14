@echo off
REM One-Click Web Scanner Launcher for Windows
REM Automatically sets up and launches the web interface

echo =================================================================
echo   Smart Vulnerability Scanner v2.0 - Web Interface Launcher
echo   Google-Level Scanner with One-Click Automation
echo =================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo X Error: Python is not installed
    echo Please install Python 3.7+ from python.org
    pause
    exit /b 1
)

echo [OK] Python detected

REM Install dependencies
echo.
echo Installing dependencies...
pip install -q flask flask-cors requests

if errorlevel 1 (
    echo Warning: Some dependencies may need manual installation
    echo Run: pip install flask flask-cors requests
)

echo [OK] Dependencies installed

echo.
echo Starting web server...
echo.
echo =================================================================
echo   Web Interface Available At:
echo   http://localhost:5000
echo =================================================================
echo.
echo   Opening browser automatically...
echo   Press Ctrl+C to stop the server
echo.

REM Wait a moment then open browser
timeout /t 2 /nobreak >nul
start http://localhost:5000

REM Start the web server
cd web
python app.py
