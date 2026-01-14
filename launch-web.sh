#!/bin/bash

# One-Click Web Scanner Launcher
# Automatically sets up and launches the web interface

echo "================================================================="
echo "  Smart Vulnerability Scanner v2.0 - Web Interface Launcher"
echo "  Google-Level Scanner with One-Click Automation"
echo "================================================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    echo "Please install Python 3.7+ first"
    exit 1
fi

echo "✓ Python 3 detected"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ Error: pip3 is not installed"
    echo "Please install pip3 first"
    exit 1
fi

echo "✓ pip3 detected"

# Install/upgrade dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install -q flask flask-cors requests 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "⚠️  Some dependencies may need manual installation"
    echo "Run: pip3 install flask flask-cors requests"
fi

echo ""
echo "🚀 Starting web server..."
echo ""
echo "================================================================="
echo "  🌐 Web Interface Available At:"
echo "  👉 http://localhost:5000"
echo "================================================================="
echo ""
echo "  📱 Opening browser automatically..."
echo "  🛑 Press Ctrl+C to stop the server"
echo ""

# Try to open browser
sleep 2
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:5000 &>/dev/null &
elif command -v open &> /dev/null; then
    open http://localhost:5000 &>/dev/null &
elif command -v start &> /dev/null; then
    start http://localhost:5000 &>/dev/null &
else
    echo "  ℹ️  Please open http://localhost:5000 in your browser"
fi

# Start the web server
cd web
python3 app.py
