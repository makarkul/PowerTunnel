#!/bin/bash
# Script to test cache population and status

set -e  # Exit immediately if a command exits with a non-zero status

# Function to handle errors
handle_error() {
    echo "ERROR: Script failed at line $1"
    exit 1
}

# Set up error trap
trap 'handle_error $LINENO' ERR

# Directory for virtual environment
VENV_DIR=".venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create and activate virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment. Make sure python3-venv is installed."
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install required packages
echo "Installing required packages..."
pip install requests

# Check if the PowerTunnel app is running
echo "Checking if PowerTunnel is running..."
adb shell "pidof io.github.krlvm.powertunnel.android.dev" > /dev/null
if [ $? -ne 0 ]; then
    echo "ERROR: PowerTunnel app is not running. Please start the app and enable VPN mode."
    exit 1
fi

echo "Setting up port forwarding..."
adb forward tcp:8081 tcp:8081

echo "Checking initial cache status..."
CACHE_STATUS=$(curl -s http://localhost:8081/cache/status)
if [ -z "$CACHE_STATUS" ]; then
    echo "ERROR: Failed to get cache status. Make sure the app is running and port forwarding is set up correctly."
    exit 1
fi
echo "$CACHE_STATUS" | python3 -m json.tool

echo -e "\nPopulating cache with test video..."
python3 populate_cache.py
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to populate cache."
    exit 1
fi

echo -e "\nChecking cache status after population..."
CACHE_STATUS=$(curl -s http://localhost:8081/cache/status)
echo "$CACHE_STATUS" | python3 -m json.tool

echo -e "\nListing cache directory on device..."
adb shell "run-as io.github.krlvm.powertunnel.android.dev ls -la /data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel"

# Deactivate virtual environment
deactivate

echo -e "\nDone!"
