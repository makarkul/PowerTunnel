#!/bin/bash
# Script to test cache population and status

echo "Setting up port forwarding..."
adb forward tcp:8081 tcp:8081

echo "Checking initial cache status..."
curl -s http://localhost:8081/cache/status | python3 -m json.tool

echo -e "\nPopulating cache with test video..."
python3 debug_populate.py

echo -e "\nChecking cache status after population..."
curl -s http://localhost:8081/cache/status | python3 -m json.tool

echo -e "\nListing cache directory on device..."
adb shell "ls -la /data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel"

echo -e "\nDone!"
