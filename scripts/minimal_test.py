#!/usr/bin/env python3
"""
Minimal test script for PowerTunnel cache population
Uses a very small file and simple HTTP request to test server-side changes
"""

import requests
import time
import os

def main():
    # Configuration
    proxy_url = "http://localhost:8081"
    item_id = "8f212c2c56d0a5b6c2247bb7e7c0e4f8"
    
    # Create a very small test file (10KB)
    test_data = b'X' * 10240  # 10KB of data
    
    # Basic headers
    headers = {
        'Host': '10.0.2.2:8096',
        'Target-Path': f'/Videos/{item_id}/stream.mp4?videoId={item_id}&mediasourceid={item_id}&static=true',
        'Content-Type': 'video/mp4',
        'Content-Length': str(len(test_data))
    }
    
    print(f"Test data size: {len(test_data)} bytes")
    print(f"Headers: {headers}")
    
    # Create a session
    session = requests.Session()
    
    # Add a small delay before sending
    print("Adding a small delay before sending...")
    time.sleep(0.5)
    
    # Send the request with minimal data
    print("Sending data as a single non-chunked request...")
    start_time = time.time()
    
    try:
        response = session.post(
            f"{proxy_url}/cache/populate",
            headers=headers,
            data=test_data,
            timeout=30  # 30 second timeout
        )
        
        # Calculate and display metrics
        elapsed = time.time() - start_time
        print(f"Request completed in {elapsed:.2f} seconds")
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text[:100]}")  # Show first 100 chars
        
        # Check cache status
        status_response = session.get(f"{proxy_url}/cache/status")
        print(f"\nCache status: {status_response.text}")
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    main()
