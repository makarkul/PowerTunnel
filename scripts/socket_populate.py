#!/usr/bin/env python3
"""
Socket-based PowerTunnel cache population script
Uses direct socket control for more reliable data transfer
"""

import socket
import time
import os
import json
import subprocess
import sys

def populate_jellyfin_video_cache(video_path, item_id, api_key, proxy_url="http://localhost:8081"):
    """Populate the cache for a Jellyfin video using direct socket control"""
    
    # Extract host and port from proxy_url
    if proxy_url.startswith("http://"):
        proxy_url = proxy_url[7:]  # Remove http:// prefix
    
    host, port_str = proxy_url.split(":")
    port = int(port_str)
    
    print(f"Populating cache with {os.path.basename(video_path)} ({os.path.getsize(video_path)} bytes)")
    print(f"Using Jellyfin item ID: {item_id}")
    
    # Create the target path that matches what the player uses
    target_path = f"/Videos/{item_id}/stream.mp4?videoId={item_id}&mediasourceid={item_id}&static=true"
    
    # Open the file for reading in binary mode
    with open(video_path, 'rb') as f:
        file_size = os.path.getsize(video_path)
        
        # Create the HTTP request headers
        http_headers = (
            f"POST /cache/populate HTTP/1.1\r\n"
            f"Host: 10.0.2.2:8096\r\n"
            f"Target-Path: {target_path}\r\n"
            f"Content-Type: video/mp4\r\n"
            f"Content-Length: {file_size}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        print(f"Headers:")
        for line in http_headers.decode('utf-8').split('\r\n'):
            if line:
                print(f"  {line}")
        
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # Connect to the server
            print(f"Connecting to {host}:{port}...")
            s.connect((host, port))
            
            # Set socket options for better performance
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)  # 128KB receive buffer
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)        # Disable Nagle's algorithm
            
            # Send the HTTP headers
            print("Sending HTTP headers...")
            s.sendall(http_headers)
            
            # Small delay before sending data
            print("Adding a small delay before sending data...")
            time.sleep(0.5)
            
            # Send the file data in chunks
            chunk_size = 64 * 1024  # 64KB chunks
            total_sent = 0
            
            print(f"Sending data in {chunk_size//1024}KB chunks with small delays...")
            start_time = time.time()
            
            # Read and send the file in chunks
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                bytes_sent = s.send(chunk)
                total_sent += bytes_sent
                
                # Log progress every 10 chunks or at the end
                if (total_sent // chunk_size) % 10 == 0 or total_sent == file_size:
                    print(f"Sent {total_sent//(1024*1024)}MB of {file_size//(1024*1024)}MB ({int(total_sent*100/file_size)}%)")
                
                # Small delay between chunks to avoid overwhelming the server
                time.sleep(0.01)  # 10ms delay
            
            # Calculate and display metrics
            elapsed = time.time() - start_time
            transfer_rate = file_size / (1024 * 1024 * elapsed) if elapsed > 0 else 0
            print(f"Data sending completed in {elapsed:.2f} seconds ({transfer_rate:.2f} MB/s)")
            
            # Wait for response
            print("Waiting for response...")
            s.settimeout(30)  # 30 second timeout for receiving
            
            # Read the response
            response = b""
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    print("Socket timeout while reading response")
                    break
            
            # Parse and display the response
            response_str = response.decode('utf-8', errors='replace')
            print("\nResponse:")
            print("=" * 40)
            print(response_str[:500])  # Show first 500 chars
            print("=" * 40)
            
            # Check if it was successful
            if "200 OK" in response_str and "success" in response_str:
                print(f"Video cached at URL: http://10.0.2.2:8096{target_path}")
                return True
            else:
                print("Cache population failed!")
                return False
                
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            # Close the socket
            s.close()

def check_cache_status(proxy_url="http://localhost:8081"):
    """Check the cache status via the admin API"""
    try:
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Extract host and port from proxy_url
        if proxy_url.startswith("http://"):
            proxy_url = proxy_url[7:]  # Remove http:// prefix
        
        host, port_str = proxy_url.split(":")
        port = int(port_str)
        
        # Connect to the server
        s.connect((host, port))
        
        # Send the HTTP request
        request = (
            "GET /cache/status HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode('utf-8')
        
        s.sendall(request)
        
        # Read the response
        response = b""
        s.settimeout(5)
        
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        
        # Parse the response
        response_str = response.decode('utf-8', errors='replace')
        
        # Extract the JSON part
        if "200 OK" in response_str and "{" in response_str:
            json_start = response_str.find("{")
            json_str = response_str[json_start:]
            return json_str
        else:
            return "Error: Could not parse response"
            
    except Exception as e:
        return f"Error: {e}"
    finally:
        s.close()

def verify_cache_files():
    """Verify cache files on the device using ADB"""
    print("\nVerifying cache by checking cache files directly...\n")
    
    # Run ADB command to list all cache files
    print("Running command to list all cache files:")
    cmd = ["adb", "shell", "run-as", "io.github.krlvm.powertunnel.android.dev", 
           "find", "/data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel", 
           "-type", "f", "-not", "-name", "*.tmp", "-not", "-name", "*.meta"]
    
    print(" ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0 and result.stdout.strip():
        print("\nFound cache files:")
        for line in result.stdout.strip().split('\n'):
            print(f"  {line}")
        
        # Get file size
        size_cmd = ["adb", "shell", "run-as", "io.github.krlvm.powertunnel.android.dev", 
                   "ls", "-la", result.stdout.strip().split('\n')[0]]
        size_result = subprocess.run(size_cmd, capture_output=True, text=True)
        
        if size_result.returncode == 0:
            print("\nCache file details:")
            print(size_result.stdout.strip())
        
        return True
    else:
        print("❌ No cache files found or error running command")
        if result.stderr:
            print(f"Error: {result.stderr}")
        return False

def main():
    """Main function"""
    # Configuration
    api_key = "c725ae3221e248019261c1a9aaea0cbb"
    
    # Check if PowerTunnel admin server is running
    status = check_cache_status()
    print(f"Admin server is running. Status: {status}\n")
    
    # Define videos to cache
    videos = [
        {
            "name": "5s Sample Video",
            "path": "/Users/makarand/PowerTunnel/scripts/media/SampleVideo (2024)_05s.mp4",
            "item_id": "8f212c2c56d0a5b6c2247bb7e7c0e4f8",
            "enabled": False  # Disable the 5s video
        },
        {
            "name": "30s Sample Video",
            "path": "/Users/makarand/PowerTunnel/scripts/media/SampleVideo (2024)_30s.mp4",
            "item_id": "9e323d3d67e1b6c7d3358cc8f8d1f5e9",
            "enabled": True
        }
    ]
    
    # Process each video
    for video in videos:
        if not video.get("enabled", True):
            print(f"Skipping {video['name']} (disabled)")
            continue
            
        print(f"\nProcessing {video['name']} - {os.path.basename(video['path'])}...")
        success = populate_jellyfin_video_cache(video['path'], video['item_id'], api_key)
        print(f"Cache population for {video['name']}: {'successful' if success else 'failed'}")
    
    # Check cache status after population
    status = check_cache_status()
    print(f"\nCache status: {status}")
    
    # Verify cache files
    verify_cache_files()

if __name__ == "__main__":
    main()
