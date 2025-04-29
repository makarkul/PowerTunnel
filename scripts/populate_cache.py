#!/usr/bin/env python3
import os
import requests
import sys
import time
import logging
import http.client as http_client

# Set up detailed HTTP logging
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

def populate_jellyfin_video_cache(video_path, item_id, api_key, proxy_url="http://localhost:8081"):
    """
    Pre-populate the PowerTunnel cache with a Jellyfin video file
    
    Args:
        video_path: Path to the local video file to cache
        item_id: Jellyfin item ID for the video
        api_key: Jellyfin API key for authentication
        proxy_url: URL of the PowerTunnel admin server
    """
    # Extract filename for logging
    filename = os.path.basename(video_path)
    
    # Jellyfin server details - using the Android emulator address that the player uses
    jellyfin_host = "10.0.2.2:8096"
    
    # Create the exact path that matches the Jellyfin URL format used by the player
    target_path = f"/Videos/{item_id}/stream.mp4?videoId={item_id}&mediasourceid={item_id}&static=true"
    
    file_size = os.path.getsize(video_path)
    print(f"Populating cache with {filename} ({file_size} bytes)")
    print(f"Using Jellyfin item ID: {item_id}")
    
    # These headers match the actual Jellyfin request format
    headers = {
        "Host": jellyfin_host,
        "Target-Path": target_path,
        "Content-Type": "video/mp4"
        # Don't set Content-Length when streaming with chunked encoding
        # Python requests will automatically use chunked encoding
    }
    
    print("Headers:", headers)
    
    # Use a smaller chunk size for better progress reporting
    chunk_size = 1024 * 1024  # 1MB chunks
    
    # Open and stream the file in binary mode
    with open(video_path, 'rb') as f:
        # Load the entire file into memory for non-chunked transfer
        print("\n=== USING NON-CHUNKED APPROACH WITH EXPLICIT CONTENT-LENGTH ===\n")
        file_content = f.read()
        print(f"Read entire file into memory: {len(file_content)} bytes")
        
        # Set Content-Length header explicitly
        headers["Content-Length"] = str(len(file_content))
        
        print(f"Sending request to {proxy_url}/cache/populate...")
        start_time = time.time()
        
        try:
            # Use a session with a longer timeout
            session = requests.Session()
            session.timeout = (10, 300)  # 10s connect timeout, 5min read timeout
            
            # Debug the request format
            print("\n=== DEBUG REQUEST FORMAT ===")
            for k, v in headers.items():
                print(f"  {k}: {v}")
            print("Using chunked encoding: No (explicit Content-Length)")
            print("=== END DEBUG INFO ===\n")
            
            response = session.post(
                f"{proxy_url}/cache/populate",
                headers=headers,
                data=file_content
            )
            
            elapsed = time.time() - start_time
            rate = file_size / elapsed / 1024 / 1024 if elapsed > 0 else 0
            print(f"Request completed in {elapsed:.2f} seconds ({rate:.2f} MB/s)")
            print(f"Response status: {response.status_code}")
            print(f"Response body: {response.text}")
            
            # The URL that will be used for cache lookups
            cached_url = f"http://{jellyfin_host}{target_path}"
            print(f"Video cached at URL: {cached_url}")
            
            return response.status_code == 200
            
        except requests.exceptions.Timeout:
            print(f"ERROR: Request timed out after {time.time() - start_time:.2f} seconds")
            return False
        except Exception as e:
            print(f"ERROR: {e}")
            return False

def main():
    # Check if admin server is running
    try:
        status = requests.get("http://localhost:8081/cache/status", timeout=5)
        print(f"Admin server is running. Status: {status.text}")
    except:
        print("Admin server not running or not accessible")
        return
    
    media_dir = os.path.join(os.path.dirname(__file__), "media")
    
    # Sample videos with Jellyfin item IDs
    videos = [
        # Enable only the 5s sample video
        {
            "path": os.path.join(media_dir, "SampleVideo (2024)_05s.mp4"),
            "item_id": "8f212c2c56d0a5b6c2247bb7e7c0e4f8",
            "name": "5s Sample Video"
        },
        # Uncomment to enable the 30s sample video
        # {
        #     "path": os.path.join(media_dir, "SampleVideo (2024)_30s.mp4"),
        #     "item_id": "eeb4ac3febf10cbe8b94c54be76431df",
        #     "name": "30s Sample Video"
        # }
    ]
    
    # API key from the URLs
    api_key = "c725ae3221e248019261c1a9aaea0cbb"
    
    # Populate cache with the videos
    for video in videos:
        print(f"\nProcessing {video['name']} - {os.path.basename(video['path'])}...")
        success = populate_jellyfin_video_cache(video['path'], video['item_id'], api_key)
        print(f"Cache population for {video['name']}: {'successful' if success else 'failed'}")
    
    # Check cache status after population
    try:
        session = requests.Session()
        session.timeout = (10, 300)  # 10s connect timeout, 5min read timeout
        status_response = session.get(f"http://localhost:8081/cache/status")
        print(f"\nCache status: {status_response.text}")
    except Exception as e:
        print(f"Error checking cache status: {e}")
        
    # Verify cache by checking the cache files directly using ADB
    print("\nVerifying cache by checking cache files directly...")
    try:
        # Use subprocess to run ADB commands
        import subprocess
        
        # Check the cache directory structure
        cmd = ["adb", "shell", "run-as", "io.github.krlvm.powertunnel.android.dev", 
               "find", "/data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel", 
               "-type", "f", "-not", "-name", "*.tmp", "-not", "-name", "*.meta"]
        
        print("\nRunning command to list all cache files:")
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
                
            print("\n✅ Cache files verified on disk")
        else:
            print("\n❌ No cache files found or error running command")
            if result.stderr:
                print(f"Error: {result.stderr}")
    except Exception as e:
        print(f"Error verifying cache: {e}")

if __name__ == "__main__":
    main()
