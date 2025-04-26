#!/usr/bin/env python3
import os
import requests
import sys
import time

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
    
    # Jellyfin server details - using the actual server port from the URLs
    jellyfin_host = "localhost:8096"
    
    # Create the exact path that matches the Jellyfin URL format
    target_path = f"/Items/{item_id}/Download?api_key={api_key}"
    
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
    with open(video_path, "rb") as f:
        print(f"Sending request to {proxy_url}/cache/populate...")
        start_time = time.time()
        
        try:
            # Use a session with a longer timeout
            session = requests.Session()
            session.timeout = (10, 300)  # 10s connect timeout, 5min read timeout
            
            # Stream the file in chunks with progress reporting
            def read_in_chunks():
                bytes_read = 0
                last_report = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    
                    # Report progress every 5MB
                    if bytes_read - last_report >= 5 * 1024 * 1024:
                        percent = (bytes_read / file_size) * 100
                        elapsed = time.time() - start_time
                        rate = bytes_read / elapsed / 1024 / 1024 if elapsed > 0 else 0
                        print(f"Progress: {bytes_read}/{file_size} bytes ({percent:.1f}%) - {rate:.2f} MB/s")
                        last_report = bytes_read
                    
                    yield chunk
            
            # Make the request with streaming data
            response = session.post(
                f"{proxy_url}/cache/populate",
                headers=headers,
                data=read_in_chunks()
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
    # Check if PowerTunnel admin server is running
    try:
        response = requests.get("http://localhost:8081/cache/status", timeout=5)
        print(f"Admin server is running. Status: {response.text}")
    except:
        print("ERROR: PowerTunnel admin server is not running on port 8081")
        print("Make sure the CachePlugin is loaded and the admin server is started")
        sys.exit(1)
    
    # Just use the smaller video file for testing
    video = {
        "path": "./Sample (2024)_05s.mp4",  # Using the 5-second sample
        "item_id": "3b78c1e5f8665308433a2f8c5b8a9da2"
    }
    
    # API key from the URLs
    api_key = "856c2b939fb34c0bb9aef9909840dbaa"
    
    # Populate cache with the video
    print(f"\nProcessing {os.path.basename(video['path'])}...")
    success = populate_jellyfin_video_cache(video['path'], video['item_id'], api_key)
    
    print(f"\nCache population {'successful' if success else 'failed'}")
    
    # Get cache status
    try:
        status = requests.get("http://localhost:8081/cache/status", timeout=5)
        print(f"\nCache status: {status.text}")
    except:
        print("Could not retrieve cache status")

if __name__ == "__main__":
    main()
