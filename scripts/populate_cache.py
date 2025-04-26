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
        "Content-Type": "video/mp4",
        "Content-Length": str(file_size)
    }
    
    # Open and stream the file in binary mode
    with open(video_path, "rb") as f:
        print(f"Sending request to {proxy_url}/cache/populate...")
        start_time = time.time()
        
        try:
            response = requests.post(
                f"{proxy_url}/cache/populate",
                headers=headers,
                data=f
            )
            
            elapsed = time.time() - start_time
            print(f"Request completed in {elapsed:.2f} seconds")
            print(f"Response status: {response.status_code}")
            print(f"Response body: {response.text}")
            
            # The URL that will be used for cache lookups
            cached_url = f"http://{jellyfin_host}{target_path}"
            print(f"Video cached at URL: {cached_url}")
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Error: {e}")
            return False

def main():
    # Check if PowerTunnel admin server is running
    try:
        requests.get("http://localhost:8081/cache/status", timeout=2)
    except:
        print("ERROR: PowerTunnel admin server is not running on port 8081")
        print("Make sure the CachePlugin is loaded and the admin server is started")
        sys.exit(1)
    
    # Define the videos to cache with their actual Jellyfin IDs
    videos = [
        {
            "path": "./Sample (2024)_05s.mp4",  # Using relative paths since we're in the same directory
            "item_id": "3b78c1e5f8665308433a2f8c5b8a9da2"
        },
        {
            "path": "./Sample (2024)_30s.mp4",
            "item_id": "42a9a397a6a26cc736b27cc8e643e6d3"
        }
    ]
    
    # API key from the URLs
    api_key = "856c2b939fb34c0bb9aef9909840dbaa"
    
    # Populate cache with each video
    success_count = 0
    for video in videos:
        print(f"\nProcessing {os.path.basename(video['path'])}...")
        if populate_jellyfin_video_cache(video['path'], video['item_id'], api_key):
            success_count += 1
    
    print(f"\nCache population complete: {success_count}/{len(videos)} videos cached successfully")
    
    # Get cache status
    try:
        status = requests.get("http://localhost:8081/cache/status")
        print(f"\nCache status: {status.text}")
    except:
        print("Could not retrieve cache status")

if __name__ == "__main__":
    main()
