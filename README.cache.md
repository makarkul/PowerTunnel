# PowerTunnel Cache System

This document provides detailed instructions for using, testing, and debugging the PowerTunnel cache system, particularly for Android applications.

## Table of Contents

1. [Overview](#overview)
2. [Setup](#setup)
   - [Prerequisites](#prerequisites)
   - [Port Forwarding](#port-forwarding)
3. [Cache Population](#cache-population)
   - [Using the Debug Script](#using-the-debug-script)
   - [Manual Population](#manual-population)
4. [Verifying Cache](#verifying-cache)
5. [Troubleshooting](#troubleshooting)
6. [URL Format](#url-format)
7. [Advanced Configuration](#advanced-configuration)

## Overview

The PowerTunnel cache system allows for efficient caching of media content, reducing bandwidth usage and improving playback performance. This is particularly useful for media streaming applications like Jellyfin.

The cache system works by:
1. Intercepting HTTP requests
2. Storing cacheable content on disk
3. Serving subsequent requests for the same content directly from the cache

## Setup

### Prerequisites

- Android device or emulator with PowerTunnel installed
- ADB (Android Debug Bridge) installed on your development machine
- Python 3.6+ with `requests` library
- Access to the media server (e.g., Jellyfin)

### Port Forwarding

To communicate with the PowerTunnel admin server running on the Android device, you need to set up port forwarding:

```bash
# Forward the PowerTunnel admin server port (default: 8081)
adb forward tcp:8081 tcp:8081
```

This allows your local machine to communicate with the PowerTunnel admin server running on the Android device.

## Cache Population

There are two ways to populate the cache:

1. Using the provided debug script (recommended)
2. Manual population through the admin API

### Using the Debug Script

The `debug_populate.py` script in the `scripts` folder automates the process of populating the cache with media files.

#### Setup Python Environment

```bash
# Navigate to the scripts directory
cd /path/to/PowerTunnel/scripts

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install requests
```

#### Running the Script

```bash
# Make sure port forwarding is set up
adb forward tcp:8081 tcp:8081

# Run the script
python debug_populate.py
```

The script will:
1. Connect to the PowerTunnel admin server
2. Upload the specified video files to the cache
3. Verify that the files are properly cached

#### Customizing the Script

You can modify the `videos` array in the script to cache different files:

```python
videos = [
    {
        "path": "./your_video_file.mp4",
        "item_id": "your_unique_id",
        "name": "descriptive_name"
    },
    # Add more videos as needed
]
```

### Manual Population

You can also manually populate the cache using HTTP requests:

```bash
# Example using curl
curl -X POST http://localhost:8081/cache/populate \
  -H "Host: 10.0.2.2:8096" \
  -H "Target-Path: /Videos/your_video_id/stream.mp4?videoId=your_video_id&mediasourceid=your_video_id&static=true" \
  -H "Content-Type: video/mp4" \
  --data-binary @/path/to/your/video.mp4
```

## Verifying Cache

### Check Cache Status

You can check the status of the cache using:

```bash
# Using curl
curl http://localhost:8081/cache/status

# Using the debug script
python debug_populate.py
```

### Verify Cache Files on Device

To directly check the cache files on the device:

```bash
# List all cache files
adb shell run-as io.github.krlvm.powertunnel.android.dev \
  find /data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel \
  -type f -not -name "*.tmp" -not -name "*.meta"

# Check details of a specific cache file
adb shell run-as io.github.krlvm.powertunnel.android.dev \
  ls -la /data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel/path/to/file
```

### Monitoring Cache Activity

To monitor cache activity in real-time:

```bash
# Watch for cache-related log entries
adb logcat | grep -i "cache\|powertunnel"

# Filter for specific video requests
adb logcat | grep -i "Videos/your_video_id/stream.mp4"
```

Look for log entries containing "Served from cache" to confirm that content is being served from the cache.

## Troubleshooting

### Cache Miss Issues

If content is not being served from the cache:

1. **Check URL formats**: Ensure the URL used for populating the cache exactly matches the URL requested by the player.
2. **Verify cache files**: Check if the files exist in the cache directory.
3. **Check logs**: Look for "Cache miss" or error messages in the logs.
4. **Clear cache**: Try clearing the cache and repopulating it.

### Clearing the Cache

To clear the cache:

```bash
# Delete all cache files
adb shell run-as io.github.krlvm.powertunnel.android.dev \
  find /data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel \
  -type f -delete

# Or via the admin API
curl http://localhost:8081/cache/clear
```

## URL Format

The cache system uses the URL as the key for caching. It's crucial that the URL format used for populating the cache matches exactly what the player will request.

### Jellyfin URL Format

For Jellyfin, the correct URL format is:

```
http://10.0.2.2:8096/Videos/{video_id}/stream.mp4?videoId={video_id}&mediasourceid={video_id}&static=true
```

Where:
- `10.0.2.2` is the special IP that Android emulators use to access the host machine
- `{video_id}` is the unique identifier for the video in Jellyfin

### URL Normalization

The cache plugin attempts to normalize URLs to increase cache hit rates. However, it's best to use the exact URL format that the player will request when populating the cache.

## Advanced Configuration

### Cache Directory

The cache is stored in:
```
/data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel
```

### Cache File Structure

Cache files are stored in a hierarchical structure:
```
/cache/powertunnel/{level1}/{level2}/{encoded_key}
```

Where:
- `{level1}` and `{level2}` are derived from the first 4 characters of the encoded key
- `{encoded_key}` is the Base64-encoded cache key

### Admin Server Configuration

The admin server runs on port 8081 by default. You can modify this in the plugin settings.

---

For more information, refer to the [PowerTunnel documentation](https://github.com/krlvm/PowerTunnel) and the [Cache Plugin source code](https://github.com/krlvm/PowerTunnel/tree/master/cache-plugin).
