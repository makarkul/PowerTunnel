#!/usr/bin/env python3
"""
Direct socket test for PowerTunnel cache population
Uses raw sockets for more control over the data transfer
"""

import socket
import time
import sys

def main():
    # Configuration
    host = 'localhost'
    port = 8081
    item_id = "8f212c2c56d0a5b6c2247bb7e7c0e4f8"
    
    # Create a very small test file (10KB)
    test_data = b'X' * 10240  # 10KB of data
    
    # Create the HTTP request
    target_path = f'/Videos/{item_id}/stream.mp4?videoId={item_id}&mediasourceid={item_id}&static=true'
    
    http_request = (
        f"POST /cache/populate HTTP/1.1\r\n"
        f"Host: 10.0.2.2:8096\r\n"
        f"Target-Path: {target_path}\r\n"
        f"Content-Type: video/mp4\r\n"
        f"Content-Length: {len(test_data)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode('utf-8')
    
    print(f"Test data size: {len(test_data)} bytes")
    print(f"Request headers size: {len(http_request)} bytes")
    
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to the server
        print(f"Connecting to {host}:{port}...")
        s.connect((host, port))
        
        # Set socket options
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)  # 128KB receive buffer
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)        # Disable Nagle's algorithm
        
        # Send the HTTP headers
        print("Sending HTTP headers...")
        s.sendall(http_request)
        
        # Small delay before sending data
        print("Adding a small delay before sending data...")
        time.sleep(0.5)
        
        # Send the data in small chunks with explicit flush
        chunk_size = 1024  # 1KB chunks
        total_sent = 0
        
        print(f"Sending data in {chunk_size} byte chunks...")
        start_time = time.time()
        
        for i in range(0, len(test_data), chunk_size):
            chunk = test_data[i:i+chunk_size]
            bytes_sent = s.send(chunk)
            total_sent += bytes_sent
            print(f"Sent chunk {i//chunk_size + 1}: {bytes_sent} bytes, total: {total_sent}/{len(test_data)}")
            # Small delay between chunks
            time.sleep(0.01)
        
        # Calculate and display metrics
        elapsed = time.time() - start_time
        print(f"Data sending completed in {elapsed:.2f} seconds")
        
        # Wait for response
        print("Waiting for response...")
        s.settimeout(10)  # 10 second timeout for receiving
        
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
        if "200 OK" in response_str:
            print("Cache population successful!")
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

if __name__ == "__main__":
    main()
