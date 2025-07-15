#!/usr/bin/env python
"""Test server behavior with slow clients (like Let's Encrypt might be)."""

import socket
import time
import os

def test_slow_request():
    """Simulate a slow client that connects but delays sending the request."""
    test_domain = os.getenv("TEST_DOMAIN", "test.atradev.org")
    
    print(f"Testing slow client behavior to {test_domain}...")
    
    # Create socket and connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    
    try:
        print("1. Connecting to server...")
        start = time.time()
        sock.connect((test_domain, 80))
        connect_time = time.time() - start
        print(f"   Connected in {connect_time*1000:.1f}ms")
        
        # Wait before sending request (simulate slow client)
        print("2. Waiting 5 seconds before sending request...")
        time.sleep(5)
        
        # Send HTTP request
        print("3. Sending HTTP request...")
        request = f"GET /.well-known/acme-challenge/test HTTP/1.1\r\nHost: {test_domain}\r\n\r\n"
        sock.send(request.encode())
        
        # Read response
        print("4. Reading response...")
        response = sock.recv(4096).decode()
        print(f"   Response received: {response.split('\\r\\n')[0]}")
        
        total_time = time.time() - start
        print(f"\nTotal time: {total_time:.1f}s")
        
    except socket.timeout:
        print("ERROR: Socket timeout!")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        sock.close()

def test_connect_only():
    """Test connecting without sending any data."""
    test_domain = os.getenv("TEST_DOMAIN", "test.atradev.org")
    
    print(f"\nTesting connect-only behavior to {test_domain}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        print("1. Connecting to server...")
        start = time.time()
        sock.connect((test_domain, 80))
        connect_time = time.time() - start
        print(f"   Connected in {connect_time*1000:.1f}ms")
        
        print("2. Waiting 10 seconds without sending data...")
        time.sleep(10)
        
        print("3. Closing connection...")
        sock.close()
        print("   Connection closed successfully")
        
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    test_slow_request()
    test_connect_only()