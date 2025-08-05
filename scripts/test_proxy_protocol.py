#!/usr/bin/env python3
"""
Simple test script to verify PROXY protocol v1 implementation.
"""
import socket
import time
import sys

def test_proxy_protocol(host='localhost', port=10001):
    """Test various PROXY protocol scenarios."""
    
    test_cases = [
        # Valid cases
        ("Valid TCP4", b"PROXY TCP4 192.168.1.100 192.168.1.200 12345 80\r\nGET / HTTP/1.1\r\n\r\n"),
        ("Valid TCP6", b"PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\nGET / HTTP/1.1\r\n\r\n"),
        
        # Invalid cases (should close connection)
        ("Invalid protocol", b"PROXY INVALID 192.168.1.1 192.168.1.2 12345 80\r\n"),
        ("Too few fields", b"PROXY TCP4 192.168.1.1 192.168.1.2 12345\r\n"),
        ("Too many fields", b"PROXY TCP4 192.168.1.1 192.168.1.2 12345 80 extra\r\n"),
        ("Invalid IPv4", b"PROXY TCP4 192.168.1.256 192.168.1.2 12345 80\r\n"),
        ("Invalid IPv6", b"PROXY TCP6 invalid::ipv6 2001:db8::2 12345 80\r\n"),
        ("Port out of range", b"PROXY TCP4 192.168.1.1 192.168.1.2 70000 80\r\n"),
        ("Port with leading zeros", b"PROXY TCP4 192.168.1.1 192.168.1.2 00080 80\r\n"),
        
        # Edge cases
        ("Port zero", b"PROXY TCP4 192.168.1.1 192.168.1.2 0 80\r\nGET / HTTP/1.1\r\n\r\n"),
        ("Max port", b"PROXY TCP4 192.168.1.1 192.168.1.2 65535 65535\r\nGET / HTTP/1.1\r\n\r\n"),
        
        # Non-PROXY data (should be forwarded)
        ("Regular HTTP", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ]
    
    for test_name, test_data in test_cases:
        print(f"\nTesting: {test_name}")
        print(f"Data: {test_data[:50]}..." if len(test_data) > 50 else f"Data: {test_data}")
        
        try:
            # Create connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((host, port))
            
            # Send test data
            sock.sendall(test_data)
            
            # Try to receive response
            try:
                response = sock.recv(1024)
                if response:
                    print(f"✓ Got response: {response[:100]}...")
                else:
                    print("✗ Connection closed by server")
            except socket.timeout:
                print("✗ Timeout waiting for response")
            except ConnectionResetError:
                print("✗ Connection reset by server")
            
            sock.close()
            
        except Exception as e:
            print(f"✗ Error: {e}")
        
        time.sleep(0.1)  # Small delay between tests

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10001
    
    print(f"Testing PROXY protocol on {host}:{port}")
    test_proxy_protocol(host, port)