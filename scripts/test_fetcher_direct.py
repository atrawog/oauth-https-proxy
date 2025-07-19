#!/usr/bin/env python3
"""Direct test of fetcher using SSE endpoint."""

import requests
import json
import sys

def test_sse_endpoint():
    """Test the SSE endpoint directly."""
    
    # Try the SSE endpoint
    url = "http://fetcher-mcp:3000/sse"
    
    print("Testing fetcher MCP SSE endpoint...")
    print(f"URL: {url}")
    print()
    
    # Create a session
    session = requests.Session()
    
    # Initialize request
    init_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    }
    
    # Send request
    print("1. Sending initialize request to SSE endpoint...")
    try:
        resp = session.post(url, json=init_request, stream=True)
        print(f"   Status: {resp.status_code}")
        print(f"   Headers: {dict(resp.headers)}")
        
        # Read SSE response
        for line in resp.iter_lines():
            if line:
                line_str = line.decode('utf-8')
                print(f"   > {line_str}")
                if line_str.startswith('data: '):
                    data = json.loads(line_str[6:])
                    print(f"   Parsed: {json.dumps(data, indent=2)}")
        
    except Exception as e:
        print(f"   Failed: {e}")
        import traceback
        traceback.print_exc()

def test_root_endpoint():
    """Test the root endpoint."""
    url = "http://fetcher-mcp:3000/"
    
    print("\n2. Testing root endpoint...")
    print(f"URL: {url}")
    
    try:
        resp = requests.get(url)
        print(f"   Status: {resp.status_code}")
        print(f"   Headers: {dict(resp.headers)}")
        print(f"   Body preview: {resp.text[:200]}...")
    except Exception as e:
        print(f"   Failed: {e}")

if __name__ == "__main__":
    test_root_endpoint()
    test_sse_endpoint()