#!/usr/bin/env python3
"""Test script for fetcher MCP using StreamableHTTP transport."""

import json
import requests
from time import sleep

def test_fetcher_mcp():
    """Test fetcher MCP with proper session management."""
    
    base_url = "http://fetcher.atradev.org"
    
    # 1. Initialize session
    print("1. Initializing MCP session...")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
    
    # Initial request without session ID to initialize
    init_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "0.1.0",
            "capabilities": {"tools": {}}
        },
        "id": 1
    }
    
    # For StreamableHTTP, first request initializes session
    response = requests.post(f"{base_url}/mcp", 
                           headers=headers,
                           json=init_request)
    
    print(f"Response status: {response.status_code}")
    print(f"Response headers: {dict(response.headers)}")
    
    # Extract session ID from response headers or body
    session_id = response.headers.get('X-Session-Id') or response.headers.get('x-session-id')
    
    if not session_id and response.status_code == 200:
        # Session might be in response body
        try:
            data = response.json()
            print(f"Response body: {json.dumps(data, indent=2)}")
        except:
            print(f"Response text: {response.text}")
    
    # 2. Test tools/list with session
    if session_id:
        print(f"\n2. Using session ID: {session_id}")
        headers['X-Session-Id'] = session_id
        
        list_request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        }
        
        response = requests.post(f"{base_url}/mcp",
                               headers=headers,
                               json=list_request)
        
        print(f"Tools list response: {response.status_code}")
        if response.status_code == 200:
            print(json.dumps(response.json(), indent=2))
    
    # 3. Alternative: Try SSE endpoint
    print("\n3. Testing SSE endpoint...")
    sse_response = requests.get(f"{base_url}/sse", stream=True)
    print(f"SSE endpoint status: {sse_response.status_code}")

if __name__ == "__main__":
    test_fetcher_mcp()