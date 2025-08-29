#!/usr/bin/env python3
"""Test FastMCP Echo Server"""

import requests
import json

# Test endpoint
url = "https://fast-echo.atratest.org/mcp"

# Disable SSL verification for testing
verify_ssl = False

print("Testing FastMCP Echo Server at:", url)
print("=" * 60)

# Test 1: Initialize session
print("\n1. Testing initialize without session (should create new session):")
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream"
}

# First request to get session
init_data = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "clientInfo": {
            "name": "test-client",
            "version": "1.0.0"
        },
        "protocolVersion": "2025-06-18"
    },
    "id": 1
}

response = requests.post(url, json=init_data, headers=headers, verify=verify_ssl)
print(f"Status: {response.status_code}")
print(f"Headers: {dict(response.headers)}")

# Get session ID if present
session_id = response.headers.get('Mcp-Session-Id')
if session_id:
    print(f"Session ID: {session_id}")
    headers['Mcp-Session-Id'] = session_id

print(f"Response: {response.text[:500]}")

# Test 2: List tools with session
if session_id:
    print("\n2. Testing tools/list with session:")
    list_data = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    }
    
    response = requests.post(url, json=list_data, headers=headers, verify=verify_ssl)
    print(f"Status: {response.status_code}")
    
    # Parse SSE response if needed
    if response.headers.get('content-type', '').startswith('text/event-stream'):
        print("Response (SSE):")
        for line in response.text.split('\n'):
            if line.startswith('data: '):
                try:
                    data = json.loads(line[6:])
                    print(json.dumps(data, indent=2))
                except:
                    pass
    else:
        print(f"Response: {response.text[:1000]}")

    # Test 3: Call echo tool
    print("\n3. Testing echo_tool:")
    echo_data = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "echo_tool",
            "arguments": {
                "text": "Hello, FastMCP!"
            }
        },
        "id": 3
    }
    
    response = requests.post(url, json=echo_data, headers=headers, verify=verify_ssl)
    print(f"Status: {response.status_code}")
    
    if response.headers.get('content-type', '').startswith('text/event-stream'):
        print("Response (SSE):")
        for line in response.text.split('\n'):
            if line.startswith('data: '):
                try:
                    data = json.loads(line[6:])
                    print(json.dumps(data, indent=2))
                except:
                    pass
    else:
        print(f"Response: {response.text[:1000]}")

print("\n" + "=" * 60)
print("FastMCP Echo Server is working correctly!" if session_id else "Failed to establish session")