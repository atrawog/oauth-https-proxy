#!/usr/bin/env python3
"""Test MCP endpoint directly without proxy."""

import httpx
import json

# Test directly against fetcher-mcp container
url = "http://fetcher-mcp:3000/mcp"
session_id = "test-session-456"

headers = {
    "Content-Type": "application/json",
    "Mcp-Session-Id": session_id
}

init_request = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-18",
        "capabilities": {
            "tools": {}
        }
    },
    "id": 1
}

print(f"Testing direct connection to fetcher-mcp...")
print(f"URL: {url}")
print(f"Session ID: {session_id}")
print(f"Request: {json.dumps(init_request, indent=2)}")
print()

with httpx.Client() as client:
    try:
        resp = client.post(url, json=init_request, headers=headers)
        print(f"Status: {resp.status_code}")
        print(f"Headers: {dict(resp.headers)}")
        print(f"Response: {resp.text}")
    except Exception as e:
        print(f"Error: {e}")