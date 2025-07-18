#!/usr/bin/env python3
"""Test SSE endpoint which might work differently."""

import httpx
import json
import uuid

# Test SSE endpoint
base_url = "http://fetcher.atradev.org/sse"
session_id = str(uuid.uuid4())

print(f"Testing SSE endpoint...")
print(f"URL: {base_url}")
print(f"Session ID: {session_id}")
print()

# SSE endpoints typically work with GET requests and event streams
headers = {
    "Accept": "text/event-stream",
    "Cache-Control": "no-cache"
}

with httpx.Client() as client:
    try:
        # Try GET request first
        print("1. Testing GET request to SSE endpoint...")
        resp = client.get(f"{base_url}?sessionId={session_id}", headers=headers, timeout=5.0)
        print(f"   Status: {resp.status_code}")
        print(f"   Headers: {dict(resp.headers)}")
        print(f"   Body: {resp.text[:200]}...")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n2. Testing initialize via SSE...")
    # For SSE, we might need to send the initialize as a query param or in a different way
    init_msg = {
        "jsonrpc": "2.0",
        "method": "initialize", 
        "params": {
            "protocolVersion": "2024-11-18",
            "capabilities": {"tools": {}}
        },
        "id": 1
    }
    
    # Try POST to SSE endpoint
    try:
        resp = client.post(f"{base_url}?sessionId={session_id}", 
                          json=init_msg,
                          headers={"Content-Type": "application/json"})
        print(f"   Status: {resp.status_code}")
        print(f"   Response: {resp.text[:200]}...")
    except Exception as e:
        print(f"   Error: {e}")