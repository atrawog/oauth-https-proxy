#!/usr/bin/env python3
"""Direct test of MCP endpoint."""

import asyncio
import httpx
import json

async def test_mcp():
    """Test MCP endpoint directly."""
    url = "https://auth.atratest.org/mcp"
    
    # Prepare MCP initialize request
    payload = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "0.1.0",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
    
    print(f"Testing MCP endpoint at {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            print(f"Status: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            print(f"Body: {response.text}")
    except httpx.TimeoutException:
        print("Request timed out after 5 seconds")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_mcp())