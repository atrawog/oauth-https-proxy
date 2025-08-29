#!/usr/bin/env python
"""Debug script to test MCP endpoint directly."""

import asyncio
import httpx
import json

async def test_mcp_endpoint():
    """Test MCP endpoint initialization."""
    
    endpoint = "https://everything.atratest.org/mcp"
    
    # Prepare request
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-verification-tools",
                "version": "1.0.0"
            }
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream, application/json",
        "MCP-Protocol-Version": "2025-06-18"
    }
    
    print(f"Testing endpoint: {endpoint}")
    print(f"Request: {json.dumps(request, indent=2)}")
    print(f"Headers: {headers}")
    print("-" * 50)
    
    async with httpx.AsyncClient() as client:
        response = await client.post(endpoint, json=request, headers=headers)
        
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Content-Type: {response.headers.get('content-type')}")
        print("-" * 50)
        print("Raw Response Body:")
        print(response.text)
        print("-" * 50)
        
        # Try to parse response
        content_type = response.headers.get('content-type', '').lower()
        
        if 'text/event-stream' in content_type:
            print("Response is SSE format")
            # Parse SSE
            lines = response.text.strip().split('\n')
            for line in lines:
                if line.startswith('data: '):
                    try:
                        data = json.loads(line[6:])
                        print("Parsed JSON from SSE:")
                        print(json.dumps(data, indent=2))
                    except json.JSONDecodeError as e:
                        print(f"Failed to parse line: {line}")
                        print(f"Error: {e}")
        else:
            try:
                data = response.json()
                print("Parsed JSON response:")
                print(json.dumps(data, indent=2))
            except Exception as e:
                print(f"Failed to parse as JSON: {e}")

if __name__ == "__main__":
    asyncio.run(test_mcp_endpoint())