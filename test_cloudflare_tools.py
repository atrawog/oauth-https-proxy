#!/usr/bin/env python3
"""Test Cloudflare SSE tools functionality"""

import asyncio
import httpx
import json

async def test_cloudflare_tools():
    print("Testing Cloudflare SSE tools endpoint...")
    
    async with httpx.AsyncClient() as client:
        # 1. Connect to SSE endpoint
        print("\n1. Connecting to SSE endpoint...")
        endpoint_url = None
        
        async with client.stream(
            "GET",
            "https://docs.mcp.cloudflare.com/sse", 
            headers={"Accept": "text/event-stream"},
            timeout=5.0
        ) as response:
            print(f"Status: {response.status_code}")
            
            # Read the endpoint event
            async for line in response.aiter_lines():
                print(f"Line: {line}")
                if line.startswith("event: endpoint"):
                    continue
                elif line.startswith("data: "):
                    endpoint_url = line[6:].strip()
                    if endpoint_url.startswith("/"):
                        endpoint_url = f"https://docs.mcp.cloudflare.com{endpoint_url}"
                    print(f"Endpoint discovered: {endpoint_url}")
                    break
        
        if not endpoint_url:
            print("No endpoint discovered!")
            return
        
        # 2. Test initialization
        print("\n2. Testing initialization...")
        init_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            },
            "id": 1
        }
        
        print(f"Sending: {json.dumps(init_request, indent=2)}")
        
        response = await client.post(
            endpoint_url,
            headers={"Content-Type": "application/json"},
            json=init_request,
            timeout=5.0
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        print(f"Response body: {response.text}")

if __name__ == "__main__":
    asyncio.run(test_cloudflare_tools())