#!/usr/bin/env python3
"""Test if Cloudflare requires initialization"""

import asyncio
import httpx
import json

async def test_direct_tools_list():
    print("Testing direct tools/list without initialization...")
    
    async with httpx.AsyncClient() as client:
        # 1. Connect to SSE endpoint and keep connection open
        print("\n1. Opening SSE connection...")
        endpoint_url = None
        
        # We need to keep the SSE connection open to receive responses
        sse_response = None
        async def sse_reader():
            nonlocal endpoint_url, sse_response
            async with client.stream(
                "GET",
                "https://docs.mcp.cloudflare.com/sse", 
                headers={"Accept": "text/event-stream"},
                timeout=30.0
            ) as response:
                print(f"SSE Status: {response.status_code}")
                
                async for line in response.aiter_lines():
                    print(f"SSE Line: {line}")
                    
                    if line.startswith("event: endpoint"):
                        continue
                    elif line.startswith("data: ") and not endpoint_url:
                        endpoint_url = line[6:].strip()
                        if endpoint_url.startswith("/"):
                            endpoint_url = f"https://docs.mcp.cloudflare.com{endpoint_url}"
                        print(f"Endpoint discovered: {endpoint_url}")
                    elif line.startswith("event: message"):
                        continue
                    elif line.startswith("data: ") and endpoint_url:
                        # This is a response message
                        try:
                            data = json.loads(line[6:])
                            print(f"Response received: {json.dumps(data, indent=2)}")
                            sse_response = data
                        except Exception as e:
                            print(f"Failed to parse response: {e}")
        
        # Start SSE reader
        sse_task = asyncio.create_task(sse_reader())
        
        # Wait for endpoint discovery
        for _ in range(50):
            if endpoint_url:
                break
            await asyncio.sleep(0.1)
        
        if not endpoint_url:
            print("No endpoint discovered!")
            sse_task.cancel()
            return
        
        # 2. Try tools/list directly
        print("\n2. Sending tools/list request...")
        tools_request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }
        
        print(f"Sending: {json.dumps(tools_request, indent=2)}")
        
        response = await client.post(
            endpoint_url,
            headers={"Content-Type": "application/json"},
            json=tools_request,
            timeout=5.0
        )
        
        print(f"POST Response status: {response.status_code}")
        print(f"POST Response body: {response.text}")
        
        # Wait for SSE response
        print("\n3. Waiting for SSE response...")
        for _ in range(50):
            if sse_response:
                break
            await asyncio.sleep(0.1)
        
        if not sse_response:
            print("No SSE response received!")
        
        # Cancel SSE reader
        sse_task.cancel()
        try:
            await sse_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    asyncio.run(test_direct_tools_list())