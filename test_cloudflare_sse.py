#!/usr/bin/env python3
"""Test Cloudflare SSE endpoint"""

import asyncio
import httpx

async def test_cloudflare():
    print("Testing Cloudflare SSE endpoint...")
    
    async with httpx.AsyncClient() as client:
        # Test 1: Simple GET
        print("\n1. Testing simple GET...")
        try:
            response = await client.get(
                "https://docs.mcp.cloudflare.com/sse",
                headers={"Accept": "text/event-stream"},
                timeout=3.0
            )
            print(f"Status: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            print(f"Body (first 500 chars): {response.text[:500]}")
        except httpx.TimeoutException:
            print("GET request timed out after 3 seconds")
        except Exception as e:
            print(f"GET request failed: {e}")
        
        # Test 2: Streaming GET
        print("\n2. Testing streaming GET...")
        try:
            async with client.stream(
                "GET",
                "https://docs.mcp.cloudflare.com/sse", 
                headers={"Accept": "text/event-stream"},
                timeout=3.0
            ) as response:
                print(f"Stream status: {response.status_code}")
                print(f"Stream headers: {dict(response.headers)}")
                
                # Try to read first line
                line_count = 0
                async for line in response.aiter_lines():
                    print(f"Line {line_count}: {line}")
                    line_count += 1
                    if line_count >= 5:
                        break
        except httpx.ReadTimeout:
            print("Stream read timed out (expected for SSE)")
        except httpx.TimeoutException as e:
            print(f"Stream connection timed out: {e}")
        except Exception as e:
            print(f"Stream request failed: {e}")
        
        # Test 3: Check if it's actually hanging or returning data
        print("\n3. Testing with no timeout...")
        try:
            response = await client.get(
                "https://docs.mcp.cloudflare.com/sse",
                timeout=30.0
            )
            print(f"No-timeout status: {response.status_code}")
            print(f"Content-Type: {response.headers.get('content-type')}")
            print(f"Response length: {len(response.content)} bytes")
        except httpx.ConnectTimeout:
            print("Connection timed out")
        except Exception as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_cloudflare())