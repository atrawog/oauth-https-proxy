#!/usr/bin/env python3
"""Simple test to check Cloudflare's auth requirements"""

import asyncio
import httpx

async def test_cloudflare_auth():
    print("Testing Cloudflare authentication requirements...")
    
    async with httpx.AsyncClient() as client:
        # Test 1: Check if MCP endpoint requires auth
        print("\n1. Testing MCP endpoint without auth...")
        try:
            response = await client.get(
                "https://docs.mcp.cloudflare.com/sse",
                headers={"Accept": "text/event-stream"},
                timeout=3.0
            )
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                print("MCP endpoint is publicly accessible (no auth required)")
            elif response.status_code == 401:
                print("MCP endpoint requires authentication")
                print(f"WWW-Authenticate: {response.headers.get('WWW-Authenticate', 'Not present')}")
        except httpx.TimeoutException:
            print("Request timed out")
        
        # Test 2: Check OAuth metadata endpoint
        print("\n2. Testing OAuth metadata endpoint...")
        try:
            response = await client.get(
                "https://docs.mcp.cloudflare.com/.well-known/oauth-protected-resource",
                timeout=3.0
            )
            print(f"Status: {response.status_code}")
            if response.status_code == 404:
                print("No OAuth metadata - this is a public MCP server")
            elif response.status_code == 200:
                print("OAuth metadata found")
                print(f"Content: {response.text[:200]}")
        except httpx.TimeoutException:
            print("Request timed out")

if __name__ == "__main__":
    asyncio.run(test_cloudflare_auth())