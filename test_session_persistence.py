#!/usr/bin/env python3
"""Test session persistence behavior."""

import asyncio
import httpx
from mcp_verification_tools.core.base_test import MCPTestBase

async def test_session_persistence():
    """Test session persistence on both endpoints."""
    endpoints = [
        'https://everything.atratest.org/mcp',
        'https://simple.atratest.org/mcp'
    ]
    
    for endpoint in endpoints:
        print(f"\nTesting: {endpoint}")
        print("=" * 60)
        
        # Initialize session
        client = MCPTestBase(endpoint)
        await client.initialize_session()
        session_id = client.session_id
        print(f"Session ID: {session_id[:30]}...")
        
        # Test request
        test_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",
            "MCP-Protocol-Version": "2025-06-18"
        }
        
        # Test 1: Valid session ID
        print("\n1. Testing with VALID session ID:")
        valid_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            response = await valid_client.post(
                endpoint,
                json=test_request,
                headers={**headers, "Mcp-Session-Id": session_id}
            )
            print(f"   Status: {response.status_code}")
            if response.status_code != 200 and response.status_code != 202:
                print(f"   Response: {response.text[:200]}")
        finally:
            await valid_client.aclose()
        
        # Test 2: Invalid session ID
        print("\n2. Testing with INVALID session ID:")
        invalid_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            response = await invalid_client.post(
                endpoint,
                json=test_request,
                headers={**headers, "Mcp-Session-Id": "invalid-session-12345"}
            )
            print(f"   Status: {response.status_code}")
            if response.status_code == 200 or response.status_code == 202:
                print(f"   WARNING: Server accepted invalid session ID!")
            else:
                print(f"   Good: Server rejected invalid session ID")
        finally:
            await invalid_client.aclose()
        
        # Test 3: No session ID
        print("\n3. Testing with NO session ID:")
        no_session_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            response = await no_session_client.post(
                endpoint,
                json=test_request,
                headers=headers
            )
            print(f"   Status: {response.status_code}")
            if response.status_code == 400:
                print(f"   Good: Server requires session ID (400 Bad Request)")
            else:
                print(f"   Response: {response.text[:200]}")
        finally:
            await no_session_client.aclose()
        
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(test_session_persistence())