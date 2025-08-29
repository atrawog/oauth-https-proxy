#!/usr/bin/env python3
"""Test tools/list method on both servers."""

import asyncio
from mcp_verification_tools.core.base_test import MCPTestBase

async def test_tools_list():
    """Test tools/list method on both endpoints."""
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
        
        # Test tools/list request
        test_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        print("\n1. Testing tools/list with valid session ID:")
        try:
            response = await client.send_request(
                test_request,
                headers={"Mcp-Session-Id": session_id}
            )
            if response.get("error"):
                print(f"   ERROR: {response['error']}")
            else:
                result = response.get("result", {})
                tools = result.get("tools", [])
                print(f"   SUCCESS: Found {len(tools)} tools")
                if tools:
                    print(f"   First tool: {tools[0].get('name', 'unnamed')}")
        except Exception as e:
            print(f"   EXCEPTION: {e}")
        
        print("\n2. Testing tools/list with invalid session ID:")
        try:
            response = await client.send_request(
                test_request,
                headers={"Mcp-Session-Id": "invalid-session-12345"}
            )
            if response.get("error"):
                print(f"   Good: Got error response: {response['error']}")
            else:
                print(f"   WARNING: No error for invalid session! Response: {response}")
        except Exception as e:
            print(f"   Good: Exception raised: {str(e)[:100]}")
        
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(test_tools_list())