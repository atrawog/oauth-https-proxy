#!/usr/bin/env python3
"""Test what methods simple.atratest.org supports."""

import asyncio
from mcp_verification_tools.core.base_test import MCPTestBase

async def test_methods():
    """Test various methods on simple server."""
    endpoint = 'https://simple.atratest.org/mcp'
    
    print(f"Testing methods on: {endpoint}")
    print("=" * 60)
    
    # Initialize session
    client = MCPTestBase(endpoint)
    result = await client.initialize_session()
    session_id = client.session_id
    print(f"Session ID: {session_id[:30]}...")
    print(f"Initialize result capabilities: {result.get('capabilities', {})}")
    
    # Try different methods
    methods = [
        ("ping", {}),
        ("tools/list", {}),
        ("resources/list", {}),
        ("prompts/list", {}),
        ("completion/complete", {"argument": {"name": "test", "value": "test"}}),
    ]
    
    for method, params in methods:
        test_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": method,
            "params": params
        }
        
        print(f"\nTesting {method}:")
        try:
            response = await client.send_request(
                test_request,
                headers={"Mcp-Session-Id": session_id}
            )
            if response.get("error"):
                print(f"   ERROR: {response['error']}")
            else:
                print(f"   SUCCESS: {response.get('result', response)}")
        except Exception as e:
            print(f"   EXCEPTION: {e}")
    
    await client.cleanup()

if __name__ == "__main__":
    asyncio.run(test_methods())