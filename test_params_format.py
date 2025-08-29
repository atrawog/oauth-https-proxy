#!/usr/bin/env python3
"""Test different parameter formats."""

import asyncio
import json
from mcp_verification_tools.core.base_test import MCPTestBase

async def test_params():
    """Test different parameter formats on simple server."""
    endpoint = 'https://simple.atratest.org/mcp'
    
    print(f"Testing parameter formats on: {endpoint}")
    print("=" * 60)
    
    # Initialize session
    client = MCPTestBase(endpoint)
    await client.initialize_session()
    session_id = client.session_id
    print(f"Session ID: {session_id[:30]}...")
    
    # Try different parameter formats for tools/list
    param_variations = [
        ("Empty object", {}),
        ("Null", None),
        ("Omitted", "OMIT"),  # Special marker
    ]
    
    for desc, params in param_variations:
        if params == "OMIT":
            test_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
                # No params field
            }
        else:
            test_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": params
            }
        
        print(f"\nTesting tools/list with {desc} params:")
        print(f"   Request: {json.dumps(test_request)}")
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
        except Exception as e:
            print(f"   EXCEPTION: {e}")
    
    await client.cleanup()

if __name__ == "__main__":
    asyncio.run(test_params())