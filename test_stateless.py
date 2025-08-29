#!/usr/bin/env python3
"""Test if MCP servers are stateful or stateless."""

import asyncio
from mcp_verification_tools.core.base_test import MCPTestBase

async def test_stateless():
    """Test if servers provide session IDs."""
    endpoints = [
        'https://everything.atratest.org/mcp',
        'https://simple.atratest.org/mcp'
    ]
    
    for endpoint in endpoints:
        client = MCPTestBase(endpoint)
        try:
            await client.initialize_session()
            session_id = client.session_id
            
            if session_id:
                print(f"{endpoint}: STATEFUL (session ID: {session_id[:20]}...)")
            else:
                print(f"{endpoint}: STATELESS (no session ID)")
                
            # Test if server accepts requests without session ID after init
            if session_id:
                # Try a request WITHOUT the session ID
                client.session_id = None  # Clear it temporarily
                try:
                    response = await client.send_request({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "ping"
                    })
                    print(f"  - Accepts requests without session ID: Yes")
                except Exception as e:
                    print(f"  - Accepts requests without session ID: No ({e})")
                    
                # Restore session ID
                client.session_id = session_id
                
        finally:
            await client.cleanup()

if __name__ == "__main__":
    asyncio.run(test_stateless())