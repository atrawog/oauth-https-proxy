#!/usr/bin/env python
"""Simple test to verify session ID detection."""

import asyncio
import sys
sys.path.insert(0, '..')

from mcp_verification_tools.core.base_test import MCPTestBase

async def test_session():
    """Test session ID detection."""
    
    client = MCPTestBase("https://everything.atratest.org/mcp")
    
    try:
        print("Initializing session...")
        result = await client.initialize_session()
        
        print(f"Session ID: {client.session_id}")
        print(f"Headers captured: {client.evidence.headers}")
        print(f"Response result: {result}")
        
        if client.session_id:
            print(f"\n✅ SUCCESS: Session ID found: {client.session_id}")
            # Test character validation
            violations = client.check_character_range(client.session_id, 0x21, 0x7E)
            if violations:
                print(f"❌ Character violations: {violations}")
            else:
                print("✅ All characters are valid ASCII (0x21-0x7E)")
        else:
            print("\n❌ FAILED: No session ID found")
            
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(test_session())