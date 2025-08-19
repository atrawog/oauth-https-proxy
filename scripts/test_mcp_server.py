#!/usr/bin/env python3
"""Test script to verify MCP server is running and all tools are working."""

import asyncio
import sys
import httpx
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.test_mcp_tools import MCPClient, MCP_BASE_URL


async def test_mcp_server():
    """Test if MCP server is running and responsive."""
    
    print("=" * 60)
    print("MCP Server Test")
    print("=" * 60)
    print(f"Testing MCP server at: {MCP_BASE_URL}")
    print()
    
    # First check if server is reachable
    print("1. Checking server health...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{MCP_BASE_URL}/health", timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                print(f"   ✓ Server is healthy")
                print(f"   ✓ {data['tools']} tools available")
            else:
                print(f"   ✗ Server returned status {response.status_code}")
                return False
    except Exception as e:
        print(f"   ✗ Cannot reach server: {e}")
        print()
        print("Please ensure the server is running:")
        print("  just up        # Start with Docker")
        print("  just dev       # Or run locally")
        return False
    
    print()
    print("2. Initializing MCP client...")
    try:
        async with MCPClient() as client:
            print(f"   ✓ Session initialized: {client.session_id[:8]}...")
            
            print()
            print("3. Listing available tools...")
            tools = await client.list_tools()
            print(f"   ✓ Found {len(tools)} tools:")
            
            # Group tools by category
            categories = {
                "Echo": ["echo", "replayLastEcho"],
                "Debug": ["printHeader", "requestTiming", "corsAnalysis", "environmentDump"],
                "Auth": ["bearerDecode", "authContext", "whoIStheGOAT"],
                "System": ["healthProbe", "sessionInfo"],
                "State": ["stateInspector", "sessionHistory", "stateManipulator",
                         "sessionCompare", "sessionTransfer", "stateBenchmark",
                         "sessionLifecycle", "stateValidator", "requestTracer",
                         "modeDetector"]
            }
            
            for category, tool_names in categories.items():
                available = [t["name"] for t in tools if t["name"] in tool_names]
                print(f"      {category:8} ({len(available)}/{len(tool_names)}): {', '.join(available)}")
            
            print()
            print("4. Testing sample tools...")
            
            # Test echo
            print("   Testing echo...")
            result = await client.call_tool("echo", {"message": "Hello, MCP!"})
            print(f"   ✓ Echo: {result}")
            
            # Test mode detector
            print("   Testing modeDetector...")
            mode = await client.call_tool("modeDetector")
            if isinstance(mode, str):
                print(f"   ✓ Mode: {mode[:100]}...")
            else:
                print(f"   ✓ Mode detected")
            
            # Test health probe
            print("   Testing healthProbe...")
            health = await client.call_tool("healthProbe")
            if isinstance(health, str):
                print(f"   ✓ Health: {health[:100]}...")
            else:
                print(f"   ✓ Health checked")
            
            print()
            print("=" * 60)
            print("✅ MCP Server is working correctly!")
            print("=" * 60)
            print()
            print("Run full test suite with:")
            print("  just test-mcp       # Test all MCP tools")
            print("  just test           # Run all tests")
            
            return True
            
    except Exception as e:
        print(f"   ✗ Error during testing: {e}")
        return False


async def main():
    """Main entry point."""
    success = await test_mcp_server()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())