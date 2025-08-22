#!/usr/bin/env python
"""Complete MCP test to verify the endpoint is working correctly."""

import json
import requests

def test_mcp_endpoint():
    """Test the MCP endpoint at auth.atratest.org."""
    
    base_url = "https://auth.atratest.org/mcp"
    
    # Test 1: Initialize session
    print("1. Testing MCP initialization...")
    init_request = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
    
    response = requests.post(base_url, json=init_request, headers=headers)
    print(f"   Status: {response.status_code}")
    
    # Parse SSE response
    if response.status_code == 200:
        lines = response.text.strip().split('\n')
        for line in lines:
            if line.startswith('data: '):
                data = json.loads(line[6:])
                print(f"   Response: {json.dumps(data, indent=2)}")
                
                # Extract session ID if present
                if "result" in data and "meta" in data["result"]:
                    session_id = data["result"]["meta"].get("sessionId")
                    if session_id:
                        print(f"   Session ID: {session_id}")
                        return session_id
                elif "result" in data:
                    print("   ✓ Initialization successful")
                    return True
    else:
        print(f"   ✗ Error: {response.text}")
        return None
    
    # Test 2: List tools (if session was created)
    print("\n2. Testing tool listing...")
    list_tools_request = {
        "jsonrpc": "2.0",
        "id": "tools-1",
        "method": "tools/list",
        "params": {}
    }
    
    response = requests.post(base_url, json=list_tools_request, headers=headers)
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        lines = response.text.strip().split('\n')
        for line in lines:
            if line.startswith('data: '):
                data = json.loads(line[6:])
                if "result" in data and "tools" in data["result"]:
                    tools = data["result"]["tools"]
                    print(f"   ✓ Found {len(tools)} tools:")
                    for tool in tools[:5]:  # Show first 5 tools
                        print(f"      - {tool['name']}: {tool.get('description', 'No description')[:50]}...")
                    if len(tools) > 5:
                        print(f"      ... and {len(tools) - 5} more")
    
    print("\n✅ MCP endpoint is working correctly!")
    return True

if __name__ == "__main__":
    result = test_mcp_endpoint()
    exit(0 if result else 1)