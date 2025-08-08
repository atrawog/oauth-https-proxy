#!/usr/bin/env python3
"""Test fetcher MCP endpoint directly."""

import json
import requests
import uuid

def test_fetcher_mcp():
    """Test the fetcher MCP endpoint."""
    # Generate session ID
    session_id = str(uuid.uuid4())
    
    # Base URL
    api_url = "http://fetcher-mcp:3000/mcp"
    
    # Headers with session ID
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "x-mcp-session-id": session_id
    }
    
    # Initialize request
    init_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-18",
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    }
    
    print("Testing fetcher MCP endpoint...")
    print(f"URL: {api_url}")
    print(f"Session ID: {session_id}")
    print()
    
    # Send initialize request
    print("1. Sending initialize request...")
    try:
        resp = requests.post(api_url, json=init_request, headers=headers)
        print(f"   Status: {resp.status_code}")
        print(f"   Response: {resp.text[:200]}...")
        
        if resp.status_code == 200:
            # Parse SSE response
            lines = resp.text.strip().split('\n')
            for line in lines:
                if line.startswith('data: '):
                    json_data = line[6:]  # Remove "data: " prefix
                    data = json.loads(json_data)
                    print(f"   Protocol Version: {data.get('result', {}).get('protocolVersion')}")
                    print(f"   Server: {data.get('result', {}).get('serverInfo', {}).get('name')}")
                    break
            print()
            
            # List tools
            print("2. Listing available tools...")
            list_tools = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 2
            }
            
            resp = requests.post(api_url, json=list_tools, headers=headers)
            print(f"   Status: {resp.status_code}")
            
            if resp.status_code == 200:
                # Parse SSE response
                lines = resp.text.strip().split('\n')
                for line in lines:
                    if line.startswith('data: '):
                        json_data = line[6:]  # Remove "data: " prefix
                        data = json.loads(json_data)
                        tools = data.get('result', {}).get('tools', [])
                        print(f"   Found {len(tools)} tools:")
                        for tool in tools[:5]:  # Show first 5
                            print(f"   - {tool.get('name')}: {tool.get('description', '')[:50]}...")
                        if len(tools) > 5:
                            print(f"   ... and {len(tools) - 5} more")
                        break
            else:
                print(f"   Error: {resp.text}")
                
        else:
            print(f"   Error: {resp.text}")
            
    except Exception as e:
        print(f"   Failed: {e}")
        
    print("\n✅ Fetcher MCP endpoint is accessible!")

if __name__ == "__main__":
    test_fetcher_mcp()