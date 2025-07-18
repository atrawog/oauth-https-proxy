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
    base_url = "http://fetcher.atradev.org/mcp"
    
    # Headers with session ID
    headers = {
        "Content-Type": "application/json",
        "Mcp-Session-Id": session_id
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
    print(f"URL: {base_url}")
    print(f"Session ID: {session_id}")
    print()
    
    # Send initialize request
    print("1. Sending initialize request...")
    try:
        resp = requests.post(base_url, json=init_request, headers=headers)
        print(f"   Status: {resp.status_code}")
        print(f"   Response: {resp.text[:200]}...")
        
        if resp.status_code == 200:
            # Parse response
            data = resp.json()
            print(f"   Protocol Version: {data.get('result', {}).get('protocolVersion')}")
            print(f"   Server: {data.get('result', {}).get('serverInfo', {}).get('name')}")
            print()
            
            # List tools
            print("2. Listing available tools...")
            list_tools = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "params": {},
                "id": 2
            }
            
            resp = requests.post(base_url, json=list_tools, headers=headers)
            print(f"   Status: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                tools = data.get('result', {}).get('tools', [])
                print(f"   Found {len(tools)} tools:")
                for tool in tools[:5]:  # Show first 5
                    print(f"   - {tool.get('name')}: {tool.get('description', '')[:50]}...")
                if len(tools) > 5:
                    print(f"   ... and {len(tools) - 5} more")
            else:
                print(f"   Error: {resp.text}")
                
        else:
            print(f"   Error: {resp.text}")
            
    except Exception as e:
        print(f"   Failed: {e}")
        
    print("\n✅ Fetcher MCP endpoint is accessible!")

if __name__ == "__main__":
    test_fetcher_mcp()