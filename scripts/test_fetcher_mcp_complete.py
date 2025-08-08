#!/usr/bin/env python3
"""Complete test of fetcher MCP fetch_url tool."""

import json
import requests
import uuid
import sys

def parse_sse_response(text):
    """Parse SSE response and extract JSON data."""
    lines = text.strip().split('\n')
    for line in lines:
        if line.startswith('data: '):
            json_data = line[6:]  # Remove "data: " prefix
            return json.loads(json_data)
    return None

def test_fetcher_fetch_url():
    """Test the fetcher MCP fetch_url tool."""
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
    
    print("Testing fetcher MCP fetch_url tool...")
    print(f"URL: {api_url}")
    print(f"Session ID: {session_id}")
    print()
    
    # Initialize request
    init_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
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
    
    # Send initialize request
    print("1. Sending initialize request...")
    try:
        resp = requests.post(api_url, json=init_request, headers=headers)
        print(f"   Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = parse_sse_response(resp.text)
            if data:
                print(f"   Protocol Version: {data.get('result', {}).get('protocolVersion')}")
                print(f"   Server: {data.get('result', {}).get('serverInfo', {}).get('name')}")
                print()
            else:
                print("   Failed to parse SSE response")
                return
        else:
            print(f"   Error: {resp.text}")
            return
            
    except Exception as e:
        print(f"   Failed: {e}")
        return
    
    # List tools
    print("2. Listing available tools...")
    list_tools = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 2
    }
    
    try:
        resp = requests.post(api_url, json=list_tools, headers=headers)
        print(f"   Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = parse_sse_response(resp.text)
            if data:
                tools = data.get('result', {}).get('tools', [])
                print(f"   Found {len(tools)} tools:")
                for tool in tools:
                    print(f"   - {tool.get('name')}: {tool.get('description', '')[:60]}...")
            else:
                print("   Failed to parse SSE response")
        else:
            print(f"   Error: {resp.text}")
            return
            
    except Exception as e:
        print(f"   Failed: {e}")
        return
    
    # Call fetch_url tool
    print("\n3. Testing fetch_url tool...")
    fetch_request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "fetch_url",
            "arguments": {
                "url": "https://example.com",
                "timeout": 10000
            }
        },
        "id": 3
    }
    
    try:
        print("   Fetching https://example.com...")
        resp = requests.post(api_url, json=fetch_request, headers=headers, timeout=30)
        print(f"   Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = parse_sse_response(resp.text)
            if data:
                result = data.get('result', {})
                if 'content' in result:
                    content = result['content'][0]
                    print(f"   Success! Content type: {content.get('type')}")
                    print(f"   Content length: {len(content.get('text', ''))}")
                    print(f"   Content preview: {content.get('text', '')[:100]}...")
                else:
                    print(f"   Result: {json.dumps(result, indent=2)}")
            else:
                print("   Failed to parse SSE response")
        else:
            print(f"   Error: {resp.text}")
            
    except requests.exceptions.Timeout:
        print("   Request timed out!")
    except Exception as e:
        print(f"   Failed: {e}")
    
    print("\n✅ Fetcher MCP test complete!")

if __name__ == "__main__":
    test_fetcher_fetch_url()