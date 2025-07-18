#!/usr/bin/env python3
"""Test echo MCP servers (stateless and stateful) directly."""

import json
import requests
import uuid

def test_echo_server(server_name, base_url):
    """Test an echo MCP server."""
    # Generate session ID
    session_id = str(uuid.uuid4())
    
    # Headers with session ID
    headers = {
        "Content-Type": "application/json",
        "Mcp-Session-Id": session_id
    }
    
    # Initialize request with correct protocol version
    init_request = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",  # Use correct version
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
    
    print(f"\n{'=' * 60}")
    print(f"Testing {server_name} MCP endpoint...")
    print(f"URL: {base_url}")
    print(f"Session ID: {session_id}")
    print('=' * 60)
    
    # Send initialize request
    print("\n1. Sending initialize request...")
    try:
        resp = requests.post(base_url, json=init_request, headers=headers)
        print(f"   Status: {resp.status_code}")
        
        if resp.status_code == 200:
            # Parse response
            data = resp.json()
            print(f"   ✓ Protocol Version: {data.get('result', {}).get('protocolVersion')}")
            print(f"   ✓ Server: {data.get('result', {}).get('serverInfo', {}).get('name')}")
            
            # List tools
            print("\n2. Listing available tools...")
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
                print(f"   ✓ Found {len(tools)} tools:")
                for tool in tools:
                    print(f"     - {tool.get('name')}: {tool.get('description', '')[:60]}...")
            
            # Test echo tool
            print("\n3. Testing echo tool...")
            echo_request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {
                        "message": "Hello from test client!"
                    }
                },
                "id": 3
            }
            
            resp = requests.post(base_url, json=echo_request, headers=headers)
            print(f"   Status: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                result = data.get('result', {})
                print(f"   ✓ Echo response: {result.get('content', [{}])[0].get('text', '')}")
            
            # Test healthProbe tool
            print("\n4. Testing healthProbe tool...")
            health_request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "healthProbe",
                    "arguments": {}
                },
                "id": 4
            }
            
            resp = requests.post(base_url, json=health_request, headers=headers)
            print(f"   Status: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                result = data.get('result', {})
                content = result.get('content', [{}])[0].get('text', '')
                print(f"   ✓ Health status:")
                # Parse and display key health info
                for line in content.split('\n'):
                    if 'Status:' in line or 'Version:' in line or 'Sessions:' in line:
                        print(f"     {line.strip()}")
            
            # For stateful server, test replayLastEcho
            if "stateful" in server_name.lower():
                print("\n5. Testing replayLastEcho tool (stateful only)...")
                replay_request = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "replayLastEcho",
                        "arguments": {}
                    },
                    "id": 5
                }
                
                resp = requests.post(base_url, json=replay_request, headers=headers)
                print(f"   Status: {resp.status_code}")
                
                if resp.status_code == 200:
                    data = resp.json()
                    result = data.get('result', {})
                    content = result.get('content', [{}])[0].get('text', '')
                    print(f"   ✓ Replay response: {content}")
                
        else:
            print(f"   ✗ Error: {resp.text}")
            
    except Exception as e:
        print(f"   ✗ Failed: {e}")
        
    print(f"\n✓ {server_name} test completed!")

def main():
    """Test both echo servers."""
    print("MCP Echo Server Testing")
    print("=" * 60)
    
    # Test stateless server
    test_echo_server("Echo Stateless", "http://echo-stateless.atradev.org/mcp")
    
    # Test stateful server
    test_echo_server("Echo Stateful", "http://echo-stateful.atradev.org/mcp")
    
    print("\n" + "=" * 60)
    print("✅ All echo server tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()