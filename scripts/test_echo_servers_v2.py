#!/usr/bin/env python3
"""Test echo MCP servers (stateless and stateful) with proper session handling."""

import json
import requests
import uuid

def test_echo_server(server_name, base_url, is_stateful=False):
    """Test an echo MCP server."""
    # Generate session ID
    session_id = str(uuid.uuid4())
    
    # Headers - start without session ID for stateful
    headers = {
        "Content-Type": "application/json"
    }
    
    # For stateless, include session ID from the start
    if not is_stateful:
        headers["Mcp-Session-Id"] = session_id
    
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
    print(f"Initial Session ID: {session_id if not is_stateful else 'None (will be assigned by server)'}")
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
            
            # For stateful server, get the session ID from response headers
            if is_stateful:
                response_session_id = resp.headers.get('Mcp-Session-Id')
                if response_session_id:
                    session_id = response_session_id
                    headers["Mcp-Session-Id"] = session_id
                    print(f"   ✓ Session ID assigned by server: {session_id}")
                else:
                    print(f"   ⚠️  No session ID in response headers, using: {session_id}")
                    headers["Mcp-Session-Id"] = session_id
            
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
            else:
                print(f"   ✗ Error: {resp.text}")
                
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
                content = result.get('content', [{}])[0].get('text', '')
                print(f"   ✓ Echo response: {content}")
            else:
                print(f"   ✗ Error: {resp.text}")
                
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
                    if any(keyword in line for keyword in ['Status:', 'Version:', 'Sessions:', 'Active sessions:']):
                        print(f"     {line.strip()}")
            else:
                print(f"   ✗ Error: {resp.text}")
                
            # For stateful server, test replayLastEcho
            if is_stateful:
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
    test_echo_server("Echo Stateless", "http://echo-stateless.atradev.org/mcp", is_stateful=False)
    
    # Test stateful server
    test_echo_server("Echo Stateful", "http://echo-stateful.atradev.org/mcp", is_stateful=True)
    
    print("\n" + "=" * 60)
    print("✅ All echo server tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()