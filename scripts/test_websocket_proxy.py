#!/usr/bin/env python3
"""Test WebSocket proxy functionality."""

import os
import sys
import time
import json
import subprocess
import asyncio
import websockets
from websockets.exceptions import WebSocketException
import httpx

# Load configuration from environment
base_url = os.getenv('BASE_URL')
if not base_url:
    print("Error: BASE_URL not set")
    sys.exit(1)

staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')

# Extract host and port from base URL
# Convert http://localhost:80 to ws://localhost:80
ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://")


async def test_websocket_echo():
    """Test WebSocket echo functionality."""
    try:
        # Echo.websocket.org echoes messages back
        uri = f"{ws_url}/echo"
        headers = {"Host": "echo.websocket.org"}
        
        print(f"Connecting to WebSocket echo server via proxy...")
        async with websockets.connect(uri, extra_headers=headers) as websocket:
            # Send test message
            test_message = "Hello WebSocket Proxy!"
            await websocket.send(test_message)
            print(f"Sent: {test_message}")
            
            # Receive echo
            response = await websocket.recv()
            print(f"Received: {response}")
            
            if response == test_message:
                print("✓ WebSocket echo test passed!")
                return True
            else:
                print("✗ Echo mismatch")
                return False
    except Exception as e:
        print(f"✗ WebSocket echo test failed: {e}")
        return False


async def test_websocket_streaming():
    """Test WebSocket streaming with multiple messages."""
    try:
        uri = f"{ws_url}/echo" 
        headers = {"Host": "echo.websocket.org"}
        
        print("\nTesting WebSocket streaming...")
        async with websockets.connect(uri, extra_headers=headers) as websocket:
            # Send multiple messages
            messages = [f"Message {i}" for i in range(5)]
            
            for msg in messages:
                await websocket.send(msg)
                print(f"Sent: {msg}")
                
                # Receive echo
                response = await websocket.recv()
                print(f"Received: {response}")
                
                if response != msg:
                    print("✗ Streaming test failed: message mismatch")
                    return False
            
            print("✓ WebSocket streaming test passed!")
            return True
    except Exception as e:
        print(f"✗ WebSocket streaming test failed: {e}")
        return False


async def test_websocket_binary():
    """Test WebSocket binary message handling."""
    try:
        uri = f"{ws_url}/echo"
        headers = {"Host": "echo.websocket.org"}
        
        print("\nTesting WebSocket binary messages...")
        async with websockets.connect(uri, extra_headers=headers) as websocket:
            # Send binary data
            binary_data = b"Binary test data \x00\x01\x02\x03"
            await websocket.send(binary_data)
            print(f"Sent binary: {len(binary_data)} bytes")
            
            # Receive echo
            response = await websocket.recv()
            print(f"Received binary: {len(response)} bytes")
            
            if response == binary_data:
                print("✓ WebSocket binary test passed!")
                return True
            else:
                print("✗ Binary data mismatch")
                return False
    except Exception as e:
        print(f"✗ WebSocket binary test failed: {e}")
        return False


async def main():
    """Run all WebSocket tests."""
    print("=" * 60)
    print("WEBSOCKET PROXY TEST")
    print("=" * 60)
    
    # First, create a proxy target for echo.websocket.org
    print("\n1. Setting up proxy target...")
    
    # Create a token
    token_name = f"ws-test-{int(time.time())}"
    result = subprocess.run(
        ["docker", "exec", "mcp-http-proxy-acme-certmanager-1", 
         "pixi", "run", "python", "scripts/generate_token.py", token_name],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"Failed to generate token: {result.stderr}")
        return False
    
    # Extract token
    token = None
    for line in result.stdout.split('\n'):
        if line.startswith('Token:'):
            token = line.split()[1]
            break
    
    if not token:
        print("Failed to extract token")
        return False
    
    print(f"✓ Token created")
    
    # Create proxy target for echo.websocket.org
    proxy_data = {
        "hostname": "echo.websocket.org",
        "target_url": "https://echo.websocket.org",
        "cert_email": "test@example.com",
        "acme_directory_url": staging_url,
        "preserve_host_header": True
    }
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = httpx.post(
            f"{base_url}/proxy/targets",
            json=proxy_data,
            headers=headers
        )
        
        if response.status_code != 200:
            print(f"Failed to create proxy target: {response.status_code}")
            print(response.text)
            return False
        
        print(f"✓ Proxy target created: {proxy_data['hostname']} → {proxy_data['target_url']}")
        
        # Wait a moment for the proxy to be ready
        await asyncio.sleep(2)
        
        # Run WebSocket tests
        print("\n2. Running WebSocket tests...")
        
        all_passed = True
        
        # Test 1: Echo test
        if not await test_websocket_echo():
            all_passed = False
        
        # Test 2: Streaming test
        if not await test_websocket_streaming():
            all_passed = False
        
        # Test 3: Binary test
        if not await test_websocket_binary():
            all_passed = False
        
        # Clean up
        print("\n3. Cleaning up...")
        response = httpx.delete(
            f"{base_url}/proxy/targets/{proxy_data['hostname']}?delete_certificate=true",
            headers=headers
        )
        
        if response.status_code == 200:
            print("  ✓ Proxy target deleted")
        else:
            print(f"  ✗ Failed to delete proxy target: {response.status_code}")
        
        # Delete token
        subprocess.run(
            ["docker", "exec", "-i", "mcp-http-proxy-acme-certmanager-1",
             "pixi", "run", "python", "scripts/delete_token.py", token_name],
            input="yes\n", text=True, capture_output=True
        )
        print("  ✓ Token cleaned up")
        
        return all_passed
        
    except Exception as e:
        print(f"Test setup failed: {e}")
        # Clean up token
        try:
            subprocess.run(
                ["docker", "exec", "-i", "mcp-http-proxy-acme-certmanager-1",
                 "pixi", "run", "python", "scripts/delete_token.py", token_name],
                input="yes\n", text=True, capture_output=True
            )
        except:
            pass
        return False


if __name__ == "__main__":
    if asyncio.run(main()):
        print("\n✅ All WebSocket tests passed!")
        sys.exit(0)
    else:
        print("\n❌ WebSocket tests failed!")
        sys.exit(1)