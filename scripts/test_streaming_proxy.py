#!/usr/bin/env python3
"""Test streaming and Server-Sent Events (SSE) proxy functionality."""

import os
import sys
import time
import json
import subprocess
import asyncio
import httpx

# Load configuration from environment
api_url = os.getenv('API_URL')
if not api_url:
    print("Error: API_URL not set")
    sys.exit(1)

target_url = os.getenv('TEST_PROXY_TARGET_URL', 'https://example.com')
staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')


async def test_chunked_response():
    """Test proxying of chunked transfer encoding."""
    print("\n1. Testing chunked transfer encoding...")
    
    # httpbin.org/stream/{n} returns n JSON objects with chunked encoding
    proxy_headers = {"Host": "stream-test.localhost"}
    
    try:
        async with httpx.AsyncClient() as client:
            # Test streaming response
            chunks_received = 0
            async with client.stream(
                "GET",
                f"http://localhost:80/stream/5",
                headers=proxy_headers,
                timeout=10.0
            ) as response:
                if response.status_code == 200:
                    async for line in response.aiter_lines():
                        if line:
                            chunks_received += 1
                            data = json.loads(line)
                            print(f"  Received chunk {chunks_received}: id={data.get('id', 'unknown')}")
                    
                    if chunks_received == 5:
                        print("  ✓ Chunked transfer test passed!")
                        return True
                    else:
                        print(f"  ✗ Expected 5 chunks, got {chunks_received}")
                        return False
                else:
                    print(f"  ✗ Stream request failed: {response.status_code}")
                    return False
    except Exception as e:
        print(f"  ✗ Chunked transfer test error: {e}")
        return False


async def test_sse_streaming():
    """Test Server-Sent Events streaming."""
    print("\n2. Testing Server-Sent Events (SSE)...")
    
    # Create a simple SSE endpoint simulation using httpbin's /stream-bytes
    proxy_headers = {"Host": "stream-test.localhost"}
    
    try:
        async with httpx.AsyncClient() as client:
            # Test SSE-like streaming
            bytes_received = 0
            async with client.stream(
                "GET",
                f"http://localhost:80/stream-bytes/1024?chunk_size=128",
                headers=proxy_headers,
                timeout=10.0
            ) as response:
                if response.status_code == 200:
                    async for chunk in response.aiter_bytes(chunk_size=128):
                        bytes_received += len(chunk)
                        print(f"  Received {len(chunk)} bytes (total: {bytes_received})")
                    
                    if bytes_received == 1024:
                        print("  ✓ SSE streaming test passed!")
                        return True
                    else:
                        print(f"  ✗ Expected 1024 bytes, got {bytes_received}")
                        return False
                else:
                    print(f"  ✗ SSE request failed: {response.status_code}")
                    return False
    except Exception as e:
        print(f"  ✗ SSE streaming test error: {e}")
        return False


async def test_large_response_streaming():
    """Test streaming of large responses."""
    print("\n3. Testing large response streaming...")
    
    proxy_headers = {"Host": "stream-test.localhost"}
    
    try:
        async with httpx.AsyncClient() as client:
            # Test large response streaming (10MB)
            size_mb = 10
            expected_bytes = size_mb * 1024 * 1024
            bytes_received = 0
            start_time = time.time()
            
            async with client.stream(
                "GET",
                f"http://localhost:80/bytes/{expected_bytes}",
                headers=proxy_headers,
                timeout=30.0
            ) as response:
                if response.status_code == 200:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        bytes_received += len(chunk)
                        if bytes_received % (1024 * 1024) == 0:
                            mb_received = bytes_received / (1024 * 1024)
                            elapsed = time.time() - start_time
                            speed = mb_received / elapsed if elapsed > 0 else 0
                            print(f"  Progress: {mb_received:.0f}MB ({speed:.1f} MB/s)")
                    
                    elapsed = time.time() - start_time
                    speed = (bytes_received / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                    
                    if bytes_received == expected_bytes:
                        print(f"  ✓ Large response test passed! ({size_mb}MB in {elapsed:.1f}s, {speed:.1f} MB/s)")
                        return True
                    else:
                        print(f"  ✗ Expected {expected_bytes} bytes, got {bytes_received}")
                        return False
                else:
                    print(f"  ✗ Large response request failed: {response.status_code}")
                    return False
    except Exception as e:
        print(f"  ✗ Large response test error: {e}")
        return False


async def test_slow_response():
    """Test handling of slow/dripping responses."""
    print("\n4. Testing slow response handling...")
    
    proxy_headers = {"Host": "stream-test.localhost"}
    
    try:
        async with httpx.AsyncClient() as client:
            # httpbin.org/drip returns data slowly
            start_time = time.time()
            bytes_received = 0
            
            async with client.stream(
                "GET",
                f"http://localhost:80/drip?duration=3&numbytes=100&code=200",
                headers=proxy_headers,
                timeout=10.0
            ) as response:
                if response.status_code == 200:
                    async for chunk in response.aiter_bytes():
                        bytes_received += len(chunk)
                        elapsed = time.time() - start_time
                        print(f"  Received {len(chunk)} bytes after {elapsed:.1f}s")
                    
                    total_time = time.time() - start_time
                    if bytes_received == 100 and total_time >= 2.5:
                        print(f"  ✓ Slow response test passed! (100 bytes in {total_time:.1f}s)")
                        return True
                    else:
                        print(f"  ✗ Unexpected result: {bytes_received} bytes in {total_time:.1f}s")
                        return False
                else:
                    print(f"  ✗ Slow response request failed: {response.status_code}")
                    return False
    except Exception as e:
        print(f"  ✗ Slow response test error: {e}")
        return False


async def main():
    """Run all streaming tests."""
    print("=" * 60)
    print("STREAMING PROXY TEST")
    print("=" * 60)
    
    # Create a token
    print("\n1. Setting up test environment...")
    token_name = f"stream-test-{int(time.time())}"
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
    
    # Create proxy target for example.com (for streaming tests)
    proxy_data = {
        "hostname": "stream-test.localhost",
        "target_url": target_url,
        "cert_email": "test@example.com",
        "acme_directory_url": staging_url,
        "preserve_host_header": False
    }
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = httpx.post(
            f"{api_url}/proxy/targets",
            json=proxy_data,
            headers=headers
        )
        
        if response.status_code != 200:
            print(f"Failed to create proxy target: {response.status_code}")
            print(response.text)
            return False
        
        print(f"✓ Proxy target created: {proxy_data['hostname']} → {proxy_data['target_url']}")
        
        # Run streaming tests
        print("\n2. Running streaming tests...")
        
        all_passed = True
        
        # Test 1: Chunked transfer encoding
        if not await test_chunked_response():
            all_passed = False
        
        # Test 2: SSE-like streaming
        if not await test_sse_streaming():
            all_passed = False
        
        # Test 3: Large response streaming
        if not await test_large_response_streaming():
            all_passed = False
        
        # Test 4: Slow/dripping response
        if not await test_slow_response():
            all_passed = False
        
        # Clean up
        print("\n3. Cleaning up...")
        response = httpx.delete(
            f"{api_url}/proxy/targets/{proxy_data['hostname']}?delete_certificate=true",
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
        print("\n✅ All streaming tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Streaming tests failed!")
        sys.exit(1)