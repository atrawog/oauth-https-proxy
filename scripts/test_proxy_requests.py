#!/usr/bin/env python3
"""Test actual proxy request forwarding."""

import os
import sys
import time
import httpx
import json
import subprocess

# Load configuration from environment
base_url = os.getenv('BASE_URL')
if not base_url:
    print("Error: BASE_URL not set")
    sys.exit(1)

target_url = os.getenv('TEST_PROXY_TARGET_URL', 'https://example.com')
staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')

def test_proxy_requests():
    """Test actual proxy request forwarding."""
    # Create a simple HTTP server to test against
    print("1. Setting up test environment...")
    
    # Create a token
    token_name = f"proxy-req-test-{int(time.time())}"
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
    
    # Create proxy target pointing to example.com
    print("\n2. Creating proxy target...")
    proxy_hostname = "test-proxy.localhost"  # Using localhost for testing
    proxy_data = {
        "hostname": proxy_hostname,
        "target_url": target_url,
        "cert_email": "test@example.com",
        "acme_directory_url": staging_url,
        "preserve_host_header": False
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
        
        print(f"✓ Proxy target created: {proxy_hostname} → {proxy_data['target_url']}")
        
        # Test proxied requests
        print("\n3. Testing proxy requests...")
        
        # Test GET request
        print("  Testing GET /get...")
        try:
            # Make request with Host header to trigger proxy
            proxy_headers = {"Host": proxy_hostname}
            response = httpx.get(
                f"http://localhost:80/get",
                headers=proxy_headers,
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                print("  ✓ GET request proxied successfully")
                print(f"    Origin: {data.get('origin', 'unknown')}")
                print(f"    Headers received by target: {len(data.get('headers', {}))}")
            else:
                print(f"  ✗ GET request failed: {response.status_code}")
                print(f"    Response: {response.text[:200]}")
        except Exception as e:
            print(f"  ✗ GET request error: {e}")
        
        # Test POST request
        print("\n  Testing POST /post...")
        try:
            post_data = {"test": "data", "timestamp": int(time.time())}
            response = httpx.post(
                f"http://localhost:80/post",
                headers=proxy_headers,
                json=post_data,
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                print("  ✓ POST request proxied successfully")
                print(f"    Data echoed: {data.get('json', {})}")
            else:
                print(f"  ✗ POST request failed: {response.status_code}")
        except Exception as e:
            print(f"  ✗ POST request error: {e}")
        
        # Test headers forwarding
        print("\n  Testing header forwarding...")
        try:
            custom_headers = {
                "Host": proxy_hostname,
                "X-Custom-Header": "test-value",
                "User-Agent": "ProxyTest/1.0"
            }
            response = httpx.get(
                f"http://localhost:80/headers",
                headers=custom_headers,
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                headers = data.get('headers', {})
                print("  ✓ Headers forwarded successfully")
                print(f"    X-Forwarded-For: {headers.get('X-Forwarded-For', 'not set')}")
                print(f"    X-Forwarded-Proto: {headers.get('X-Forwarded-Proto', 'not set')}")
                print(f"    Custom header: {headers.get('X-Custom-Header', 'not forwarded')}")
            else:
                print(f"  ✗ Headers test failed: {response.status_code}")
        except Exception as e:
            print(f"  ✗ Headers test error: {e}")
        
        # Test non-existent proxy target
        print("\n4. Testing non-existent proxy target...")
        try:
            response = httpx.get(
                f"http://localhost:80/test",
                headers={"Host": "non-existent.localhost"},
                timeout=5.0
            )
            
            if response.status_code == 404:
                print("  ✓ Non-existent target returns 404 as expected")
            else:
                print(f"  ✗ Unexpected status code: {response.status_code}")
        except Exception as e:
            print(f"  ✗ Non-existent target test error: {e}")
        
        # Clean up
        print("\n5. Cleaning up...")
        response = httpx.delete(
            f"{base_url}/proxy/targets/{proxy_hostname}?delete_certificate=true",
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
        
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        # Clean up
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
    print("=" * 60)
    print("PROXY REQUEST FORWARDING TEST")
    print("=" * 60)
    
    if test_proxy_requests():
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)