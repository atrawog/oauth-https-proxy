#!/usr/bin/env python3
"""Test proxy forwarding to example.com."""

import os
import sys
import time
import httpx
import subprocess

# Load configuration from environment
base_url = os.getenv('BASE_URL')
if not base_url:
    print("Error: BASE_URL not set")
    sys.exit(1)

target_url = os.getenv('TEST_PROXY_TARGET_URL', 'https://example.com')
staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')

def test_proxy_example():
    """Test proxy forwarding to example.com."""
    print("1. Setting up test environment...")
    
    # Create a token
    token_name = f"proxy-example-test-{int(time.time())}"
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
    
    # Create proxy target
    print("\n2. Creating proxy target...")
    proxy_hostname = "example-proxy.localhost"
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
        
        print(f"✓ Proxy target created: {proxy_hostname} → {target_url}")
        
        # Test proxied request to homepage
        print("\n3. Testing proxy request to homepage...")
        proxy_headers = {"Host": proxy_hostname}
        
        try:
            response = httpx.get(
                f"http://localhost:80/",
                headers=proxy_headers,
                timeout=10.0
            )
            
            if response.status_code == 200:
                # Check if we got the example.com page
                if "Example Domain" in response.text:
                    print("  ✓ Successfully proxied request to example.com")
                    print(f"  ✓ Response contains: Example Domain")
                    print(f"  ✓ Response length: {len(response.text)} bytes")
                    success = True
                else:
                    print("  ✗ Unexpected response content")
                    print(f"  Response preview: {response.text[:200]}...")
                    success = False
            else:
                print(f"  ✗ Request failed: {response.status_code}")
                success = False
                
        except Exception as e:
            print(f"  ✗ Request error: {e}")
            success = False
        
        # Clean up
        print("\n4. Cleaning up...")
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
        
        return success
        
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
    print("PROXY EXAMPLE.COM TEST")
    print("=" * 60)
    
    if test_proxy_example():
        print("\n✅ Test passed!")
        sys.exit(0)
    else:
        print("\n❌ Test failed!")
        sys.exit(1)