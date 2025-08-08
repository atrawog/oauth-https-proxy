#!/usr/bin/env python3
"""Simple proxy test with echo endpoint."""

import os
import sys
import time
import httpx
import json
import subprocess

# Load configuration from environment
api_url = os.getenv('API_URL')
if not api_url:
    print("Error: API_URL not set")
    sys.exit(1)

staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')

def test_simple_proxy():
    """Test proxy with a simple echo endpoint."""
    # Create a token
    print("1. Creating API token...")
    token_name = f"simple-proxy-test-{int(time.time())}"
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
    
    # Create proxy target pointing to the health endpoint itself
    print("\n2. Creating proxy target...")
    proxy_hostname = "echo.localhost"
    proxy_data = {
        "hostname": proxy_hostname,
        "target_url": api_url,  # Point to itself for testing
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
        
        print(f"✓ Proxy target created: {proxy_hostname} → {proxy_data['target_url']}")
        
        # Test proxied health endpoint
        print("\n3. Testing proxy request to /health...")
        try:
            # Make request with Host header to trigger proxy
            proxy_headers = {"Host": proxy_hostname}
            response = httpx.get(
                f"http://localhost:80/health",
                headers=proxy_headers,
                timeout=5.0
            )
            
            if response.status_code == 200:
                data = response.json()
                print("  ✓ Health endpoint proxied successfully")
                print(f"    Status: {data.get('status', 'unknown')}")
                print(f"    Redis: {data.get('redis', 'unknown')}")
                print(f"    HTTPS enabled: {data.get('https_enabled', False)}")
            else:
                print(f"  ✗ Health request failed: {response.status_code}")
                print(f"    Response: {response.text[:200]}")
                return False
        except Exception as e:
            print(f"  ✗ Health request error: {e}")
            return False
        
        # Test disabled proxy
        print("\n4. Testing disabled proxy...")
        update_response = httpx.put(
            f"{api_url}/proxy/targets/{proxy_hostname}",
            json={"enabled": False},
            headers=headers
        )
        
        if update_response.status_code == 200:
            print("  ✓ Proxy disabled")
            
            # Try to access through disabled proxy
            try:
                response = httpx.get(
                    f"http://localhost:80/health",
                    headers=proxy_headers,
                    timeout=5.0
                )
                
                if response.status_code == 503:
                    print("  ✓ Disabled proxy returns 503 as expected")
                else:
                    print(f"  ✗ Unexpected status for disabled proxy: {response.status_code}")
            except Exception as e:
                print(f"  ✗ Disabled proxy test error: {e}")
        
        # Clean up
        print("\n5. Cleaning up...")
        response = httpx.delete(
            f"{api_url}/proxy/targets/{proxy_hostname}?delete_certificate=true",
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
    print("SIMPLE PROXY TEST")
    print("=" * 60)
    
    if test_simple_proxy():
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)