#!/usr/bin/env python3
"""Basic proxy functionality test."""

import os
import sys
import time
import httpx
import json

# Load configuration from environment
base_url = os.getenv('BASE_URL')
if not base_url:
    print("Error: BASE_URL not set")
    sys.exit(1)

target_url = os.getenv('TEST_PROXY_TARGET_URL', 'https://example.com')
staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')

def test_proxy_basic():
    """Test basic proxy functionality."""
    # First, create a token
    print("1. Creating API token...")
    token_name = f"proxy-test-{int(time.time())}"
    
    # Generate token using subprocess
    import subprocess
    result = subprocess.run(
        ["docker", "exec", "mcp-http-proxy-acme-certmanager-1", 
         "pixi", "run", "python", "scripts/generate_token.py", token_name],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"Failed to generate token: {result.stderr}")
        return False
    
    # Extract token from output
    token = None
    for line in result.stdout.split('\n'):
        if line.startswith('Token:'):
            token = line.split()[1]
            break
    
    if not token:
        print("Failed to extract token from output")
        return False
    
    print(f"✓ Token created: {token[:20]}...")
    
    # Create proxy target
    print("\n2. Creating proxy target...")
    proxy_data = {
        "hostname": f"test-proxy-{int(time.time())}.atradev.org",
        "target_url": target_url,
        "cert_email": "test@atradev.org",
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
        
        result = response.json()
        print(f"✓ Proxy target created: {proxy_data['hostname']}")
        print(f"  Certificate status: {result.get('certificate_status', 'unknown')}")
        
        # List proxy targets
        print("\n3. Listing proxy targets...")
        response = httpx.get(f"{base_url}/proxy/targets", headers=headers)
        
        if response.status_code != 200:
            print(f"Failed to list proxy targets: {response.status_code}")
            return False
        
        targets = response.json()
        found = False
        for target in targets:
            if target['hostname'] == proxy_data['hostname']:
                found = True
                print(f"✓ Found proxy target in list")
                print(f"  Status: {target['enabled']}")
                print(f"  Target URL: {target['target_url']}")
                break
        
        if not found:
            print("✗ Proxy target not found in list")
            return False
        
        # Update proxy target
        print("\n4. Updating proxy target...")
        update_data = {
            "enabled": False
        }
        
        response = httpx.put(
            f"{base_url}/proxy/targets/{proxy_data['hostname']}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code != 200:
            print(f"Failed to update proxy target: {response.status_code}")
            return False
        
        print("✓ Proxy target disabled")
        
        # Delete proxy target
        print("\n5. Deleting proxy target...")
        response = httpx.delete(
            f"{base_url}/proxy/targets/{proxy_data['hostname']}?delete_certificate=true",
            headers=headers
        )
        
        if response.status_code != 200:
            print(f"Failed to delete proxy target: {response.status_code}")
            return False
        
        print("✓ Proxy target deleted")
        
        # Clean up token
        print("\n6. Cleaning up token...")
        subprocess.run(
            ["docker", "exec", "-i", "mcp-http-proxy-acme-certmanager-1",
             "pixi", "run", "python", "scripts/delete_token.py", token_name],
            input="yes\n", text=True, capture_output=True
        )
        print("✓ Token cleaned up")
        
        return True
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        # Try to clean up
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
    print("BASIC PROXY FUNCTIONALITY TEST")
    print("=" * 60)
    
    if test_proxy_basic():
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)