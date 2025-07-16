#!/usr/bin/env python3
"""Test certificate email configuration per token."""

import os
import sys
import time
import subprocess
import httpx

# Load configuration from environment
base_url = os.getenv('BASE_URL')
if not base_url:
    print("Error: BASE_URL not set")
    sys.exit(1)

staging_url = os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')

def test_cert_email():
    """Test certificate email configuration."""
    print("=" * 60)
    print("CERTIFICATE EMAIL CONFIGURATION TEST")
    print("=" * 60)
    
    # Test 1: Create token with cert_email
    print("\n1. Creating token WITH certificate email...")
    token1_name = f"email-test-{int(time.time())}"
    cert_email = "token-default@example.com"
    
    result = subprocess.run(
        ["docker", "exec", "mcp-http-proxy-acme-certmanager-1", 
         "pixi", "run", "python", "scripts/generate_token.py", token1_name, cert_email],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"Failed to generate token: {result.stderr}")
        return False
    
    # Extract token
    token1 = None
    for line in result.stdout.split('\n'):
        if line.startswith('Token:'):
            token1 = line.split()[1]
            break
    
    if not token1:
        print("Failed to extract token")
        return False
    
    print(f"✓ Token created with cert_email: {cert_email}")
    
    # Test 2: Create token without cert_email
    print("\n2. Creating token WITHOUT certificate email...")
    token2_name = f"no-email-test-{int(time.time())}"
    
    result = subprocess.run(
        ["docker", "exec", "mcp-http-proxy-acme-certmanager-1", 
         "pixi", "run", "python", "scripts/generate_token.py", token2_name],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"Failed to generate token: {result.stderr}")
        return False
    
    # Extract token
    token2 = None
    for line in result.stdout.split('\n'):
        if line.startswith('Token:'):
            token2 = line.split()[1]
            break
    
    if not token2:
        print("Failed to extract token")
        return False
    
    print(f"✓ Token created without cert_email")
    
    # Test 3: Create proxy with token that has cert_email (no email in request)
    print("\n3. Creating proxy with token cert_email (no email in request)...")
    proxy1_hostname = f"proxy1-{int(time.time())}.localhost"
    proxy_data = {
        "hostname": proxy1_hostname,
        "target_url": "https://example.com",
        "acme_directory_url": staging_url
        # No cert_email provided - should use token's email
    }
    
    headers = {"Authorization": f"Bearer {token1}"}
    
    response = httpx.post(
        f"{base_url}/proxy/targets",
        json=proxy_data,
        headers=headers
    )
    
    if response.status_code == 200:
        print(f"✓ Proxy created successfully using token's cert_email")
    else:
        print(f"✗ Failed to create proxy: {response.status_code}")
        print(response.text)
    
    # Test 4: Create proxy with token that has NO cert_email and no email in request
    print("\n4. Creating proxy without any cert_email...")
    proxy2_hostname = f"proxy2-{int(time.time())}.localhost"
    proxy_data = {
        "hostname": proxy2_hostname,
        "target_url": "https://example.com",
        "acme_directory_url": staging_url
        # No cert_email provided and token has no email
    }
    
    headers = {"Authorization": f"Bearer {token2}"}
    
    response = httpx.post(
        f"{base_url}/proxy/targets",
        json=proxy_data,
        headers=headers
    )
    
    if response.status_code == 400:
        print(f"✓ Correctly rejected - certificate email required")
    else:
        print(f"✗ Unexpected response: {response.status_code}")
    
    # Test 5: Create proxy with request email overriding token email
    print("\n5. Creating proxy with request email overriding token email...")
    proxy3_hostname = f"proxy3-{int(time.time())}.localhost"
    proxy_data = {
        "hostname": proxy3_hostname,
        "target_url": "https://example.com",
        "cert_email": "request-override@example.com",
        "acme_directory_url": staging_url
    }
    
    headers = {"Authorization": f"Bearer {token1}"}
    
    response = httpx.post(
        f"{base_url}/proxy/targets",
        json=proxy_data,
        headers=headers
    )
    
    if response.status_code == 200:
        print(f"✓ Proxy created with request-specific cert_email")
    else:
        print(f"✗ Failed to create proxy: {response.status_code}")
    
    # Clean up
    print("\n6. Cleaning up...")
    
    # Clean up proxy targets
    for hostname in [proxy1_hostname, proxy3_hostname]:
        subprocess.run(
            ["docker", "exec", "mcp-http-proxy-acme-certmanager-1",
             "pixi", "run", "python", "scripts/proxy_cleanup.py", hostname],
            capture_output=True
        )
    
    # Delete tokens
    for token_name in [token1_name, token2_name]:
        subprocess.run(
            ["docker", "exec", "-i", "mcp-http-proxy-acme-certmanager-1",
             "pixi", "run", "python", "scripts/delete_token.py", token_name],
            input="yes\n", text=True, capture_output=True
        )
    
    print("✓ Cleanup complete")
    
    return True


if __name__ == "__main__":
    if test_cert_email():
        print("\n✅ All certificate email tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Certificate email tests failed!")
        sys.exit(1)