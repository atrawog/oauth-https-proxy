#!/usr/bin/env python3
"""Test authentication flow for a proxy target."""

import argparse
import asyncio
import httpx
import sys
import os
from pathlib import Path

# Add parent directory to path to import from acme_certmanager
sys.path.insert(0, str(Path(__file__).parent.parent))


async def test_auth_flow(hostname: str):
    """Test authentication flow for a proxy target."""
    print(f"\nTesting auth flow for {hostname}...")
    print("=" * 60)
    
    async with httpx.AsyncClient(follow_redirects=False) as client:
        # Test 1: Request without authentication
        print("\n1. Testing request without authentication...")
        try:
            response = await client.get(
                f"https://{hostname}/",
                verify=False  # Allow self-signed certs for testing
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                print("   ✓ Request succeeded (auth might be in passthrough mode)")
                # Check for auth headers
                print("\n   Checking for auth headers in response...")
                for header, value in response.headers.items():
                    if header.lower().startswith('x-auth-'):
                        print(f"   - {header}: {value}")
                        
            elif response.status_code == 401:
                print("   ✓ Got 401 Unauthorized (expected for forward mode)")
                if 'www-authenticate' in response.headers:
                    print(f"   WWW-Authenticate: {response.headers['www-authenticate']}")
                    
            elif response.status_code == 302:
                print("   ✓ Got redirect (expected for redirect mode)")
                if 'location' in response.headers:
                    print(f"   Redirect to: {response.headers['location']}")
                    
            else:
                print(f"   ✗ Unexpected status code: {response.status_code}")
                
        except httpx.ConnectError:
            print("   ✗ Failed to connect (is the proxy running?)")
            return False
        except Exception as e:
            print(f"   ✗ Error: {e}")
            return False
        
        # Test 2: Request with invalid token
        print("\n2. Testing request with invalid Bearer token...")
        try:
            response = await client.get(
                f"https://{hostname}/",
                headers={"Authorization": "Bearer invalid_token"},
                verify=False
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 401:
                print("   ✓ Got 401 Unauthorized (expected)")
            elif response.status_code == 302:
                print("   ✓ Got redirect (expected for redirect mode)")
            else:
                print(f"   ✗ Unexpected status code: {response.status_code}")
                
        except Exception as e:
            print(f"   ✗ Error: {e}")
            return False
        
        # Test 3: Check auth configuration
        print("\n3. Checking auth configuration...")
        try:
            # Get proxy target info through API
            base_url = os.getenv('BASE_URL', 'http://localhost')
            response = await client.get(
                f"{base_url}/proxy/targets/{hostname}/auth"
            )
            
            if response.status_code == 200:
                config = response.json()
                print(f"   Auth enabled: {'✓' if config['auth_enabled'] else '✗'}")
                if config['auth_enabled']:
                    print(f"   Auth proxy: {config.get('auth_proxy', 'Not set')}")
                    print(f"   Auth mode: {config.get('auth_mode', 'forward')}")
                    if config.get('auth_required_users'):
                        print(f"   Required users: {', '.join(config['auth_required_users'])}")
                    if config.get('auth_required_emails'):
                        print(f"   Required emails: {', '.join(config['auth_required_emails'])}")
            else:
                print(f"   Failed to get auth config (status: {response.status_code})")
                
        except Exception as e:
            print(f"   Error getting auth config: {e}")
    
    print("\n" + "=" * 60)
    print("Auth flow test completed")
    return True


def main():
    parser = argparse.ArgumentParser(description="Test authentication flow for a proxy target")
    parser.add_argument("hostname", help="Proxy hostname to test")
    
    args = parser.parse_args()
    
    # Run async function
    success = asyncio.run(test_auth_flow(args.hostname))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()