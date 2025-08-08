#!/usr/bin/env python3
"""Clean up nonsensical localhost configurations."""

import os
import sys
import httpx
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_api_api_url, get_admin_token


def cleanup_localhost_configs():
    """Remove nonsensical localhost configurations."""
    api_url = get_api_api_url()
    if not api_url:
        print("Error: Unable to determine API base URL")
        return False
    
    # Get admin token
    token = get_admin_token()
    if not token:
        print("Error: Unable to get admin token")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    print("🧹 Cleaning up nonsensical localhost configurations...")
    print("=" * 60)
    
    # 1. Remove duplicate OAuth routes pointing to localhost
    duplicate_oauth_routes = [
        "verify-a741f6d3",      # Should use auth.atradev.org
        "jwks-b49a4a6a",        # Should use auth.atradev.org
        "token-ab2af70d",       # Should use auth.atradev.org
        "callback-29e91464",    # Should use auth.atradev.org
        "register-f554c19c",    # Should use auth.atradev.org
        "revoke-dfd9fa5a",      # Should use auth.atradev.org
        "introspect-bb00450a",  # Should use auth.atradev.org
        ".well-known-oauth-authorization-server-0e057d79"  # Should use auth.atradev.org
    ]
    
    print("\n1️⃣ Removing duplicate OAuth routes pointing to localhost...")
    for route_id in duplicate_oauth_routes:
        try:
            with httpx.Client() as client:
                response = client.delete(f"{api_url}/api/v1/routes/{route_id}", headers=headers, timeout=10)
                response.raise_for_status()
                print(f"   ✓ Deleted route: {route_id}")
        except httpx.HTTPError as e:
            if hasattr(e, 'response') and e.response.status_code == 404:
                print(f"   ⚠️  Route {route_id} not found (already deleted?)")
            else:
                print(f"   ✗ Failed to delete route {route_id}: {e}")
    
    # 2. Remove nonsensical proxy configurations
    bad_proxies = [
        "gui.atradev.org",   # Circular reference to localhost:80
        "auth.localhost"     # Points to non-existent auth:8000 service
    ]
    
    print("\n2️⃣ Removing nonsensical proxy configurations...")
    for hostname in bad_proxies:
        try:
            with httpx.Client() as client:
                response = client.delete(f"{api_url}/api/v1/proxy/targets/{hostname}", headers=headers, timeout=10)
                response.raise_for_status()
                print(f"   ✓ Deleted proxy: {hostname}")
        except httpx.HTTPError as e:
            if hasattr(e, 'response') and e.response.status_code == 404:
                print(f"   ⚠️  Proxy {hostname} not found (already deleted?)")
            else:
                print(f"   ✗ Failed to delete proxy {hostname}: {e}")
    
    # 3. Remove outdated instance
    print("\n3️⃣ Removing outdated instance configurations...")
    try:
        with httpx.Client() as client:
            response = client.delete(f"{api_url}/api/v1/instances/oauth-server", headers=headers, timeout=10)
            response.raise_for_status()
            print(f"   ✓ Deleted instance: oauth-server")
    except httpx.HTTPError as e:
        if hasattr(e, 'response') and e.response.status_code == 404:
            print(f"   ⚠️  Instance oauth-server not found (already deleted?)")
        else:
            print(f"   ✗ Failed to delete instance oauth-server: {e}")
    
    print("\n✅ Cleanup completed!")
    print("\nRemaining localhost routes (these are legitimate):")
    print("   - / (root) → Web interface")
    print("   - /.well-known/acme-challenge/ → ACME validation")
    print("   - /health → Health check endpoint")
    print("\nRemaining proxy:")
    print("   - auth.atradev.org → localhost:9000 (OAuth integration)")
    
    return True


if __name__ == "__main__":
    success = cleanup_localhost_configs()
    sys.exit(0 if success else 1)