#!/usr/bin/env python3
"""Enable authentication for a proxy target."""

import argparse
import asyncio
import httpx
import sys
import os
from pathlib import Path

# Add parent directory to path to import from acme_certmanager
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shared.models import ProxyAuthConfig


async def enable_proxy_auth(hostname: str, token: str, auth_proxy: str, mode: str):
    """Enable authentication for a proxy target."""
    base_url = os.getenv('BASE_URL', 'http://localhost')
    
    # Configure auth
    config = {
        "enabled": True,
        "auth_proxy": auth_proxy,
        "mode": mode,
        "pass_headers": True,
        "cookie_name": "unified_auth_token",
        "header_prefix": "X-Auth-"
    }
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        # Send auth configuration
        response = await client.post(
            f"{base_url}/proxy/targets/{hostname}/auth",
            json=config,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Auth enabled for {hostname}")
            print(f"  Auth proxy: {auth_proxy}")
            print(f"  Mode: {mode}")
            return True
        elif response.status_code == 404:
            print(f"Error: Proxy target {hostname} not found")
            return False
        elif response.status_code == 400:
            error = response.json()
            print(f"Error: {error['detail']}")
            return False
        elif response.status_code == 401:
            print("Error: Invalid or missing authentication token")
            return False
        elif response.status_code == 403:
            print("Error: Not authorized to modify this proxy target")
            return False
        else:
            print(f"Error: Failed to enable auth (status: {response.status_code})")
            try:
                error = response.json()
                print(f"Details: {error}")
            except:
                print(f"Response: {response.text}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Enable authentication for a proxy target")
    parser.add_argument("hostname", help="Proxy hostname")
    parser.add_argument("token", help="API token")
    parser.add_argument("--auth-proxy", default=f"auth.{os.getenv('BASE_DOMAIN', 'localhost')}", 
                       help="Auth proxy hostname")
    parser.add_argument("--mode", choices=["forward", "redirect", "passthrough"], 
                       default="forward", help="Auth mode")
    
    args = parser.parse_args()
    
    # Run async function
    success = asyncio.run(enable_proxy_auth(
        args.hostname, 
        args.token, 
        args.auth_proxy,
        args.mode
    ))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()