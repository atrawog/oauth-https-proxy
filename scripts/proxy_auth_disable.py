#!/usr/bin/env python3
"""Disable authentication for a proxy target."""

import argparse
import asyncio
import httpx
import sys
import os
from pathlib import Path

# Add parent directory to path to import from acme_certmanager
sys.path.insert(0, str(Path(__file__).parent.parent))


async def disable_proxy_auth(hostname: str, token: str):
    """Disable authentication for a proxy target."""
    api_url = os.getenv('API_URL', 'http://localhost')
    
    headers = {
        "Authorization": f"Bearer {token}",
    }
    
    async with httpx.AsyncClient() as client:
        # Send delete request to auth endpoint
        response = await client.delete(
            f"{api_url}/proxy/targets/{hostname}/auth",
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Auth disabled for {hostname}")
            return True
        elif response.status_code == 404:
            print(f"Error: Proxy target {hostname} not found")
            return False
        elif response.status_code == 401:
            print("Error: Invalid or missing authentication token")
            return False
        elif response.status_code == 403:
            print("Error: Not authorized to modify this proxy target")
            return False
        else:
            print(f"Error: Failed to disable auth (status: {response.status_code})")
            try:
                error = response.json()
                print(f"Details: {error}")
            except:
                print(f"Response: {response.text}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Disable authentication for a proxy target")
    parser.add_argument("hostname", help="Proxy hostname")
    parser.add_argument("token", help="API token")
    
    args = parser.parse_args()
    
    # Run async function
    success = asyncio.run(disable_proxy_auth(args.hostname, args.token))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()