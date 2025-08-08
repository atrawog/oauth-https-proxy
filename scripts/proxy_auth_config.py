#!/usr/bin/env python3
"""Configure authentication requirements for a proxy target."""

import argparse
import asyncio
import httpx
import sys
import os
from pathlib import Path
from typing import Optional, List

# Add parent directory to path to import from acme_certmanager
sys.path.insert(0, str(Path(__file__).parent.parent))


async def configure_proxy_auth(hostname: str, token: str, users: Optional[List[str]], 
                              emails: Optional[List[str]], groups: Optional[List[str]]):
    """Configure authentication requirements for a proxy target."""
    api_url = os.getenv('API_URL', 'http://localhost')
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        # First get current auth config
        response = await client.get(
            f"{api_url}/proxy/targets/{hostname}/auth",
            headers=headers
        )
        
        if response.status_code != 200:
            print(f"Error: Failed to get current auth config (status: {response.status_code})")
            return False
        
        current_config = response.json()
        
        # Update only specified fields
        config = {
            "enabled": current_config.get("auth_enabled", True),
            "auth_proxy": current_config.get("auth_proxy", f"auth.{os.getenv('BASE_DOMAIN', 'localhost')}"),
            "mode": current_config.get("auth_mode", "forward"),
            "pass_headers": current_config.get("auth_pass_headers", True),
            "cookie_name": current_config.get("auth_cookie_name", "unified_auth_token"),
            "header_prefix": current_config.get("auth_header_prefix", "X-Auth-")
        }
        
        # Update requirements if provided
        if users is not None:
            config["required_users"] = users
        else:
            config["required_users"] = current_config.get("auth_required_users")
            
        if emails is not None:
            config["required_emails"] = emails
        else:
            config["required_emails"] = current_config.get("auth_required_emails")
            
        if groups is not None:
            config["required_groups"] = groups
        else:
            config["required_groups"] = current_config.get("auth_required_groups")
        
        # Send updated configuration
        response = await client.post(
            f"{api_url}/proxy/targets/{hostname}/auth",
            json=config,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Auth requirements updated for {hostname}")
            
            if config.get("required_users"):
                print(f"  Required users: {', '.join(config['required_users'])}")
            if config.get("required_emails"):
                print(f"  Required emails: {', '.join(config['required_emails'])}")
            if config.get("required_groups"):
                print(f"  Required groups: {', '.join(config['required_groups'])}")
                
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
            print(f"Error: Failed to update auth config (status: {response.status_code})")
            try:
                error = response.json()
                print(f"Details: {error}")
            except:
                print(f"Response: {response.text}")
            return False


def parse_list(value: str) -> Optional[List[str]]:
    """Parse comma-separated list."""
    if not value:
        return None
    return [item.strip() for item in value.split(',') if item.strip()]


def main():
    parser = argparse.ArgumentParser(description="Configure authentication requirements for a proxy target")
    parser.add_argument("hostname", help="Proxy hostname")
    parser.add_argument("token", help="API token")
    parser.add_argument("--users", help="Comma-separated list of required usernames")
    parser.add_argument("--emails", help="Comma-separated list of required email patterns")
    parser.add_argument("--groups", help="Comma-separated list of required groups")
    
    args = parser.parse_args()
    
    # Parse lists
    users = parse_list(args.users) if args.users else None
    emails = parse_list(args.emails) if args.emails else None
    groups = parse_list(args.groups) if args.groups else None
    
    # Run async function
    success = asyncio.run(configure_proxy_auth(
        args.hostname, 
        args.token,
        users,
        emails,
        groups
    ))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()