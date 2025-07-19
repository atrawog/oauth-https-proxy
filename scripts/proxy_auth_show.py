#!/usr/bin/env python3
"""Show authentication configuration for a proxy target."""

import argparse
import asyncio
import httpx
import sys
import os
from pathlib import Path
from tabulate import tabulate

# Add parent directory to path to import from acme_certmanager
sys.path.insert(0, str(Path(__file__).parent.parent))


async def show_proxy_auth(hostname: str):
    """Show authentication configuration for a proxy target."""
    base_url = os.getenv('BASE_URL', 'http://localhost')
    
    async with httpx.AsyncClient() as client:
        # Get auth config (public endpoint)
        response = await client.get(
            f"{base_url}/proxy/targets/{hostname}/auth"
        )
        
        if response.status_code == 200:
            config = response.json()
            
            # Format for display
            table_data = []
            table_data.append(["Auth Enabled", "✓" if config["auth_enabled"] else "✗"])
            
            if config["auth_enabled"]:
                table_data.append(["Auth Proxy", config.get("auth_proxy", "Not set")])
                table_data.append(["Auth Mode", config.get("auth_mode", "forward")])
                table_data.append(["Pass Headers", "✓" if config.get("auth_pass_headers", True) else "✗"])
                table_data.append(["Cookie Name", config.get("auth_cookie_name", "unified_auth_token")])
                table_data.append(["Header Prefix", config.get("auth_header_prefix", "X-Auth-")])
                
                # Requirements
                if config.get("auth_required_users"):
                    table_data.append(["Required Users", ", ".join(config["auth_required_users"])])
                else:
                    table_data.append(["Required Users", "Any authenticated user"])
                    
                if config.get("auth_required_emails"):
                    table_data.append(["Required Emails", ", ".join(config["auth_required_emails"])])
                else:
                    table_data.append(["Required Emails", "Any email"])
                    
                if config.get("auth_required_groups"):
                    table_data.append(["Required Groups", ", ".join(config["auth_required_groups"])])
                else:
                    table_data.append(["Required Groups", "Any group"])
            
            print(f"\nAuth Configuration for {hostname}:")
            print(tabulate(table_data, headers=["Setting", "Value"], tablefmt="simple"))
            
            if config["auth_enabled"]:
                print("\nAuth Flow:")
                if config.get("auth_mode") == "forward":
                    print("  1. Request arrives at proxy")
                    print("  2. Proxy checks auth via auth proxy /verify endpoint")
                    print("  3. If valid, request forwarded with auth headers")
                    print("  4. If invalid, returns 401 Unauthorized")
                elif config.get("auth_mode") == "redirect":
                    print("  1. Request arrives at proxy")
                    print("  2. Proxy checks auth via auth proxy /verify endpoint")
                    print("  3. If valid, request forwarded with auth headers")
                    print("  4. If invalid, redirects to auth proxy login page")
                elif config.get("auth_mode") == "passthrough":
                    print("  1. Request arrives at proxy")
                    print("  2. Proxy checks auth via auth proxy /verify endpoint")
                    print("  3. If valid, adds auth headers")
                    print("  4. Request always forwarded (auth optional)")
            
            return True
            
        elif response.status_code == 404:
            print(f"Error: Proxy target {hostname} not found")
            return False
        else:
            print(f"Error: Failed to get auth config (status: {response.status_code})")
            try:
                error = response.json()
                print(f"Details: {error}")
            except:
                print(f"Response: {response.text}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Show authentication configuration for a proxy target")
    parser.add_argument("hostname", help="Proxy hostname")
    
    args = parser.parse_args()
    
    # Run async function
    success = asyncio.run(show_proxy_auth(args.hostname))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()