#!/usr/bin/env python3
"""Setup OAuth routes for authentication."""

import os
import sys
import json
import time
import hashlib
import secrets
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.test_utils import run_command, get_admin_token


def setup_oauth_routes(auth_domain: str, token: str = None) -> bool:
    """Setup all OAuth routes for the given authentication domain.
    
    Args:
        auth_domain: The domain where OAuth server is hosted (e.g., auth.example.com)
        token: Optional authentication token. If not provided, uses ADMIN token.
    
    Returns:
        bool: True if all routes were created successfully
    """
    if not token:
        token = os.getenv("ADMIN_TOKEN")
        if not token:
            print("Error: No token provided and ADMIN_TOKEN not found in environment")
            return False
    
    # OAuth routes configuration
    oauth_routes = [
        {
            "path": "/authorize",
            "description": "OAuth authorization endpoint"
        },
        {
            "path": "/token",
            "description": "OAuth token endpoint"
        },
        {
            "path": "/callback",
            "description": "OAuth callback endpoint"
        },
        {
            "path": "/register",
            "description": "OAuth client registration"
        },
        {
            "path": "/verify",
            "description": "ForwardAuth verification"
        },
        {
            "path": "/.well-known/oauth-authorization-server",
            "description": "OAuth server metadata"
        },
        {
            "path": "/jwks",
            "description": "JSON Web Key Set"
        },
        {
            "path": "/revoke",
            "description": "Token revocation"
        },
        {
            "path": "/introspect",
            "description": "Token introspection"
        }
    ]
    
    success_count = 0
    failed_routes = []
    
    print(f"Setting up OAuth routes for {auth_domain}")
    print("=" * 60)
    
    for route in oauth_routes:
        # Generate unique route ID
        route_id = f"{route['path'].replace('/', '-').replace('.', '-').strip('-')}-{hashlib.md5(f'{route["path"]}{time.time()}'.encode()).hexdigest()[:8]}"
        
        # Create route command (positional arguments)
        cmd = [
            "python", "scripts/route_create.py",
            route['path'],        # path
            "hostname",           # target-type
            auth_domain,          # target-value
            token,                # token
            "95",                 # priority
            "",                   # methods (empty = all)
            "false",              # is-regex
            route['description']  # description
        ]
        
        print(f"\nCreating route: {route['path']} -> {auth_domain}")
        result = run_command(" ".join(cmd))
        
        if result["success"]:
            print(f"✓ Created successfully")
            success_count += 1
        else:
            # Check if route already exists
            if "already exists" in result["stderr"]:
                print(f"✓ Route already exists")
                success_count += 1
            else:
                print(f"✗ Failed: {result['stderr']}")
                failed_routes.append(route['path'])
    
    print("\n" + "=" * 60)
    print(f"Summary: {success_count}/{len(oauth_routes)} routes configured")
    
    if failed_routes:
        print(f"\nFailed routes:")
        for route in failed_routes:
            print(f"  - {route}")
        return False
    
    print(f"\n✅ All OAuth routes configured successfully for {auth_domain}")
    return True


def cleanup_oauth_routes(auth_domain: str, token: str = None) -> bool:
    """Remove all OAuth routes for the given authentication domain.
    
    Args:
        auth_domain: The domain where OAuth server is hosted
        token: Optional authentication token
    
    Returns:
        bool: True if cleanup was successful
    """
    if not token:
        token = os.getenv("ADMIN_TOKEN")
        if not token:
            print("Error: No token provided and ADMIN_TOKEN not found in environment")
            return False
    
    # List all routes
    result = run_command("just route-list")
    if not result["success"]:
        print(f"Failed to list routes: {result['stderr']}")
        return False
    
    # Parse routes and find OAuth routes for this domain
    routes_to_delete = []
    lines = result["stdout"].split("\n")
    
    for line in lines:
        if f"hostname:{auth_domain}" in line:
            # Extract route ID from the line
            parts = line.split("|")
            if len(parts) > 2:
                route_id = parts[1].strip()
                routes_to_delete.append(route_id)
    
    if not routes_to_delete:
        print(f"No OAuth routes found for {auth_domain}")
        return True
    
    print(f"Found {len(routes_to_delete)} OAuth routes to remove")
    
    success_count = 0
    for route_id in routes_to_delete:
        cmd = f'just route-delete "{route_id}" "{token}"'
        result = run_command(cmd)
        if result["success"]:
            print(f"✓ Deleted route: {route_id}")
            success_count += 1
        else:
            print(f"✗ Failed to delete route {route_id}: {result['stderr']}")
    
    return success_count == len(routes_to_delete)


def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) < 2:
        print("Usage: oauth_routes_setup.py <auth_domain> [token] [cleanup]")
        print("  auth_domain: The domain where OAuth server is hosted (e.g., auth.example.com)")
        print("  token: Optional authentication token (uses ADMIN_TOKEN if not provided)")
        print("  cleanup: Optional flag to remove OAuth routes instead of creating them")
        sys.exit(1)
    
    auth_domain = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "cleanup" else None
    cleanup = "cleanup" in sys.argv
    
    if cleanup:
        success = cleanup_oauth_routes(auth_domain, token)
    else:
        success = setup_oauth_routes(auth_domain, token)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()