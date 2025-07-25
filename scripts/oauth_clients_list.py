#!/usr/bin/env python3
"""List OAuth clients."""

import os
import sys
import requests
from datetime import datetime
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_utils import get_api_base_url, get_admin_token


def list_oauth_clients(active_only: bool = False):
    """List all OAuth clients."""
    base_url = get_api_base_url()
    if not base_url:
        print("Error: Unable to determine API base URL")
        return False
    
    # Get token
    token = get_admin_token()
    if not token:
        print("Error: Admin token not found")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{base_url}/oauth/clients", headers=headers, timeout=10)
        
        if response.status_code == 401:
            print("Error: Unauthorized - invalid or expired token")
            return False
        elif response.status_code == 404:
            print("Error: OAuth endpoints not available")
            return False
        
        response.raise_for_status()
        
        data = response.json()
        clients = data.get("clients", [])
        
        if not clients:
            print("No OAuth clients registered")
            return True
        
        # Filter if active_only
        if active_only:
            clients = [c for c in clients if c.get("is_active", True)]
        
        # Format for display
        table_data = []
        for client in clients:
            created = client.get("created_at", "")
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    created = created_dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            expires = client.get("expires_at", "")
            if expires:
                try:
                    expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                    expires = expires_dt.strftime("%Y-%m-%d")
                except:
                    pass
            else:
                expires = "Never"
            
            status = "✓ Active" if client.get("is_active", True) else "✗ Inactive"
            
            table_data.append([
                client.get("client_id", ""),
                client.get("client_name", ""),
                status,
                client.get("token_count", 0),
                created,
                expires
            ])
        
        headers = ["Client ID", "Client Name", "Status", "Tokens", "Created", "Expires"]
        
        print(f"\n=== OAuth Clients ({len(clients)} total) ===\n")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Show summary
        active_count = len([c for c in clients if c.get("is_active", True)])
        inactive_count = len(clients) - active_count
        total_tokens = sum(c.get("token_count", 0) for c in clients)
        
        print(f"\nSummary:")
        print(f"  Active clients: {active_count}")
        if inactive_count > 0:
            print(f"  Inactive clients: {inactive_count}")
        print(f"  Total tokens issued: {total_tokens}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to list OAuth clients: {e}")
        return False


if __name__ == "__main__":
    # Check for active-only flag
    active_only = "--active-only" in sys.argv or "-a" in sys.argv
    success = list_oauth_clients(active_only)
    sys.exit(0 if success else 1)