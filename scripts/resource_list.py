#!/usr/bin/env python3
"""List protected resources."""

import os
import sys
import requests
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_utils import get_api_api_url, get_admin_token


def list_resources():
    """List all protected resources."""
    api_url = get_api_api_url()
    if not api_url:
        print("Error: Unable to determine API base URL")
        return False
    
    # Get token
    token = get_admin_token()
    if not token:
        print("Error: Admin token not found")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{api_url}/resources/", headers=headers, timeout=10)
        
        if response.status_code == 401:
            print("Error: Unauthorized - invalid or expired token")
            return False
        elif response.status_code == 404:
            print("Error: Resources endpoint not available")
            return False
        
        response.raise_for_status()
        
        resources = response.json()
        
        if not resources:
            print("No protected resources registered")
            print("\nTo register protected resources:")
            print("  just resource-register <uri> <proxy> <name> [scopes]")
            print("  just resource-auto-register")
            return True
        
        # Format for display
        table_data = []
        for resource in resources:
            scopes = resource.get("scopes", [])
            if scopes:
                scopes_str = ", ".join(scopes)
                if len(scopes_str) > 30:
                    scopes_str = scopes_str[:27] + "..."
            else:
                scopes_str = "none"
            
            uri = resource.get("uri", "")
            if len(uri) > 40:
                uri = uri[:37] + "..."
            
            proxy = resource.get("proxy_target", "")
            if len(proxy) > 25:
                proxy = proxy[:22] + "..."
            
            table_data.append([
                resource.get("name", ""),
                uri,
                proxy,
                scopes_str,
                "✓" if resource.get("metadata_url") else "✗"
            ])
        
        headers = ["Name", "Resource URI", "Proxy Target", "Scopes", "Metadata"]
        
        print(f"\n=== MCP Resources ({len(resources)} total) ===\n")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Show summary
        with_metadata = len([r for r in resources if r.get("metadata_url")])
        without_metadata = len(resources) - with_metadata
        
        print(f"\nSummary:")
        print(f"  Resources with metadata: {with_metadata}")
        if without_metadata > 0:
            print(f"  Resources without metadata: {without_metadata}")
        
        # Show unique scopes
        all_scopes = set()
        for resource in resources:
            all_scopes.update(resource.get("scopes", []))
        
        if all_scopes:
            print(f"\nAvailable scopes: {', '.join(sorted(all_scopes))}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to list resources: {e}")
        return False


if __name__ == "__main__":
    success = list_resources()
    sys.exit(0 if success else 1)