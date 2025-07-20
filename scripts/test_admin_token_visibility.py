#!/usr/bin/env python3
"""Test admin token visibility for routes."""

import os
import sys
import requests
from tabulate import tabulate

def test_route_visibility():
    """Test route visibility for admin token."""
    base_url = os.getenv('BASE_URL', 'http://localhost')
    admin_token = os.getenv('ADMIN_TOKEN')
    
    if not admin_token:
        print("Error: ADMIN_TOKEN must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Test routes endpoint
    print("\n=== Testing /routes endpoint with admin token ===")
    try:
        response = requests.get(f"{base_url}/routes", headers=headers)
        response.raise_for_status()
        routes = response.json()
        
        print(f"\nTotal routes visible to admin: {len(routes)}")
        
        if routes:
            table_data = []
            for route in routes:
                table_data.append([
                    route.get('route_id', 'N/A'),
                    route.get('path_pattern', 'N/A'),
                    route.get('priority', 'N/A'),
                    route.get('owner_token_hash', 'N/A')[:16] + '...' if route.get('owner_token_hash') else 'None',
                    route.get('created_by', 'N/A')
                ])
            
            print(tabulate(table_data, 
                         headers=['Route ID', 'Path Pattern', 'Priority', 'Owner Hash', 'Created By'],
                         tablefmt='grid'))
        else:
            print("No routes found!")
            
    except Exception as e:
        print(f"Error fetching routes: {e}")
        return False
    
    # Test certificates endpoint
    print("\n=== Testing /certificates endpoint with admin token ===")
    try:
        response = requests.get(f"{base_url}/certificates", headers=headers)
        response.raise_for_status()
        certs = response.json()
        
        print(f"\nTotal certificates visible to admin: {len(certs)}")
        
        if certs:
            table_data = []
            for cert in certs:
                table_data.append([
                    cert.get('cert_name', 'N/A'),
                    ', '.join(cert.get('domains', [])) if cert.get('domains') else 'N/A',
                    cert.get('owner_token_hash', 'N/A')[:16] + '...' if cert.get('owner_token_hash') else 'None',
                    cert.get('created_by', 'N/A')
                ])
            
            print(tabulate(table_data, 
                         headers=['Cert Name', 'Domains', 'Owner Hash', 'Created By'],
                         tablefmt='grid'))
        
    except Exception as e:
        print(f"Error fetching certificates: {e}")
    
    # Test proxy targets endpoint
    print("\n=== Testing /proxy/targets endpoint with admin token ===")
    try:
        response = requests.get(f"{base_url}/proxy/targets", headers=headers)
        response.raise_for_status()
        targets = response.json()
        
        print(f"\nTotal proxy targets visible to admin: {len(targets)}")
        
        if targets:
            table_data = []
            for target in targets:
                table_data.append([
                    target.get('hostname', 'N/A'),
                    target.get('target_url', 'N/A'),
                    target.get('owner_token_hash', 'N/A')[:16] + '...' if target.get('owner_token_hash') else 'None',
                    target.get('created_by', 'N/A')
                ])
            
            print(tabulate(table_data, 
                         headers=['Hostname', 'Target URL', 'Owner Hash', 'Created By'],
                         tablefmt='grid'))
        
    except Exception as e:
        print(f"Error fetching proxy targets: {e}")
    
    return True

if __name__ == "__main__":
    if not test_route_visibility():
        sys.exit(1)