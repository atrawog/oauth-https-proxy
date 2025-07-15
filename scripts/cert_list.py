#!/usr/bin/env python3
"""List all certificates owned by the token."""

import sys
import os
import requests
from datetime import datetime
from tabulate import tabulate

def list_certificates(token: str = None):
    """List all certificates (optionally filtered by token)."""
    base_url = os.getenv('BASE_URL', 'http://localhost:80')
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        response = requests.get(
            f"{base_url}/certificates",
            headers=headers
        )
        
        if response.status_code == 200:
            certificates = response.json()
            
            if not certificates:
                print("No certificates found.")
                print("\nCreate your first certificate with:")
                print("  just cert-create <name> <domain> <email>")
                return True
            
            # Prepare data for table
            table_data = []
            for cert in certificates:
                # Calculate days until expiry
                expires = cert.get('expires_at')
                days_left = 'N/A'
                if expires:
                    expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                    days_left = (expires_dt - datetime.now(expires_dt.tzinfo)).days
                    expires_str = f"{expires_dt.strftime('%Y-%m-%d')} ({days_left}d)"
                else:
                    expires_str = 'N/A'
                
                table_data.append({
                    'Name': cert.get('cert_name', 'Unknown'),
                    'Domains': ', '.join(cert.get('domains', [])),
                    'Status': cert.get('status', 'Unknown'),
                    'Expires': expires_str,
                    'Email': cert.get('email', 'Unknown')
                })
            
            # Sort by name
            table_data.sort(key=lambda x: x['Name'])
            
            print(f"\n=== Your Certificates ({len(certificates)} total) ===\n")
            print(tabulate(table_data, headers='keys', tablefmt='grid'))
            
            # Check for expiring certificates
            expiring = [c for c in table_data if isinstance(c.get('Expires'), str) and '(' in c['Expires'] and int(c['Expires'].split('(')[1].split('d')[0]) < 30]
            if expiring:
                print(f"\n⚠ Warning: {len(expiring)} certificate(s) expiring soon!")
                print("  Run 'just cert-renew <name>' to renew")
            
            return True
        else:
            print(f"✗ Failed to list certificates: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    # Token is optional - if provided, shows only your certs
    token = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not list_certificates(token):
        sys.exit(1)