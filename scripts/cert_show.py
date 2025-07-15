#!/usr/bin/env python3
"""Show certificate details."""

import sys
import os
import requests
from datetime import datetime

def show_certificate(cert_name: str, token: str = None, show_pem: bool = False):
    """Display certificate details."""
    if not cert_name:
        print("Error: Certificate name is required")
        return False
    
    base_url = os.getenv('BASE_URL', 'http://localhost:80')
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        response = requests.get(
            f"{base_url}/certificates/{cert_name}",
            headers=headers
        )
        
        if response.status_code == 200:
            cert = response.json()
            
            print(f"=== Certificate: {cert_name} ===\n")
            print(f"Status: {cert.get('status', 'Unknown')}")
            print(f"Domains: {', '.join(cert.get('domains', []))}")
            print(f"Email: {cert.get('email', 'Unknown')}")
            
            # Parse dates
            issued = cert.get('issued_at')
            expires = cert.get('expires_at')
            
            if issued:
                issued_dt = datetime.fromisoformat(issued.replace('Z', '+00:00'))
                print(f"Issued: {issued_dt.strftime('%Y-%m-%d %H:%M UTC')}")
            
            if expires:
                expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                days_left = (expires_dt - datetime.now(expires_dt.tzinfo)).days
                print(f"Expires: {expires_dt.strftime('%Y-%m-%d %H:%M UTC')} ({days_left} days)")
            
            if cert.get('fingerprint'):
                print(f"Fingerprint: {cert['fingerprint']}")
            
            print(f"ACME Provider: {cert.get('acme_directory_url', 'Unknown')}")
            print(f"Owner: {cert.get('created_by', 'Unknown')}")
            
            if show_pem:
                print("\n=== Certificate Chain ===")
                print(cert.get('fullchain_pem', 'Not available'))
                print("\n=== Private Key ===")
                print(cert.get('private_key_pem', 'Not available'))
            else:
                print("\nTip: Use --pem flag to show certificate and key content")
            
            return True
        elif response.status_code == 404:
            print(f"✗ Certificate '{cert_name}' not found")
            return False
        elif response.status_code == 403:
            print(f"✗ Access denied - authentication required to view this certificate")
            return False
        else:
            print(f"✗ Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: cert_show.py <cert_name> [token] [--pem]")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    token = None
    show_pem = '--pem' in sys.argv
    
    # Find token if provided (not --pem)
    for arg in sys.argv[2:]:
        if arg != '--pem':
            token = arg
            break
    
    if not show_certificate(cert_name, token, show_pem):
        sys.exit(1)