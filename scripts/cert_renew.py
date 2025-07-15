#!/usr/bin/env python3
"""Renew a certificate."""

import sys
import os
import requests
from datetime import datetime

def renew_certificate(cert_name: str, token: str, force: bool = False):
    """Renew a certificate."""
    if not cert_name or not token:
        print("Error: Certificate name and token are required")
        return False
    
    base_url = os.getenv('BASE_URL')

    
    if not base_url:

    
        print("Error: BASE_URL must be set in .env")

    
        return False
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # First check the certificate
        response = requests.get(
            f"{base_url}/certificates/{cert_name}",
            headers=headers
        )
        
        if response.status_code == 404:
            print(f"✗ Certificate '{cert_name}' not found")
            return False
        elif response.status_code == 403:
            print(f"✗ Access denied - you don't own certificate '{cert_name}'")
            return False
        elif response.status_code != 200:
            print(f"✗ Failed to get certificate: {response.status_code}")
            return False
        
        cert = response.json()
        
        # Check expiry
        expires = cert.get('expires_at')
        if expires and not force:
            expires_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
            days_left = (expires_dt - datetime.now(expires_dt.tzinfo)).days
            
            if days_left > 30:
                print(f"Certificate '{cert_name}' doesn't need renewal yet ({days_left} days remaining)")
                print("Use --force to renew anyway")
                return True
        
        # Renew the certificate
        print(f"Renewing certificate '{cert_name}'...")
        print(f"  Domains: {', '.join(cert.get('domains', []))}")
        
        response = requests.post(
            f"{base_url}/certificates/{cert_name}/renew",
            headers=headers
        )
        
        if response.status_code == 200:
            renewed_cert = response.json()
            print(f"\n✓ Certificate renewed successfully!")
            
            new_expires = renewed_cert.get('expires_at')
            if new_expires:
                expires_dt = datetime.fromisoformat(new_expires.replace('Z', '+00:00'))
                print(f"  New expiry: {expires_dt.strftime('%Y-%m-%d %H:%M UTC')}")
            
            return True
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to renew certificate: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: cert_renew.py <cert_name> <token> [--force]")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    token = sys.argv[2]
    force = '--force' in sys.argv
    
    if not renew_certificate(cert_name, token, force):
        sys.exit(1)