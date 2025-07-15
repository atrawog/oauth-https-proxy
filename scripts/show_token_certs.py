#!/usr/bin/env python3
"""Show certificates owned by a specific token or all tokens."""

import sys
import os
import json
from datetime import datetime
from tabulate import tabulate
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage

def show_token_certificates(token_name: str = None):
    """Show certificates owned by tokens."""
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    # If token name provided)
        
        if not token_data:
            print(f"Error: Token '{token_name}' not found")
            return False
        
        target_token_hash = token_data.get('hash')
        print(f"\n=== Certificates owned by token '{token_name}' ===\n")
    else:
        print("\n=== All Certificates by Token ===\n")
    
    # Collect all certificates
    certificates = []
    cert_cursor = 0
    
    while True:
        cert_cursor, cert_keys = storage.redis_client.scan(
            cert_cursor, match="cert:*", count=100
        )
        
        for cert_key in cert_keys:
            cert_json = storage.redis_client.get(cert_key)
            if cert_json:
                cert = json.loads(cert_json)
                owner_hash = cert.get('owner_token_hash')
                
                # Filter by token if specified
                if token_name and owner_hash != target_token_hash:
                    continue
                
                # Get token name from hash
                token_display = "Unknown"
                created_by = cert.get('created_by', 'Unknown')
                
                if owner_hash:
                    # Try to find token by hash
                    token_data = storage.get_api_token(owner_hash)
                    if token_data:
                        token_display = token_data.get('name', 'Unknown')
                
                # Parse dates
                expires_at = cert.get('expires_at')
                if expires_at:
                    expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                    days_left = (expires_dt - datetime.now(expires_dt.tzinfo)).days
                    expires_display = f"{expires_dt.strftime('%Y-%m-%d')} ({days_left}d)"
                else:
                    expires_display = "Unknown"
                
                certificates.append({
                    'Certificate': cert.get('cert_name', 'Unknown'),
                    'Domains': ', '.join(cert.get('domains', [])),
                    'Status': cert.get('status', 'Unknown'),
                    'Expires': expires_display,
                    'Token': token_display,
                    'Created By': created_by
                })
        
        if cert_cursor == 0:
            break
    
    if not certificates:
        if token_name:
            print(f"No certificates found for token '{token_name}'")
        else:
            print("No certificates found")
        return True
    
    # Sort by token name, then certificate name
    certificates.sort(key=lambda x: (x['Token'], x['Certificate']))
    
    # Display results
    if token_name:
        # Single token view - don't show token column
        for cert in certificates:
            del cert['Token']
    
    print(tabulate(certificates, headers='keys', tablefmt='grid'))
    print(f"\nTotal certificates: {len(certificates)}")
    
    # Summary by token if showing all
    if not token_name:
        token_counts = defaultdict(int)
        for cert in certificates:
            token_counts[cert['Token']] += 1
        
        print("\n=== Summary by Token ===")
        for token, count in sorted(token_counts.items()):
            print(f"  {token}: {count} certificate(s)")
    
    return True


if __name__ == "__main__":
    token_name = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not show_token_certificates(token_name):
        sys.exit(1)