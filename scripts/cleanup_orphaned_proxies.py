#!/usr/bin/env python3
"""Clean up orphaned proxy target certificate references."""

import sys
import os
import json
import redis
from dotenv import load_dotenv

load_dotenv()

def cleanup_orphaned_proxies():
    """Clean up proxy targets with non-existent certificate references."""
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        print("Error: REDIS_URL must be set in .env")
        return False
    
    client = redis.from_url(redis_url, decode_responses=True)
    
    # First, get all existing certificate names
    existing_certs = set()
    for key in client.scan_iter(match="cert:*"):
        cert_name = key.split(":", 1)[1]
        existing_certs.add(cert_name)
    
    print(f"Found {len(existing_certs)} existing certificates: {existing_certs}")
    
    # Check all proxy targets
    cleaned_count = 0
    checked_count = 0
    
    for key in client.scan_iter(match="proxy:*"):
        checked_count += 1
        proxy_json = client.get(key)
        if proxy_json:
            proxy_data = json.loads(proxy_json)
            cert_name = proxy_data.get('cert_name')
            
            if cert_name and cert_name not in existing_certs:
                hostname = key.split(":", 1)[1]
                print(f"Cleaning orphaned cert reference '{cert_name}' from proxy '{hostname}'")
                
                # Clear the cert_name
                proxy_data['cert_name'] = None
                client.set(key, json.dumps(proxy_data))
                cleaned_count += 1
    
    print(f"\nChecked {checked_count} proxy targets")
    print(f"Cleaned {cleaned_count} orphaned certificate references")
    
    return True


if __name__ == "__main__":
    if not cleanup_orphaned_proxies():
        sys.exit(1)