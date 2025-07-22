#!/usr/bin/env python3
"""Delete an API token."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

def delete_token(token_name: str):
    """Delete an API token by name."""
    if not token_name:
        print("Error: Token name is required")
        return False
    
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    # Find the token by name
    token_key = f"token:{token_name}"
    token_data = storage.redis_client.hgetall(token_key)
    
    if not token_data:
        print(f"Error: Token '{token_name}' not found")
        return False
    
    token_hash = token_data.get('hash')
    
    # Check if any certificates are owned by this token
    cert_count = 0
    owned_certs = []
    cert_cursor = 0
    
    while True:
        cert_cursor, cert_keys = storage.redis_client.scan(cert_cursor, match="cert:*", count=100)
        for cert_key in cert_keys:
            cert_json = storage.redis_client.get(cert_key)
            if cert_json:
                cert = json.loads(cert_json)
                if cert.get('owner_token_hash') == token_hash:
                    cert_count += 1
                    owned_certs.append(cert.get('cert_name', 'Unknown'))
        if cert_cursor == 0:
            break
    
    # Check if any proxy targets are owned by this token
    proxy_count = 0
    owned_proxies = []
    proxy_cursor = 0
    
    while True:
        proxy_cursor, proxy_keys = storage.redis_client.scan(proxy_cursor, match="proxy:*", count=100)
        for proxy_key in proxy_keys:
            proxy_json = storage.redis_client.get(proxy_key)
            if proxy_json:
                proxy = json.loads(proxy_json)
                if proxy.get('owner_token_hash') == token_hash:
                    proxy_count += 1
                    hostname = proxy_key.split(':', 1)[1]
                    owned_proxies.append(hostname)
        if proxy_cursor == 0:
            break
    
    # Confirm deletion
    print(f"\n=== Token Details ===")
    print(f"Name: {token_name}")
    print(f"Created: {token_data.get('created_at', 'Unknown')}")
    print(f"Last Used: {token_data.get('last_used', 'Never')}")
    print(f"Certificates Owned: {cert_count}")
    print(f"Proxy Targets Owned: {proxy_count}")
    
    if owned_certs:
        print(f"\nThis token owns the following certificates:")
        for cert_name in owned_certs:
            print(f"  - {cert_name}")
    
    if owned_proxies:
        print(f"\nThis token owns the following proxy targets:")
        for hostname in owned_proxies:
            print(f"  - {hostname}")
    
    if owned_certs or owned_proxies:
        print("\nWARNING: Deleting this token will ALSO DELETE all resources owned by it!")
    
    # Ask for confirmation
    confirm = input(f"\nAre you sure you want to delete token '{token_name}' and all its resources? (yes/no): ")
    
    if confirm.lower() != 'yes':
        print("Deletion cancelled.")
        return False
    
    # Delete the token and all owned resources using cascade deletion
    print("\nDeleting token and all owned resources...")
    result = storage.delete_api_token_cascade_by_name(token_name)
    
    if result['token_deleted']:
        print(f"\n✓ Token '{token_name}' deleted successfully")
        if result['certificates_deleted'] > 0:
            print(f"✓ Deleted {result['certificates_deleted']} certificate(s)")
        if result['proxy_targets_deleted'] > 0:
            print(f"✓ Deleted {result['proxy_targets_deleted']} proxy target(s)")
        
        return True
    else:
        print(f"\n✗ Failed to delete token '{token_name}'")
        if result['errors']:
            print("Errors encountered:")
            for error in result['errors']:
                print(f"  - {error}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python delete_token.py <token_name>")
        sys.exit(1)
    
    token_name = sys.argv[1]
    if not delete_token(token_name):
        sys.exit(1)