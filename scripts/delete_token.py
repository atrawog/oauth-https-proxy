#!/usr/bin/env python3
"""Delete an API token."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage

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
    
    # Confirm deletion
    print(f"\n=== Token Details ===")
    print(f"Name: {token_name}")
    print(f"Created: {token_data.get('created_at', 'Unknown')}")
    print(f"Last Used: {token_data.get('last_used', 'Never')}")
    print(f"Certificates Owned: {cert_count}")
    
    if owned_certs:
        print(f"\nThis token owns the following certificates:")
        for cert_name in owned_certs:
            print(f"  - {cert_name}")
        print("\nWARNING: Deleting this token will ALSO DELETE all certificates owned by it!")
    
    # Ask for confirmation
    confirm = input(f"\nAre you sure you want to delete token '{token_name}' and all its certificates? (yes/no): ")
    
    if confirm.lower() != 'yes':
        print("Deletion cancelled.")
        return False
    
    # Delete all certificates owned by this token
    deleted_certs = 0
    if owned_certs:
        print("\nDeleting certificates...")
        cert_cursor = 0
        while True:
            cert_cursor, cert_keys = storage.redis_client.scan(
                cert_cursor, match="cert:*", count=100
            )
            for cert_key in cert_keys:
                cert_json = storage.redis_client.get(cert_key)
                if cert_json:
                    cert = json.loads(cert_json)
                    if cert.get('owner_token_hash') == token_hash:
                        cert_name = cert.get('cert_name', 'Unknown')
                        if storage.redis_client.delete(cert_key):
                            deleted_certs += 1
                            print(f"  ✓ Deleted certificate: {cert_name}")
                        else:
                            print(f"  ✗ Failed to delete certificate: {cert_name}")
            if cert_cursor == 0:
                break
    
    # Delete the token using storage method
    result = storage.delete_api_token_by_name(token_name)
    
    if result:
        print(f"\n✓ Token '{token_name}' deleted successfully")
        if deleted_certs > 0:
            print(f"✓ Deleted {deleted_certs} certificate(s)")
        
        return True
    else:
        print(f"\n✗ Failed to delete token '{token_name}'")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python delete_token.py <token_name>")
        sys.exit(1)
    
    token_name = sys.argv[1]
    if not delete_token(token_name):
        sys.exit(1)