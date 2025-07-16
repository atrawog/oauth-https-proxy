#!/usr/bin/env python3
"""Fix existing certificates in Redis by adding cert_name field."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage


def fix_certificate_names():
    """Add cert_name field to existing certificates."""
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    print("Fixing certificate names in Redis...")
    
    fixed_count = 0
    cursor = 0
    
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="cert:*", count=100)
        
        for key in keys:
            cert_name = key.decode('utf-8').split(':', 1)[1]
            cert_json = storage.redis_client.get(key)
            
            if cert_json:
                try:
                    cert_data = json.loads(cert_json)
                    
                    # Check if cert_name is missing
                    if 'cert_name' not in cert_data:
                        print(f"  Fixing certificate: {cert_name}")
                        cert_data['cert_name'] = cert_name
                        
                        # Update in Redis
                        storage.redis_client.set(key, json.dumps(cert_data))
                        fixed_count += 1
                    else:
                        print(f"  Certificate already has cert_name: {cert_name}")
                        
                except Exception as e:
                    print(f"  Error fixing {cert_name}: {e}")
        
        if cursor == 0:
            break
    
    print(f"\nFixed {fixed_count} certificates")
    return True


if __name__ == "__main__":
    if not fix_certificate_names():
        sys.exit(1)