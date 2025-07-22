#!/usr/bin/env python3
"""Check ADMIN token certificate email."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

redis_url = os.getenv('REDIS_URL')
storage = RedisStorage(redis_url)

# Get ADMIN token info
admin_token = storage.get_api_token_by_name("ADMIN")
if admin_token:
    print(f"ADMIN token found:")
    print(f"  Name: {admin_token.get('name')}")
    print(f"  Hash: {admin_token.get('hash')[:16]}...")
    print(f"  Cert Email: {admin_token.get('cert_email', '(not set)')}")
    print(f"  Created: {admin_token.get('created_at')}")
else:
    print("ADMIN token not found")
    
# Check from ADMIN_EMAIL env var
admin_email = os.getenv('ADMIN_EMAIL')
print(f"\nADMIN_EMAIL from environment: {admin_email}")