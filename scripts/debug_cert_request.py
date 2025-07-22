#!/usr/bin/env python3
"""Debug certificate request details."""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

redis_url = os.getenv('REDIS_URL')
storage = RedisStorage(redis_url)

# Check proxy details
proxy = storage.get_proxy_target("gui.atradev.org")
if proxy:
    print("Proxy target details:")
    print(f"  Hostname: {proxy.hostname}")
    print(f"  Cert name: {proxy.cert_name}")
    print(f"  Owner: {proxy.created_by}")
    
    # Get owner token details
    token_data = storage.get_api_token(proxy.owner_token_hash)
    if token_data:
        print(f"\nOwner token details:")
        print(f"  Name: {token_data.get('name')}")
        print(f"  Cert email: {token_data.get('cert_email')}")
        
# Check ADMIN_EMAIL
print(f"\nADMIN_EMAIL from env: {os.getenv('ADMIN_EMAIL')}")

# Check any existing account keys
print("\nChecking ACME account keys...")
cursor = 0
account_keys = []
while True:
    cursor, keys = storage.redis_client.scan(cursor, match="account:*", count=100)
    account_keys.extend(keys)
    if cursor == 0:
        break

for key in account_keys:
    print(f"  Found account key: {key}")