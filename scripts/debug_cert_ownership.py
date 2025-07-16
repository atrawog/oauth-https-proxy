#!/usr/bin/env python3
"""Debug certificate ownership information."""

import os
import sys
import json
from tabulate import tabulate

sys.path.insert(0, '/app')

from acme_certmanager.storage import RedisStorage

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

print("\n" + "="*80)
print("CERTIFICATE OWNERSHIP DEBUG")
print("="*80)

# Get all tokens first
print("\n1. Current Tokens:")
print("-" * 40)
tokens = {}
for key in storage.redis_client.scan_iter(match="token:*"):
    name = key.split(":", 1)[1]
    data = storage.redis_client.hgetall(key)
    if data:
        tokens[data.get('hash')] = {
            'name': name,
            'hash': data.get('hash'),
            'created': data.get('created_at', 'Unknown')
        }
        print(f"Token: {name}")
        print(f"  Hash: {data.get('hash')}")
        print(f"  Email: {data.get('cert_email', '(not set)')}")

# Get all certificates
print("\n2. Certificates and Their Owners:")
print("-" * 40)
cert_data = []
for key in storage.redis_client.scan_iter(match="cert:*"):
    cert_name = key.split(":", 1)[1]
    cert_json = storage.redis_client.get(key)
    if cert_json:
        cert = json.loads(cert_json)
        owner_hash = cert.get('owner_token_hash', 'NO_OWNER')
        owner_name = tokens.get(owner_hash, {}).get('name', 'UNKNOWN_TOKEN')
        
        cert_data.append([
            cert_name[:40] + '...' if len(cert_name) > 40 else cert_name,
            owner_hash[:16] + '...' if owner_hash and len(owner_hash) > 16 else owner_hash,
            owner_name,
            'FOUND' if owner_hash in tokens else 'ORPHANED'
        ])

if cert_data:
    print(tabulate(cert_data, headers=['Certificate', 'Owner Hash', 'Owner Name', 'Status'], tablefmt='grid'))
else:
    print("No certificates found")

# Count summary
print("\n3. Summary:")
print("-" * 40)
total_certs = len(cert_data)
orphaned = sum(1 for row in cert_data if row[3] == 'ORPHANED')
owned = total_certs - orphaned

print(f"Total certificates: {total_certs}")
print(f"Owned certificates: {owned}")
print(f"Orphaned certificates: {orphaned}")

# Check for mismatches
print("\n4. Token Certificate Count Check:")
print("-" * 40)
for token_hash, token_info in tokens.items():
    actual_count = sum(1 for row in cert_data if row[1].startswith(token_hash[:16]))
    print(f"Token: {token_info['name']}")
    print(f"  Certificates found: {actual_count}")

print("\n" + "="*80)