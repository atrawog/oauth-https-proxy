#!/usr/bin/env python3
"""Test certificate storage operation."""

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage
from src.shared.models import Certificate

redis_url = os.getenv('REDIS_URL')
storage = RedisStorage(redis_url)

print("=== TESTING CERTIFICATE STORAGE ===\n")

# 1. Create a test certificate
print("1. Creating test certificate...")
test_cert = Certificate(
    cert_name="test-cert",
    domains=["test.example.com"],
    email="test@example.com",
    acme_directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
    status="active",
    expires_at=datetime.now(timezone.utc),
    issued_at=datetime.now(timezone.utc),
    fingerprint="test-fingerprint",
    fullchain_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    private_key_pem="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
)

# 2. Try to store it
print("2. Attempting to store certificate...")
result = storage.store_certificate("test-cert", test_cert)
print(f"   Store result: {result}")

# 3. Try to retrieve it
print("\n3. Attempting to retrieve certificate...")
retrieved = storage.get_certificate("test-cert")
if retrieved:
    print(f"   ✓ Retrieved successfully!")
    print(f"   Cert name: {retrieved.cert_name}")
    print(f"   Domains: {retrieved.domains}")
else:
    print(f"   ✗ Failed to retrieve")
    
# 4. Check Redis directly
print("\n4. Checking Redis directly...")
key = "cert:test-cert"
value = storage.redis_client.get(key)
if value:
    print(f"   ✓ Found in Redis")
    data = json.loads(value)
    print(f"   Keys in data: {list(data.keys())}")
else:
    print(f"   ✗ Not found in Redis")
    
# 5. Check Redis connection
print("\n5. Testing Redis connection...")
try:
    # Try a simple operation
    test_key = "test:connection"
    storage.redis_client.set(test_key, "test-value")
    test_value = storage.redis_client.get(test_key)
    storage.redis_client.delete(test_key)
    print(f"   ✓ Redis connection working (test value: {test_value})")
except Exception as e:
    print(f"   ✗ Redis connection error: {e}")
    
# 6. Clean up test certificate
print("\n6. Cleaning up test certificate...")
if storage.delete_certificate("test-cert"):
    print(f"   ✓ Test certificate deleted")
else:
    print(f"   ✗ Failed to delete test certificate")
    
# 7. Check if gui certificate can be retrieved by alternate methods
print("\n7. Checking for gui certificate with raw Redis commands...")
# Try to find any keys that might contain the cert
cursor = 0
found_certs = []
while True:
    cursor, keys = storage.redis_client.scan(cursor, match="*proxy-gui-atradev-org*", count=100)
    found_certs.extend(keys)
    if cursor == 0:
        break
        
if found_certs:
    print(f"   Found {len(found_certs)} keys:")
    for key in found_certs:
        print(f"   - {key}")