#!/usr/bin/env python3
"""Debug token storage to understand the issue."""

import os
import redis
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to Redis
redis_password = os.getenv("REDIS_PASSWORD")
redis_url = os.getenv("REDIS_URL", f"redis://:{redis_password}@redis:6379/0")

# Parse Redis URL
from urllib.parse import urlparse
parsed = urlparse(redis_url)

redis_client = redis.Redis(
    host=parsed.hostname or 'redis',
    port=parsed.port or 6379,
    password=redis_password,
    decode_responses=True
)

print("Checking token storage...\n")

# List all keys matching token:*
print("Keys matching 'token:*':")
token_keys = list(redis_client.scan_iter(match="token:*"))
for key in token_keys:
    print(f"  - {key}")
    # Get the value
    key_type = redis_client.type(key)
    print(f"    Type: {key_type}")
    if key_type == 'hash':
        data = redis_client.hgetall(key)
        print(f"    Data: {data}")
    elif key_type == 'string':
        data = redis_client.get(key)
        print(f"    Data: {data}")
    print()

print("\nKeys matching 'auth:token:*':")
auth_keys = list(redis_client.scan_iter(match="auth:token:*"))
# Show most recent keys first
for i, key in enumerate(sorted(auth_keys)[-10:]):
    print(f"  - {key}")
    data = redis_client.get(key)
    if data:
        try:
            parsed = json.loads(data)
            print(f"    Name: {parsed.get('name')}")
            print(f"    Email: {parsed.get('cert_email')}")
            print(f"    Created: {parsed.get('created_at', 'unknown')}")
        except:
            print(f"    Raw: {data[:100]}...")
    print()
    
# Check for specific token
import hashlib
test_token = "acm_ba5h6fPsmqLztgp81FthKQ4dGO5KUrZSqr11ba3C1o0"  # From last test
test_hash = f"sha256:{hashlib.sha256(test_token.encode()).hexdigest()}"
test_key = f"auth:token:{test_hash}"
print(f"\nChecking for specific token key: {test_key}")
exists = redis_client.exists(test_key)
print(f"Exists: {exists}")
if exists:
    data = redis_client.get(test_key)
    print(f"Data: {data}")

print(f"\nTotal token:* keys: {len(token_keys)}")
print(f"Total auth:token:* keys: {len(auth_keys)}")