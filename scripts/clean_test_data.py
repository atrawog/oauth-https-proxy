#!/usr/bin/env python3
"""Clean up test data from Redis."""

import redis
import os
import json

redis_url = os.getenv('REDIS_URL')
if not redis_url:
    print("REDIS_URL not set")
    exit(1)

client = redis.from_url(redis_url, decode_responses=True)

# Find all certificate keys using SCAN
cert_keys = []
cursor = 0
while True:
    cursor, keys = client.scan(cursor, match='cert:*', count=100)
    cert_keys.extend(keys)
    if cursor == 0:
        break
print(f'Found {len(cert_keys)} certificate keys')

# Check for corrupted data
corrupted = []
for key in cert_keys:
    try:
        # First check if it's a hash (correct format)
        key_type = client.type(key)
        if key_type != 'hash':
            print(f'Wrong type for {key}: {key_type}')
            value = client.get(key) if key_type == 'string' else None
            if value:
                print(f'  Value: {value}')
            corrupted.append(key)
            continue
            
        # Check hash contents
        data = client.hgetall(key)
        if not data or len(data) == 0:
            print(f'Empty cert: {key}')
            corrupted.append(key)
        elif 'fullchain_pem' not in data:
            print(f'Invalid cert (no fullchain_pem): {key}')
            print(f'  Keys present: {list(data.keys())}')
            corrupted.append(key)
    except Exception as e:
        print(f'Error checking {key}: {e}')
        corrupted.append(key)

# Clean up test data patterns
test_patterns = [
    'cert:test-*',
    'cert:multi-test-*',
    'proxy:test-*',
    'token:test-*',
    'route:test-*',
    'route:*-test-*',
    'instance:test-*',
    'challenge:test-*'
]

print(f'\nLooking for test data patterns...')
for pattern in test_patterns:
    # Use SCAN for each pattern
    keys = []
    cursor = 0
    while True:
        cursor, batch = client.scan(cursor, match=pattern, count=100)
        keys.extend(batch)
        if cursor == 0:
            break
    if keys:
        print(f'Found {len(keys)} keys matching {pattern}')
        for key in keys:
            print(f'  Deleting: {key}')
            client.delete(key)

# Delete corrupted keys
if corrupted:
    print(f'\nDeleting {len(corrupted)} corrupted keys...')
    for key in corrupted:
        print(f'  Deleting: {key}')
        client.delete(key)

print('\nCleanup complete!')