#!/usr/bin/env python3
"""Clean ALL proxies and related state from Redis."""

import os
import redis
import json

# Get Redis connection
redis_password = os.environ.get('REDIS_PASSWORD', '')
redis_host = os.environ.get('REDIS_HOST', 'redis')
redis_port = int(os.environ.get('REDIS_PORT', 6379))

r = redis.Redis(
    host=redis_host,
    port=redis_port,
    password=redis_password,
    decode_responses=True
)

print("Cleaning ALL proxy-related data from Redis...")

# Delete patterns
patterns = [
    "proxy:*",
    "instance:state:*",
    "workflow:state:*",
    "ports:allocated:*",
    "route:*",
    "cert:proxy-*",
    "events:workflow*",
    "stream:workflow*"
]

total_deleted = 0

for pattern in patterns:
    keys = r.keys(pattern)
    if keys:
        print(f"Deleting {len(keys)} keys matching pattern: {pattern}")
        for key in keys:
            print(f"  Deleting: {key}")
            r.delete(key)
            total_deleted += 1
    else:
        print(f"No keys found for pattern: {pattern}")

# Clean consumer groups
try:
    groups = r.xinfo_groups("events:workflow")
    for group in groups:
        print(f"Deleting consumer group: {group['name']}")
        r.xgroup_destroy("events:workflow", group['name'])
except:
    pass

print(f"\n✓ Deleted {total_deleted} keys total")
print("✓ All proxy-related data cleaned from Redis")