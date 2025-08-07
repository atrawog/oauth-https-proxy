#!/usr/bin/env python3
"""Fix remaining routes with 'instance' target type."""

import json
import redis
import os
from pathlib import Path

# Load environment
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                key, _, value = line.partition("=")
                os.environ[key.strip()] = value.strip()

# Connect to Redis
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(redis_url, decode_responses=True)

# Find all route keys
route_keys = r.keys("route:*")
fixed_count = 0

for key in route_keys:
    route_data = r.get(key)
    if route_data:
        try:
            route = json.loads(route_data)
            if route.get("target_type") == "instance":
                # Fix the target type
                route["target_type"] = "service"
                r.set(key, json.dumps(route))
                fixed_count += 1
                print(f"Fixed route: {route['route_id']} - {route['path_pattern']}")
        except json.JSONDecodeError:
            print(f"Skipping invalid JSON in {key}")

print(f"\nFixed {fixed_count} routes from 'instance' to 'service' target type")

# Verify the changes
print("\nVerifying all routes now use 'service' target type:")
for key in route_keys:
    route_data = r.get(key)
    if route_data:
        try:
            route = json.loads(route_data)
            if route.get("target_type") == "instance":
                print(f"  WARNING: Route {route['route_id']} still has 'instance' target type!")
        except json.JSONDecodeError:
            pass

print("Route fix complete!")