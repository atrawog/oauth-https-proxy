#!/usr/bin/env python3
"""Test what routes are visible to admin in GUI."""
import os
import requests
import json

base_url = os.getenv('BASE_URL', 'http://localhost')
admin_token = os.getenv('ADMIN_TOKEN')

if not admin_token:
    print("Error: ADMIN_TOKEN not found in environment")
    exit(1)

headers = {"Authorization": f"Bearer {admin_token}"}

print("Testing Admin Token Route Visibility")
print("=" * 50)

# Get all routes via API
response = requests.get(f"{base_url}/routes", headers=headers)
routes = response.json()

print(f"\nTotal routes returned by API: {len(routes)}")
print("\nRoutes visible to admin token:")
print("-" * 50)

for route in routes:
    owner = route.get('created_by', 'none')
    is_default = route['route_id'] in ['acme-challenge', 'api', 'health']
    print(f"Route: {route['route_id']}")
    print(f"  Path: {route['path_pattern']}")
    print(f"  Owner: {owner}")
    print(f"  Default Route: {is_default}")
    print()

# Count by owner
owners = {}
for route in routes:
    owner = route.get('created_by', 'none')
    owners[owner] = owners.get(owner, 0) + 1

print("\nRoutes by owner:")
for owner, count in owners.items():
    print(f"  {owner}: {count} routes")