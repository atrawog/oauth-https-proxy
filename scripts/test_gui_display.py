#!/usr/bin/env python3
"""Simulate what the web GUI displays for routes."""
import os
import requests

# Get admin token
admin_token = os.popen("just token-show admin | grep '^Token:' | cut -d' ' -f2").read().strip()

if not admin_token:
    print("Error: Could not get admin token")
    exit(1)

# Get routes as admin
headers = {"Authorization": f"Bearer {admin_token}"}
response = requests.get("http://localhost/routes", headers=headers)
routes = response.json()

print("Routes visible in Web GUI (logged in as admin)")
print("=" * 80)
print(f"Total routes: {len(routes)}")
print()

# Show what the GUI would display
print("Path                            Owner      Actions Available")
print("-" * 80)

for route in sorted(routes, key=lambda r: -r['priority']):
    path = route['path_pattern'][:30].ljust(30)
    owner = route.get('created_by', 'none')[:10].ljust(10)
    
    # In the updated GUI, all routes show action buttons
    actions = "Enable/Disable, Delete"
    
    print(f"{path} {owner} {actions}")

print()
print("Note: With the updated GUI, all routes show action buttons.")
print("The API enforces permissions, so only the owner can actually modify their routes.")