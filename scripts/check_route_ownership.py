#!/usr/bin/env python3
"""Check route ownership."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.manager import CertificateManager

# Create manager
manager = CertificateManager()

# Get all routes
routes = manager.storage.get_all_routes()

print("Route Ownership Status:")
print("=" * 60)

for route in routes:
    print(f"Route ID: {route.route_id}")
    print(f"  Path: {route.path_pattern}")
    print(f"  Target: {route.target_type}:{route.target_value}")
    if route.owner_token_hash:
        print(f"  Owner Hash: {route.owner_token_hash[:16]}...")
    else:
        print(f"  Owner Hash: None")
    print(f"  Created By: {route.created_by or 'None'}")
    print()

print(f"Total routes: {len(routes)}")