#!/usr/bin/env python3
"""Check storage methods for proxy management."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage

# List all proxy-related methods
proxy_methods = [m for m in dir(RedisStorage) if 'proxy' in m]
print("Proxy-related methods in RedisStorage:")
for method in proxy_methods:
    print(f"  - {method}")

# Check for update methods
update_methods = [m for m in dir(RedisStorage) if 'update' in m and 'proxy' in m]
print("\nUpdate methods for proxy:")
for method in update_methods:
    print(f"  - {method}")