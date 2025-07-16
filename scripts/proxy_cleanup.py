#!/usr/bin/env python3
"""Clean up proxy targets from Redis."""

import sys
import os
sys.path.insert(0, '/app')
from acme_certmanager.storage import RedisStorage

def cleanup_proxy_target(hostname: str):
    """Clean up a specific proxy target."""
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    storage = RedisStorage(redis_url)
    
    if storage.delete_proxy_target(hostname):
        print(f"✓ Cleaned up proxy target: {hostname}")
        return True
    else:
        print(f"✗ No proxy target found: {hostname}")
        return False


def cleanup_all_proxy_targets():
    """Clean up all proxy targets."""
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    storage = RedisStorage(redis_url)
    targets = storage.list_proxy_targets()
    
    if not targets:
        print("No proxy targets to clean up")
        return True
    
    print(f"Found {len(targets)} proxy targets to clean up")
    for target in targets:
        if storage.delete_proxy_target(target.hostname):
            print(f"  ✓ Cleaned up: {target.hostname}")
        else:
            print(f"  ✗ Failed to clean up: {target.hostname}")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1:
        hostname = sys.argv[1]
        if not cleanup_proxy_target(hostname):
            sys.exit(1)
    else:
        if not cleanup_all_proxy_targets():
            sys.exit(1)