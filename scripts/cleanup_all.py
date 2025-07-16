#!/usr/bin/env python3
"""Delete all tokens and certificates from Redis."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage


def cleanup_all():
    """Delete all tokens and certificates."""
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    print("🧹 Cleaning up all tokens and certificates...")
    
    # Delete all certificates
    cert_count = 0
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="cert:*", count=100)
        for key in keys:
            storage.redis_client.delete(key)
            cert_count += 1
        if cursor == 0:
            break
    
    print(f"  ✓ Deleted {cert_count} certificates")
    
    # Delete all tokens (both by name and by hash)
    token_count = 0
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="token:*", count=100)
        for key in keys:
            storage.redis_client.delete(key)
            token_count += 1
        if cursor == 0:
            break
    
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="api_token:*", count=100)
        for key in keys:
            storage.redis_client.delete(key)
            token_count += 1
        if cursor == 0:
            break
    
    print(f"  ✓ Deleted {token_count} token entries")
    
    # Delete all challenges (cleanup)
    challenge_count = 0
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="challenge:*", count=100)
        for key in keys:
            storage.redis_client.delete(key)
            challenge_count += 1
        if cursor == 0:
            break
    
    if challenge_count > 0:
        print(f"  ✓ Deleted {challenge_count} stale challenges")
    
    print("\n✅ Cleanup complete!")
    return True


if __name__ == "__main__":
    if not cleanup_all():
        sys.exit(1)