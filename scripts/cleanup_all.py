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
    
    # Get all tokens first
    tokens = []
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="token:*", count=100)
        for key in keys:
            token_name = key.split(':', 1)[1]
            tokens.append(token_name)
        if cursor == 0:
            break
    
    # Delete tokens with cascade deletion
    total_certs = 0
    total_proxies = 0
    total_tokens = 0
    
    for token_name in tokens:
        result = storage.delete_api_token_cascade_by_name(token_name)
        if result['token_deleted']:
            total_tokens += 1
            total_certs += result['certificates_deleted']
            total_proxies += result['proxy_targets_deleted']
            print(f"  ✓ Deleted token '{token_name}' with {result['certificates_deleted']} certificates and {result['proxy_targets_deleted']} proxy targets")
        else:
            print(f"  ✗ Failed to delete token '{token_name}'")
    
    # Clean up any orphaned certificates (shouldn't be any after cascade deletion)
    orphaned_certs = 0
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="cert:*", count=100)
        for key in keys:
            storage.redis_client.delete(key)
            orphaned_certs += 1
        if cursor == 0:
            break
    
    # Clean up any orphaned proxy targets
    orphaned_proxies = 0
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="proxy:*", count=100)
        for key in keys:
            storage.redis_client.delete(key)
            orphaned_proxies += 1
        if cursor == 0:
            break
    
    print(f"\n  ✓ Deleted {total_tokens} tokens")
    print(f"  ✓ Deleted {total_certs} certificates (via cascade)")
    print(f"  ✓ Deleted {total_proxies} proxy targets (via cascade)")
    
    if orphaned_certs > 0:
        print(f"  ✓ Cleaned up {orphaned_certs} orphaned certificates")
    if orphaned_proxies > 0:
        print(f"  ✓ Cleaned up {orphaned_proxies} orphaned proxy targets")
    
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