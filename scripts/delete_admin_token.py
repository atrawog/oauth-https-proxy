#!/usr/bin/env python3
"""Delete admin token if it exists."""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage

def delete_admin_token():
    """Delete admin token from Redis."""
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    storage = RedisStorage(redis_url)
    
    # Check if admin token exists (using hash storage)
    token_key = "token:admin"
    if storage.redis_client.exists(token_key):
        # Get the token hash for cleanup
        token_hash = storage.redis_client.hget(token_key, "hash")
        
        # Delete by name
        storage.redis_client.delete(token_key)
        
        # Also delete any hash-based key if it exists
        if token_hash:
            storage.redis_client.delete(f"token:{token_hash}")
        
        print("✓ Existing admin token removed")
        return True
    else:
        print("No admin token found")
        return False

if __name__ == "__main__":
    delete_admin_token()