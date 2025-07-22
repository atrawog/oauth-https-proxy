#!/usr/bin/env python3
"""Force delete admin token without confirmation."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage
import os

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
storage = RedisStorage(redis_url)
redis = storage.redis_client

# Delete admin token
token_key = "token:name:admin"
token_data = redis.get(token_key)
if token_data:
    token = storage._deserialize(token_data)
    token_hash = token.get("hash")
    
    # Delete by hash
    redis.delete(f"token:hash:{token_hash}")
    # Delete by name
    redis.delete(token_key)
    
    print("✓ Admin token deleted")
else:
    print("Admin token not found")