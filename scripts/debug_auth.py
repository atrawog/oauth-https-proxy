#!/usr/bin/env python3
"""Debug auth system initialization."""

import asyncio
import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

async def main():
    # Get admin token from env
    admin_token = os.environ.get('ADMIN_TOKEN', 'acm_7d9d6c935a8a4c41e692d1ce8b0d9bb14bd73593c7b75c0bdae156d7851188f0')
    print(f"Testing with ADMIN_TOKEN: {admin_token[:20]}...")
    
    # Initialize storage
    from src.storage.async_redis_storage import AsyncRedisStorage
    redis_url = os.environ.get('REDIS_URL', 'redis://:c0f6020e0ad678c45d453f540ff067df4b9c0070b7d62967df1ac973ef47cbde@localhost:6379/0')
    storage = AsyncRedisStorage(redis_url)
    await storage.initialize()
    print("Storage initialized")
    
    # Initialize auth service
    from src.auth.service import FlexibleAuthService
    from src.auth.defaults import initialize_auth_system
    
    auth_service = FlexibleAuthService(storage=storage)
    await auth_service.initialize()
    print("Auth service initialized")
    
    # Initialize auth system with defaults
    await initialize_auth_system(storage, load_defaults=True, migrate=True)
    print("Auth system defaults loaded")
    
    # Test admin token validation
    validation = await auth_service.validate_bearer_token(admin_token)
    print(f"\nAdmin token validation:")
    print(f"  Valid: {validation.valid}")
    print(f"  Is Admin: {validation.is_admin}")
    print(f"  Token Name: {validation.token_name}")
    print(f"  Error: {validation.error}")
    
    # Check what's in Redis for admin token
    import hashlib
    admin_hash = hashlib.sha256(admin_token.encode()).hexdigest()
    token_data = await storage.redis_client.get(f"token:hash:{admin_hash}")
    print(f"\nToken data in Redis: {token_data}")
    
    # Check if admin token is set correctly
    stored_admin = await storage.redis_client.get("admin:token")
    print(f"Stored admin token: {stored_admin}")
    
    await storage.close()

if __name__ == "__main__":
    asyncio.run(main())