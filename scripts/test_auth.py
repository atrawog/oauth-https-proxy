#!/usr/bin/env python3
"""Test authentication system directly."""

import asyncio
import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth.service import FlexibleAuthService
from src.storage.async_redis_storage import AsyncRedisStorage

async def main():
    # Initialize storage
    redis_url = 'redis://:c0f6020e0ad678c45d453f540ff067df4b9c0070b7d62967df1ac973ef47cbde@redis:6379/0'
    storage = AsyncRedisStorage(redis_url)
    await storage.initialize()
    
    # Initialize auth service
    auth_service = FlexibleAuthService(storage)
    await auth_service.initialize()
    
    # Test admin token
    admin_token = "acm_7d9d6c935a8a4c41e692d1ce8b0d9bb14bd73593c7b75c0bdae156d7851188f0"
    
    print(f"Testing admin token: {admin_token[:20]}...")
    print(f"ADMIN_TOKEN env var: {os.environ.get('ADMIN_TOKEN', 'NOT SET')}")
    
    validation = await auth_service.validate_bearer_token(admin_token)
    
    print(f"\nValidation result:")
    print(f"  Valid: {validation.valid}")
    print(f"  Is Admin: {validation.is_admin}")
    print(f"  Token Name: {validation.token_name}")
    print(f"  Token Hash: {validation.token_hash[:20]}..." if validation.token_hash else "")
    print(f"  Error: {validation.error}")
    
    await storage.close()

if __name__ == "__main__":
    # Set the admin token env var for testing
    os.environ["ADMIN_TOKEN"] = "acm_7d9d6c935a8a4c41e692d1ce8b0d9bb14bd73593c7b75c0bdae156d7851188f0"
    asyncio.run(main())