#!/usr/bin/env python3
"""Debug OAuth callback issue by testing the exchange_github_code path"""

import asyncio
import json
import redis.asyncio as redis
from src.api.oauth.auth_authlib import AuthManager
from src.api.oauth.settings import OAuthSettings
from src.shared.config import get_config
from src.storage.async_redis_storage import AsyncRedisStorage

async def test_github_client_retrieval():
    """Test if we can retrieve GitHub client for claude.atratest.org"""
    
    print("=" * 60)
    print("Testing GitHub Client Retrieval")
    print("=" * 60)
    
    # Initialize components
    settings = OAuthSettings()
    auth_manager = AuthManager(settings)
    
    # Test 1: Get default client
    print("\n1. Testing default GitHub client:")
    default_client = await auth_manager.get_github_client(None)
    if default_client:
        print(f"   ✅ Default client available: {default_client.client_id}")
    else:
        print("   ❌ No default client")
    
    # Test 2: Get proxy-specific client
    print("\n2. Testing proxy-specific GitHub client for claude.atratest.org:")
    proxy_client = await auth_manager.get_github_client("claude.atratest.org")
    if proxy_client:
        print(f"   ✅ Proxy client available: {proxy_client.client_id}")
    else:
        print("   ❌ No proxy client")
    
    # Test 3: Check Redis storage directly
    print("\n3. Checking Redis storage directly:")
    config = get_config()
    storage = AsyncRedisStorage(config.get_redis_url_with_password())
    
    try:
        await storage.initialize()
        print("   ✅ Redis storage initialized")
        
        proxy_target = await storage.get_proxy_target("claude.atratest.org")
        if proxy_target:
            print(f"   ✅ Proxy target found")
            print(f"   - GitHub Client ID: {proxy_target.github_client_id}")
            print(f"   - GitHub Secret: {'***configured***' if proxy_target.github_client_secret else 'None'}")
        else:
            print("   ❌ No proxy target found")
    except Exception as e:
        print(f"   ❌ Error accessing Redis: {e}")
    finally:
        await storage.close()
    
    print("\n" + "=" * 60)

async def test_code_exchange():
    """Test the actual code exchange path (without a real code)"""
    
    print("\nTesting Code Exchange Path")
    print("=" * 60)
    
    settings = OAuthSettings()
    auth_manager = AuthManager(settings)
    
    # Test with fake code to see what error we get
    print("\nAttempting code exchange with test code:")
    try:
        result = await auth_manager.exchange_github_code(
            code="test_code_123",
            proxy_hostname="claude.atratest.org",
            redirect_uri="https://claude.atratest.org/callback"
        )
        if result:
            print(f"   Unexpected success: {result}")
        else:
            print(f"   Expected failure (test code)")
    except Exception as e:
        print(f"   Exception during exchange: {type(e).__name__}: {e}")
        import traceback
        print(f"   Traceback:\n{traceback.format_exc()}")
    
    print("\n" + "=" * 60)

async def check_redis_connection():
    """Check basic Redis connectivity"""
    
    print("\nChecking Redis Connection")
    print("=" * 60)
    
    config = get_config()
    
    # Test with redis.asyncio directly
    print("\n1. Testing direct Redis connection:")
    try:
        client = await redis.from_url(
            config.get_redis_url_with_password(),
            decode_responses=True
        )
        result = await client.ping()
        print(f"   ✅ Redis ping successful: {result}")
        
        # Check for OAuth states
        states = await client.keys("oauth:state:*")
        print(f"   - Active OAuth states: {len(states)}")
        
        # Check for proxy config
        proxy_key = "proxy:claude.atratest.org"
        proxy_data = await client.get(proxy_key)
        if proxy_data:
            proxy_config = json.loads(proxy_data)
            print(f"   - Proxy config found: {proxy_key}")
            if 'github_client_id' in proxy_config:
                print(f"   - GitHub Client ID: {proxy_config['github_client_id']}")
        else:
            print(f"   - No proxy config at {proxy_key}")
        
        await client.close()
    except Exception as e:
        print(f"   ❌ Redis connection failed: {e}")
    
    print("\n" + "=" * 60)

async def main():
    """Run all tests"""
    await check_redis_connection()
    await test_github_client_retrieval()
    await test_code_exchange()

if __name__ == "__main__":
    asyncio.run(main())