#!/usr/bin/env python3
"""Test UnifiedStorage implementation."""

import os
import sys
import asyncio

# Add project root to path
sys.path.insert(0, '/home/atrawog/oauth-https-proxy')

from src.storage import RedisStorage, UnifiedStorage, AsyncRedisStorage

def test_sync():
    """Test synchronous usage."""
    redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
    print('Testing synchronous usage...')
    
    try:
        # Test RedisStorage compatibility shim
        print('  Creating RedisStorage (compatibility shim)...')
        storage = RedisStorage(redis_url)
        print('  ✓ RedisStorage created and initialized')
        
        # Test direct UnifiedStorage
        print('  Creating UnifiedStorage directly...')
        unified = UnifiedStorage(redis_url)
        unified.initialize()
        print('  ✓ UnifiedStorage initialized')
        
        # Test a sync method call
        print('  Testing method call...')
        result = unified.health_check()
        print(f'  ✓ health_check() returned: {result}')
        
        return True
    except Exception as e:
        print(f'  ✗ Error: {e}')
        import traceback
        traceback.print_exc()
        return False

async def test_async():
    """Test asynchronous usage."""
    redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
    print('Testing asynchronous usage...')
    
    try:
        # Test AsyncRedisStorage compatibility shim
        print('  Creating AsyncRedisStorage (compatibility shim)...')
        storage = AsyncRedisStorage(redis_url)
        await storage.initialize()
        print('  ✓ AsyncRedisStorage created and initialized')
        
        # Test direct UnifiedStorage
        print('  Creating UnifiedStorage directly...')
        unified = UnifiedStorage(redis_url)
        await unified.initialize_async()
        print('  ✓ UnifiedStorage initialized (async)')
        
        # Test an async method call
        print('  Testing async method call...')
        result = await unified.health_check()
        print(f'  ✓ health_check() returned: {result}')
        
        return True
    except Exception as e:
        print(f'  ✗ Error: {e}')
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print('=' * 60)
    print('UnifiedStorage Implementation Test')
    print('=' * 60)
    
    # Test sync
    sync_ok = test_sync()
    print()
    
    # Test async
    async_ok = asyncio.run(test_async())
    print()
    
    # Summary
    print('=' * 60)
    if sync_ok and async_ok:
        print('✅ All tests passed!')
        return 0
    else:
        print('❌ Some tests failed')
        return 1

if __name__ == '__main__':
    sys.exit(main())