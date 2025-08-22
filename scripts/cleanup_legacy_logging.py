#!/usr/bin/env python3
"""
Cleanup script to remove all legacy logging keys and indexes from Redis.

This removes:
- idx:req:* indexes
- req:* keys
- logs:stream (old AsyncRedisLogHandler stream)
- logs:index:* indexes
- stats:* keys (optional, if desired)
"""

import asyncio
import os
import sys
import redis.asyncio as redis_async
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

async def cleanup_legacy_logging():
    """Remove all legacy logging keys from Redis."""
    
    # Get Redis URL from environment
    redis_password = os.getenv('REDIS_PASSWORD', '')
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = os.getenv('REDIS_PORT', '6379')
    
    if redis_password:
        redis_url = f"redis://:{redis_password}@{redis_host}:{redis_port}/0"
    else:
        redis_url = f"redis://{redis_host}:{redis_port}/0"
    
    print(f"Connecting to Redis at {redis_host}:{redis_port}")
    
    # Connect to Redis
    client = await redis_async.from_url(redis_url, decode_responses=True)
    
    try:
        # Count keys before cleanup
        total_deleted = 0
        
        # Delete idx:req:* indexes
        print("\nDeleting idx:req:* indexes...")
        cursor = 0
        count = 0
        while True:
            cursor, keys = await client.scan(cursor, match="idx:req:*", count=100)
            if keys:
                await client.delete(*keys)
                count += len(keys)
                print(f"  Deleted {len(keys)} index keys")
            if cursor == 0:
                break
        print(f"Total idx:req:* keys deleted: {count}")
        total_deleted += count
        
        # Delete req:* keys
        print("\nDeleting req:* keys...")
        cursor = 0
        count = 0
        while True:
            cursor, keys = await client.scan(cursor, match="req:*", count=100)
            if keys:
                await client.delete(*keys)
                count += len(keys)
                print(f"  Deleted {len(keys)} request keys")
            if cursor == 0:
                break
        print(f"Total req:* keys deleted: {count}")
        total_deleted += count
        
        # Delete logs:stream (old AsyncRedisLogHandler stream)
        print("\nDeleting logs:stream...")
        result = await client.delete("logs:stream")
        if result:
            print("  Deleted logs:stream")
            total_deleted += 1
        
        # Delete logs:index:* indexes
        print("\nDeleting logs:index:* indexes...")
        cursor = 0
        count = 0
        while True:
            cursor, keys = await client.scan(cursor, match="logs:index:*", count=100)
            if keys:
                await client.delete(*keys)
                count += len(keys)
                print(f"  Deleted {len(keys)} log index keys")
            if cursor == 0:
                break
        print(f"Total logs:index:* keys deleted: {count}")
        total_deleted += count
        
        # Optionally delete stats:* keys (uncomment if desired)
        # print("\nDeleting stats:* keys...")
        # cursor = 0
        # count = 0
        # while True:
        #     cursor, keys = await client.scan(cursor, match="stats:*", count=100)
        #     if keys:
        #         await client.delete(*keys)
        #         count += len(keys)
        #         print(f"  Deleted {len(keys)} stats keys")
        #     if cursor == 0:
        #         break
        # print(f"Total stats:* keys deleted: {count}")
        # total_deleted += count
        
        # Delete the old stream used by RequestLoggerMiddleware
        print("\nDeleting stream:requests...")
        result = await client.delete("stream:requests")
        if result:
            print("  Deleted stream:requests")
            total_deleted += 1
        
        print(f"\n✅ Cleanup complete! Total keys deleted: {total_deleted}")
        
        # Show what remains
        print("\n📊 Remaining Redis keys summary:")
        
        # Count logs:all:stream entries
        try:
            stream_info = await client.xinfo_stream("logs:all:stream")
            print(f"  logs:all:stream entries: {stream_info.get('length', 0)}")
        except:
            print("  logs:all:stream: not found (will be created on first log)")
        
        # Count other important keys
        for pattern in ["proxy:*", "cert:*", "token:*", "route:*", "service:*"]:
            cursor = 0
            count = 0
            while True:
                cursor, keys = await client.scan(cursor, match=pattern, count=100)
                count += len(keys)
                if cursor == 0:
                    break
            if count > 0:
                print(f"  {pattern} keys: {count}")
        
        print("\n✨ Legacy logging cleanup complete! System now uses unified logging via Redis Streams.")
        
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        return 1
    finally:
        await client.close()
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(cleanup_legacy_logging())
    sys.exit(exit_code)