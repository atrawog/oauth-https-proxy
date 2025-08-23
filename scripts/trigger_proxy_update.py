#!/usr/bin/env python3
"""Trigger proxy update event to force instance creation."""

import asyncio
import json
from pathlib import Path
import sys

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

async def main():
    from src.storage.async_redis_storage import AsyncRedisStorage
    
    # Initialize storage
    redis_url = 'redis://:c0f6020e0ad678c45d453f540ff067df4b9c0070b7d62967df1ac973ef47cbde@redis:6379/0'
    storage = AsyncRedisStorage(redis_url)
    await storage.initialize()
    
    # Publish proxy_updated event
    event_data = {
        "event_type": "proxy_updated",
        "proxy_hostname": "claude.atratest.org",
        "action": "create",
        "timestamp": "2025-08-23T13:30:00Z"
    }
    
    # Publish to events stream
    event_id = await storage.redis_client.xadd(
        "events:all:stream",
        event_data
    )
    
    print(f"Published proxy_updated event: {event_id}")
    print(f"Event data: {json.dumps(event_data, indent=2)}")
    
    await storage.close()

if __name__ == "__main__":
    asyncio.run(main())