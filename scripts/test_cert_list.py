#!/usr/bin/env python3
"""Test certificate listing directly."""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.async_redis_storage import AsyncRedisStorage
from src.certmanager.models import Certificate

async def main():
    # Initialize storage
    # Use Docker network hostname since Redis is in container
    redis_url = 'redis://:c0f6020e0ad678c45d453f540ff067df4b9c0070b7d62967df1ac973ef47cbde@redis:6379/0'
    storage = AsyncRedisStorage(redis_url)
    await storage.initialize()
    
    print("Testing certificate listing...")
    
    # List all cert keys
    cert_keys = []
    async for key in storage.redis_client.scan_iter(match="cert:*"):
        cert_keys.append(key)
    
    print(f"Found {len(cert_keys)} cert:* keys in Redis")
    for key in sorted(cert_keys)[:10]:
        print(f"  - {key}")
    
    # Try to get a specific certificate
    cert_name = "proxy-claude-atratest-org"
    print(f"\nTrying to get certificate: {cert_name}")
    
    cert_json = await storage.redis_client.get(f"cert:{cert_name}")
    if cert_json:
        cert_data = json.loads(cert_json)
        print(f"Certificate data fields: {list(cert_data.keys())}")
        
        # Try to parse as Certificate model
        try:
            cert = Certificate.parse_raw(cert_json)
            print(f"Successfully parsed as Certificate model: {cert.cert_name}")
        except Exception as e:
            print(f"Failed to parse as Certificate model: {e}")
    
    # Try list_certificates
    print("\nTrying list_certificates()...")
    try:
        certs = await storage.list_certificates()
        print(f"list_certificates() returned {len(certs)} certificates")
        for cert in certs[:3]:
            print(f"  - {cert.cert_name}: {cert.status}")
    except Exception as e:
        print(f"list_certificates() failed: {e}")
        import traceback
        traceback.print_exc()
    
    await storage.close()

if __name__ == "__main__":
    asyncio.run(main())