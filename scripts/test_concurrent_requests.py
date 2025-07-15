#!/usr/bin/env python
"""Test server behavior under concurrent requests."""

import httpx
import asyncio
import time
import os

async def make_request(client, url, request_id):
    """Make a single request and time it."""
    start = time.time()
    try:
        response = await client.get(url, timeout=30)
        elapsed = time.time() - start
        return request_id, response.status_code, elapsed, None
    except Exception as e:
        elapsed = time.time() - start
        return request_id, None, elapsed, str(e)

async def main():
    base_url = os.getenv("TEST_BASE_URL")
    
    # Test concurrent health checks
    print("Testing concurrent requests to /health...")
    async with httpx.AsyncClient(base_url=base_url) as client:
        tasks = []
        for i in range(10):
            tasks.append(make_request(client, "/health", i))
        
        results = await asyncio.gather(*tasks)
        
        for req_id, status, elapsed, error in results:
            if error:
                print(f"  Request {req_id}: ERROR in {elapsed*1000:.1f}ms - {error}")
            else:
                print(f"  Request {req_id}: {status} in {elapsed*1000:.1f}ms")
    
    # Test concurrent challenge requests (404s)
    print("\nTesting concurrent requests to challenge endpoint...")
    async with httpx.AsyncClient(base_url=base_url) as client:
        tasks = []
        for i in range(10):
            tasks.append(make_request(client, f"/.well-known/acme-challenge/test-{i}", i))
        
        results = await asyncio.gather(*tasks)
        
        for req_id, status, elapsed, error in results:
            if error:
                print(f"  Request {req_id}: ERROR in {elapsed*1000:.1f}ms - {error}")
            else:
                print(f"  Request {req_id}: {status} in {elapsed*1000:.1f}ms")
    
    # Test if server blocks on certificate creation
    print("\nTesting if other endpoints work during certificate creation...")
    print("(This test will fail if no certificate operation is running)")

if __name__ == "__main__":
    asyncio.run(main())