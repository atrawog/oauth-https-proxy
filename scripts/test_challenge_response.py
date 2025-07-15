#!/usr/bin/env python
"""Test challenge response speed."""

import httpx
import time
import os
from acme_certmanager.storage import RedisStorage

def main():
    # Test direct challenge response
    redis_url = os.getenv("REDIS_URL")
    assert redis_url, "REDIS_URL must be set"
    
    storage = RedisStorage(redis_url)
    
    # Store a test challenge
    test_token = "speed-test-token"
    test_auth = "speed-test-token.test-auth-key"
    
    print("Storing test challenge...")
    assert storage.store_challenge(test_token, test_auth)
    
    # Test retrieval speed via API
    base_url = os.getenv("TEST_BASE_URL")
    client = httpx.Client(base_url=base_url)
    
    print("\nTesting challenge endpoint response time...")
    times = []
    
    for i in range(10):
        start = time.time()
        response = client.get(f"/.well-known/acme-challenge/{test_token}")
        elapsed = time.time() - start
        times.append(elapsed)
        
        assert response.status_code == 200
        assert response.text == test_auth
        print(f"  Request {i+1}: {elapsed*1000:.1f}ms")
    
    avg_time = sum(times) / len(times)
    max_time = max(times)
    print(f"\nAverage response time: {avg_time*1000:.1f}ms")
    print(f"Max response time: {max_time*1000:.1f}ms")
    
    # Clean up
    storage.delete_challenge(test_token)
    
    if max_time > 1.0:
        print("\n⚠️  WARNING: Response time > 1s could cause Let's Encrypt timeouts!")

if __name__ == "__main__":
    main()