#!/usr/bin/env python
"""Test Redis operation speed."""

import time
import redis
import os

def main():
    redis_url = os.getenv("REDIS_URL")
    assert redis_url, "REDIS_URL must be set"
    
    client = redis.from_url(redis_url, decode_responses=True)
    
    print("Testing Redis operation speed...")
    
    # Test set/get speed
    print("\n1. Testing set/get operations:")
    times = []
    for i in range(10):
        key = f"test:speed:{i}"
        value = f"test_value_{i}" * 100  # ~1KB value
        
        # Test SET
        start = time.time()
        client.setex(key, 60, value)
        set_time = time.time() - start
        
        # Test GET
        start = time.time()
        retrieved = client.get(key)
        get_time = time.time() - start
        
        times.append((set_time, get_time))
        print(f"   Operation {i+1}: SET {set_time*1000:.1f}ms, GET {get_time*1000:.1f}ms")
        
        # Clean up
        client.delete(key)
    
    avg_set = sum(t[0] for t in times) / len(times)
    avg_get = sum(t[1] for t in times) / len(times)
    print(f"\n   Average SET: {avg_set*1000:.1f}ms")
    print(f"   Average GET: {avg_get*1000:.1f}ms")
    
    # Test challenge-like operations
    print("\n2. Testing challenge storage pattern:")
    token = "test-challenge-token"
    auth = "test-challenge-token.test-key-authorization"
    
    start = time.time()
    client.setex(f"challenge:{token}", 3600, auth)
    set_time = time.time() - start
    
    start = time.time()
    retrieved = client.get(f"challenge:{token}")
    get_time = time.time() - start
    
    print(f"   Challenge SET: {set_time*1000:.1f}ms")
    print(f"   Challenge GET: {get_time*1000:.1f}ms")
    
    client.delete(f"challenge:{token}")
    
    if avg_get > 0.1:  # 100ms
        print("\n⚠️  WARNING: Redis operations are slow!")

if __name__ == "__main__":
    main()