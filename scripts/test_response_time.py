#!/usr/bin/env python
"""Test challenge endpoint response time."""

import time
import httpx
import os

def main():
    base_url = os.getenv("TEST_BASE_URL")
    
    print(f"Testing response time to {base_url}")
    
    # First, test a non-existent challenge (should 404 quickly)
    print("\n1. Testing 404 response time:")
    times = []
    for i in range(5):
        start = time.time()
        try:
            response = httpx.get(f"{base_url}/.well-known/acme-challenge/nonexistent", timeout=10)
            elapsed = time.time() - start
            times.append(elapsed)
            print(f"   Request {i+1}: {response.status_code} in {elapsed*1000:.1f}ms")
        except Exception as e:
            print(f"   Request {i+1}: ERROR - {e}")
    
    if times:
        avg_time = sum(times) / len(times)
        print(f"   Average: {avg_time*1000:.1f}ms")
    
    # Test health endpoint
    print("\n2. Testing health endpoint:")
    times = []
    for i in range(5):
        start = time.time()
        try:
            response = httpx.get(f"{base_url}/health", timeout=10)
            elapsed = time.time() - start
            times.append(elapsed)
            print(f"   Request {i+1}: {response.status_code} in {elapsed*1000:.1f}ms")
        except Exception as e:
            print(f"   Request {i+1}: ERROR - {e}")
    
    if times:
        avg_time = sum(times) / len(times)
        print(f"   Average: {avg_time*1000:.1f}ms")
        
        if avg_time > 1.0:
            print("\n⚠️  WARNING: Average response time > 1s could cause Let's Encrypt timeouts!")

if __name__ == "__main__":
    main()