#!/usr/bin/env python
"""Test challenge timing to debug Let's Encrypt timeout."""

import httpx
import time
import os
from datetime import datetime

def log_time(msg):
    """Log with timestamp."""
    print(f"[{datetime.now().isoformat()}] {msg}")

def main():
    base_url = os.getenv("TEST_BASE_URL")
    assert base_url)
    
    client = httpx.Client(base_url=base_url)
    
    # Test non-existent challenge
    start = time.time()
    response = client.get("/.well-known/acme-challenge/test-timing")
    elapsed = time.time() - start
    log_time(f"Challenge endpoint responded in {elapsed:.3f}s with status {response.status_code}")
    
    # Now test certificate generation
    log_time("Starting certificate generation...")
    
    response = client.post('/certificates', json={
        'domain': os.getenv("TEST_DOMAIN"),
        'email': os.getenv("TEST_EMAIL"),
        'cert_name': f'test-timing-{int(time.time())}',
        'acme_directory_url': os.getenv("ACME_STAGING_URL")
    })
    
    log_time(f"Certificate request completed with status {response.status_code}")
    if response.status_code != 200:
        print(f"Error: {response.text[:500]}")

if __name__ == "__main__":
    main()