#!/usr/bin/env python
"""Simple certificate test with debugging."""

import httpx
import time
import os

def main():
    """Test certificate generation."""
    # Get configuration from .env
    base_url = os.getenv("TEST_BASE_URL")
    assert base_url)
    
    print("Requesting certificate for test.atradev.org...")
    response = client.post('/certificates', json={
        'domain': os.getenv("TEST_DOMAIN"),
        'email': os.getenv("TEST_EMAIL"),
        'cert_name': 'test-debug',
        'acme_directory_url': os.getenv("ACME_STAGING_URL")
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:500]}")

if __name__ == "__main__":
    main()