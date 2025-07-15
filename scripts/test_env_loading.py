#!/usr/bin/env python
"""Test that .env is loaded properly."""

import os

def main():
    print("Testing .env loading...")
    
    # Check all required env vars
    required_vars = [
        "REDIS_URL",
        "HTTP_PORT", 
        "HTTPS_PORT",
        "ACME_DIRECTORY_URL",
        "ACME_STAGING_URL",
        "TEST_DOMAIN",
        "TEST_EMAIL",
        "TEST_BASE_URL",
        "BASE_URL"
    ]
    
    all_set = True
    for var in required_vars:
        value = os.getenv(var)
        if value:
            print(f"✓ {var} = {value}")
        else:
            print(f"✗ {var} is NOT set")
            all_set = False
    
    if all_set:
        print("\n✓ All environment variables are properly set from .env")
    else:
        print("\n✗ Some environment variables are missing")
        print("  Make sure to run this script with 'just' to load .env")

if __name__ == "__main__":
    main()