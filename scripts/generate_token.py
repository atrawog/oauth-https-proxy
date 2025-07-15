#!/usr/bin/env python
"""Generate API token and store in Redis."""

import sys
import os

# Add app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.auth import generate_token, hash_token
from acme_certmanager.storage import RedisStorage


def main():
    if len(sys.argv) != 2:
        print("Usage: generate_token.py <token-name>")
        sys.exit(1)
    
    name = sys.argv[1]
    redis_url = os.getenv("REDIS_URL")
    
    if not redis_url:
        print("ERROR: REDIS_URL must be set in .env")
        sys.exit(1)
    
    # Generate token
    token = generate_token()
    token_hash = hash_token(token)
    
    # Store in Redis
    storage = RedisStorage(redis_url)
    if storage.store_api_token(token_hash, name):
        print(f"Token generated successfully!")
        print(f"Name: {name}")
        print(f"Token: {token}")
        print(f"\nIMPORTANT: Save this token securely. It cannot be retrieved again.")
    else:
        print("Failed to store token in Redis")
        sys.exit(1)


if __name__ == "__main__":
    main()