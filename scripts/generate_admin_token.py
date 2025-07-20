#!/usr/bin/env python
"""Generate ADMIN_TOKEN and store it both in Redis and return for .env."""

import sys
import os

# Add app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.auth import generate_token, hash_token
from acme_certmanager.storage import RedisStorage


def main():
    if len(sys.argv) < 2:
        print("Usage: generate_admin_token.py <cert-email>")
        sys.exit(1)
    
    cert_email = sys.argv[1]
    redis_url = os.getenv("REDIS_URL")
    
    if not redis_url:
        print("ERROR: REDIS_URL must be set in .env")
        sys.exit(1)
    
    # Generate token
    token = generate_token()
    token_hash = hash_token(token)
    
    # Store in Redis with name "ADMIN" (matching auth.py special handling)
    storage = RedisStorage(redis_url)
    if storage.store_api_token(token_hash, "ADMIN", token, cert_email):
        print(f"Admin token generated successfully!")
        print(f"Name: ADMIN")
        print(f"Token: {token}")
        print(f"Certificate Email: {cert_email}")
        print(f"\nThis token will be stored as ADMIN_TOKEN in .env")
        print(f"It will also be visible in 'just token-list' as 'ADMIN'")
    else:
        print("Failed to store token in Redis")
        sys.exit(1)


if __name__ == "__main__":
    main()