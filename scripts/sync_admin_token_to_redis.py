#!/usr/bin/env python
"""Sync existing ADMIN_TOKEN from environment to Redis."""

import sys
import os

# Add app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.auth import hash_token, ADMIN_TOKEN
from src.storage import RedisStorage


def main():
    if not ADMIN_TOKEN:
        print("ERROR: ADMIN_TOKEN not found in environment")
        print("Please ensure ADMIN_TOKEN is set in .env and loaded")
        sys.exit(1)
    
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        print("ERROR: REDIS_URL must be set in .env")
        sys.exit(1)
    
    # Get cert email from ADMIN_EMAIL environment variable
    cert_email = os.getenv("ADMIN_EMAIL")
    if not cert_email:
        print("ERROR: ADMIN_EMAIL not found in environment")
        print("Please ensure ADMIN_EMAIL is set in .env and loaded")
        sys.exit(1)
    
    # Store existing ADMIN_TOKEN in Redis with name "ADMIN"
    storage = RedisStorage(redis_url)
    token_hash = hash_token(ADMIN_TOKEN)
    
    # First, check if there's already a token named "ADMIN"
    existing = storage.get_api_token_by_name("ADMIN")
    if existing:
        existing_hash = existing.get("hash")
        existing_email = existing.get("cert_email", "")
        
        if existing_hash == token_hash:
            # Same token, just update the email if different
            if existing_email != cert_email:
                print(f"Updating ADMIN token email from '{existing_email}' to '{cert_email}'...")
                if storage.update_api_token_email(token_hash, cert_email):
                    print(f"✓ ADMIN token email updated successfully!")
                    print(f"  Name: ADMIN")
                    print(f"  Token: {ADMIN_TOKEN}")
                    print(f"  Hash: {token_hash}")
                    print(f"  Email: {cert_email}")
                else:
                    print("Failed to update ADMIN token email")
                    sys.exit(1)
            else:
                print(f"✓ ADMIN token already synced with correct email!")
                print(f"  Name: ADMIN")
                print(f"  Token: {ADMIN_TOKEN}")
                print(f"  Hash: {token_hash}")
                print(f"  Email: {cert_email}")
        else:
            # Different token, remove old one and store new
            print(f"Removing existing ADMIN token with different hash...")
            if existing_hash:
                storage.delete_api_token(existing_hash)
            
            # Store the new ADMIN_TOKEN
            if storage.store_api_token(token_hash, "ADMIN", ADMIN_TOKEN, cert_email):
                print(f"✓ ADMIN_TOKEN synced to Redis successfully!")
                print(f"  Name: ADMIN")
                print(f"  Token: {ADMIN_TOKEN}")
                print(f"  Hash: {token_hash}")
                print(f"  Email: {cert_email}")
            else:
                print("Failed to store ADMIN_TOKEN in Redis")
                sys.exit(1)
    else:
        # No existing ADMIN token, create new
        if storage.store_api_token(token_hash, "ADMIN", ADMIN_TOKEN, cert_email):
            print(f"✓ ADMIN_TOKEN synced to Redis successfully!")
            print(f"  Name: ADMIN")
            print(f"  Token: {ADMIN_TOKEN}")
            print(f"  Hash: {token_hash}")
            print(f"  Email: {cert_email}")
        else:
            print("Failed to store ADMIN_TOKEN in Redis")
            sys.exit(1)


if __name__ == "__main__":
    main()