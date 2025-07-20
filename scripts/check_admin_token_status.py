#!/usr/bin/env python3
"""Check the status of admin tokens - both real ADMIN_TOKEN and any fake 'admin' token in Redis."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage
from acme_certmanager.auth import hash_token, ADMIN_TOKEN

def check_admin_tokens():
    """Check status of both real ADMIN_TOKEN and any Redis-stored 'admin' token."""
    storage = RedisStorage(os.getenv('REDIS_URL'))
    
    print("=== Admin Token Analysis ===\n")
    
    # Check if there's a token named 'admin' in Redis
    admin_token_data = storage.get_api_token_by_name('admin')
    if admin_token_data:
        print('1. Found token named "admin" in Redis:')
        print(f'   - Token: {admin_token_data.get("token")}')
        print(f'   - Hash: {admin_token_data.get("hash")}')
        print(f'   - Created: {admin_token_data.get("created_at")}')
        print(f'   - Email: {admin_token_data.get("cert_email", "(not set)")}')
    else:
        print('1. No token named "admin" found in Redis')
    
    # Check real ADMIN_TOKEN
    print(f'\n2. Real ADMIN_TOKEN from environment:')
    if ADMIN_TOKEN:
        print(f'   - Token: {ADMIN_TOKEN}')
        print(f'   - Hash: {hash_token(ADMIN_TOKEN)}')
        print(f'   - Stored in Redis: NO (handled specially in auth.py)')
    else:
        print('   - Not set in environment!')
    
    # Show the problem
    print("\n=== THE PROBLEM ===")
    if admin_token_data and ADMIN_TOKEN:
        fake_hash = admin_token_data.get("hash")
        real_hash = hash_token(ADMIN_TOKEN)
        
        if fake_hash != real_hash:
            print("❌ There's a FAKE 'admin' token in Redis that is NOT the real ADMIN_TOKEN!")
            print(f"   - Fake token hash: {fake_hash}")
            print(f"   - Real ADMIN_TOKEN hash: {real_hash}")
            print("\nThis causes confusion because:")
            print("   1. The real ADMIN_TOKEN is not stored in Redis (by design)")
            print("   2. A fake 'admin' token was created and stored in Redis")
            print("   3. When code looks up 'admin' token, it finds the fake one")
            print("   4. Default routes get assigned to the fake token instead of real ADMIN_TOKEN")
        else:
            print("✅ The 'admin' token in Redis matches the real ADMIN_TOKEN hash")
    elif admin_token_data and not ADMIN_TOKEN:
        print("⚠️  There's an 'admin' token in Redis but no ADMIN_TOKEN in environment")
    elif not admin_token_data and ADMIN_TOKEN:
        print("✅ No fake 'admin' token in Redis - only the real ADMIN_TOKEN exists")
    else:
        print("⚠️  No ADMIN_TOKEN in environment and no 'admin' token in Redis")
    
    return True

if __name__ == "__main__":
    check_admin_tokens()