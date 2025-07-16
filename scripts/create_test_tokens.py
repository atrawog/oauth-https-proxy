#!/usr/bin/env python3
"""Create test tokens with various configurations."""

import os
import sys
import time

# Add the parent directory to sys.path
sys.path.insert(0, '/app')

from acme_certmanager.storage import RedisStorage

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

def create_test_tokens():
    """Create several test tokens with different configurations."""
    print("\n" + "="*60)
    print("Creating Test Tokens")
    print("="*60)
    
    test_tokens = [
        {
            "name": f"test-with-email-{int(time.time())}",
            "cert_email": "test-with-email@example.com"
        },
        {
            "name": f"test-no-email-{int(time.time())}",
            "cert_email": None
        },
        {
            "name": f"test-empty-email-{int(time.time())}",
            "cert_email": ""
        },
        {
            "name": f"test-production-{int(time.time())}",
            "cert_email": "production@company.com"
        }
    ]
    
    created_tokens = []
    
    for token_config in test_tokens:
        name = token_config["name"]
        cert_email = token_config["cert_email"]
        
        # Generate token
        import hashlib
        import secrets
        token = f"acm_{secrets.token_urlsafe(32)}"
        # Hash the token (no prefix)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store token
        success = storage.store_api_token(token_hash, name, token, cert_email)
        
        if success:
            print(f"\n✅ Created token: {name}")
            print(f"   Token: {token}")
            print(f"   Email: {cert_email or '(not set)'}")
            created_tokens.append({
                "name": name,
                "token": token,
                "email": cert_email
            })
        else:
            print(f"\n❌ Failed to create token: {name}")
    
    print("\n" + "="*60)
    print(f"Created {len(created_tokens)} test tokens")
    print("="*60)
    
    # Save to file for easy cleanup later
    with open('/tmp/test_tokens.txt', 'w') as f:
        for t in created_tokens:
            f.write(f"{t['name']}|{t['token']}\n")
    
    print("\nTokens saved to /tmp/test_tokens.txt for cleanup")
    
    return created_tokens

if __name__ == "__main__":
    create_test_tokens()