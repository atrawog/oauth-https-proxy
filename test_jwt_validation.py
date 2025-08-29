#!/usr/bin/env python3
"""Test JWT validation to see why it's failing."""

import asyncio
import os
import jwt
from src.storage import UnifiedStorage

async def test_jwt_validation():
    """Test JWT validation."""
    
    # Get environment variables
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_password = os.getenv('REDIS_PASSWORD')
    token = os.getenv('OAUTH_ACCESS_TOKEN')
    
    if not token:
        print("❌ No OAUTH_ACCESS_TOKEN found in environment")
        return
    
    if redis_password:
        # Add password to URL if not already present
        if '@' not in redis_url:
            redis_url = redis_url.replace('://', f'://:{redis_password}@')
    
    # Initialize storage
    storage = UnifiedStorage(redis_url)
    await storage.initialize_async()
    
    # Get public key from Redis
    public_key = await storage.get("oauth:public_key")
    if not public_key:
        print("❌ No public key found in Redis at oauth:public_key")
        return
    
    print(f"✅ Found public key in Redis (length: {len(public_key)} chars)")
    
    # Try to decode the JWT
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False}
        )
        
        print(f"\n✅ JWT validation successful!")
        print(f"  Username: {payload.get('username')}")
        print(f"  Scope: {payload.get('scope')}")
        print(f"  Audience: {payload.get('aud')}")
        print(f"  Issuer: {payload.get('iss')}")
        print(f"  Client ID: {payload.get('client_id')}")
        
        # Check if localhost is in audience
        aud = payload.get('aud', [])
        if isinstance(aud, str):
            aud = [aud]
        
        if "http://localhost" in aud:
            print(f"\n✅ http://localhost is in audience list")
        else:
            print(f"\n❌ http://localhost NOT in audience list: {aud}")
            
    except jwt.ExpiredSignatureError:
        print("❌ JWT has expired")
    except jwt.InvalidTokenError as e:
        print(f"❌ JWT validation failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    asyncio.run(test_jwt_validation())