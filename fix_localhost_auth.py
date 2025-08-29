#!/usr/bin/env python3
"""Fix localhost proxy authentication to use OAUTH_ADMIN_USERS as default."""

import asyncio
import os
from src.storage import UnifiedStorage

async def fix_localhost_auth():
    """Update localhost proxy to properly use OAuth admin users."""
    
    # Get environment variables
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_password = os.getenv('REDIS_PASSWORD')
    
    if redis_password:
        # Add password to URL if not already present
        if '@' not in redis_url:
            redis_url = redis_url.replace('://', f'://:{redis_password}@')
    
    # Initialize storage
    storage = UnifiedStorage(redis_url)
    await storage.initialize_async()
    
    # Get localhost proxy
    proxy = await storage.get_proxy_target('localhost')
    if not proxy:
        print("❌ Localhost proxy not found!")
        return
    
    print(f"Current localhost proxy configuration:")
    print(f"  auth_enabled: {proxy.auth_enabled}")
    print(f"  auth_required_users: {proxy.auth_required_users}")
    print(f"  oauth_admin_users: {proxy.oauth_admin_users}")
    print(f"  oauth_user_users: {proxy.oauth_user_users}")
    
    # Update the proxy to enable OAuth with proper configuration
    proxy.auth_enabled = True
    proxy.auth_proxy = "localhost"
    proxy.auth_mode = "redirect"
    
    # Leave auth_required_users as None to use OAuth user lists
    proxy.auth_required_users = None
    
    # Ensure OAuth user lists are properly set from environment
    oauth_admin_users = os.getenv("OAUTH_ADMIN_USERS", "").split(",") if os.getenv("OAUTH_ADMIN_USERS") else []
    oauth_user_users = os.getenv("OAUTH_USER_USERS", "").split(",") if os.getenv("OAUTH_USER_USERS") else []
    
    # Clean up lists
    oauth_admin_users = [u.strip() for u in oauth_admin_users if u.strip()]
    oauth_user_users = [u.strip() for u in oauth_user_users if u.strip()]
    
    # Set the OAuth user lists
    proxy.oauth_admin_users = oauth_admin_users
    proxy.oauth_user_users = oauth_user_users
    
    # Store updated proxy
    await storage.store_proxy_target('localhost', proxy)
    
    print(f"\n✅ Updated localhost proxy configuration:")
    print(f"  auth_enabled: {proxy.auth_enabled}")
    print(f"  auth_required_users: {proxy.auth_required_users} (None = use OAuth user lists)")
    print(f"  oauth_admin_users: {proxy.oauth_admin_users}")
    print(f"  oauth_user_users: {proxy.oauth_user_users}")
    
    # Publish event to trigger reconciliation
    await storage.publish_event('proxy_updated', {'hostname': 'localhost'})
    print(f"\n✅ Published proxy_updated event for reconciliation")

if __name__ == "__main__":
    asyncio.run(fix_localhost_auth())