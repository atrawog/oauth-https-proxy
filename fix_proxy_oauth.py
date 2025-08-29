#!/usr/bin/env python3
"""Temporary script to fix proxy OAuth configuration."""

import asyncio
import os
import sys

# Add src to path
sys.path.insert(0, '/home/atrawog/oauth-https-proxy/src')

from src.shared.config import get_config
from src.storage import RedisStorage

async def fix_proxy_oauth():
    """Fix OAuth configuration for simple-oauth.atratest.org."""
    try:
        # Get config
        config = get_config()
        redis_url = config.get_redis_url_with_password()
        
        # Initialize storage
        storage = RedisStorage(redis_url)
        await storage.initialize_async()
        
        # Get the proxy
        proxy = await storage.get_proxy_target('simple-oauth.atratest.org')
        if not proxy:
            print("Proxy not found")
            return False
            
        print(f"Current auth_excluded_paths: {proxy.auth_excluded_paths}")
        
        # Update the auth excluded paths to include OAuth protected resource endpoint
        proxy.auth_excluded_paths = ["/health", "/.well-known/*", "/.well-known/oauth-protected-resource"]
        
        # Save the updated proxy
        await storage.store_proxy_target(proxy)
        
        print("Proxy configuration updated successfully!")
        print(f"New auth_excluded_paths: {proxy.auth_excluded_paths}")
        
        return True
        
    except Exception as e:
        print(f"Error updating proxy: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(fix_proxy_oauth())
    sys.exit(0 if success else 1)