#!/usr/bin/env python3
import asyncio
import os
import sys
sys.path.insert(0, '/app')
from src.storage.unified_storage import UnifiedStorage

async def update_oauth_defaults():
    # Get OAuth defaults from environment
    oauth_admin_users = os.getenv('OAUTH_ADMIN_USERS', '').split(',') if os.getenv('OAUTH_ADMIN_USERS') else []
    oauth_user_users = os.getenv('OAUTH_USER_USERS', '*').split(',') if os.getenv('OAUTH_USER_USERS') else ['*']
    
    # Clean up lists
    oauth_admin_users = [u.strip() for u in oauth_admin_users if u.strip()]
    oauth_user_users = [u.strip() for u in oauth_user_users if u.strip()]
    
    print(f'OAuth defaults - Admin: {oauth_admin_users}, User: {oauth_user_users}')
    
    # Connect to storage
    redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
    storage = UnifiedStorage(redis_url=redis_url)
    await storage.initialize_async()
    
    # Get simple-oauth proxy specifically
    proxy = await storage.get_proxy_target('simple-oauth.atratest.org')
    
    if proxy:
        # Update OAuth lists
        updated = False
        
        if proxy.auth_required_users is None:
            if oauth_admin_users:
                proxy.auth_required_users = oauth_admin_users
            else:
                proxy.auth_required_users = ['*']  # Allow all if no admin users specified
            updated = True
            
        if proxy.oauth_admin_users is None:
            proxy.oauth_admin_users = oauth_admin_users if oauth_admin_users else []
            updated = True
            
        if proxy.oauth_user_users is None:
            proxy.oauth_user_users = oauth_user_users
            updated = True
            
        if updated:
            print(f'Updating simple-oauth.atratest.org with OAuth defaults')
            await storage.store_proxy_target(proxy.proxy_hostname, proxy)
            print(f'Updated:')
            print(f'  auth_required_users: {proxy.auth_required_users}')
            print(f'  oauth_admin_users: {proxy.oauth_admin_users}')
            print(f'  oauth_user_users: {proxy.oauth_user_users}')
        else:
            print('Proxy already has OAuth configuration')
            print(f'  auth_required_users: {proxy.auth_required_users}')
            print(f'  oauth_admin_users: {proxy.oauth_admin_users}')
            print(f'  oauth_user_users: {proxy.oauth_user_users}')
    else:
        print('Proxy not found')

if __name__ == "__main__":
    asyncio.run(update_oauth_defaults())