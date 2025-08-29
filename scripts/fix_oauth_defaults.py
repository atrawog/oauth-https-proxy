#!/usr/bin/env python3
"""
Fix OAuth defaults for all existing proxies.

This script loads all existing proxies and re-saves them with OAuth defaults applied.
This ensures auth_required_users, oauth_admin_users, and oauth_user_users are never null.
"""

import asyncio
import os
import sys
sys.path.insert(0, '/app')
from src.storage.unified_storage import UnifiedStorage

async def fix_oauth_defaults():
    """Fix OAuth defaults for all existing proxies."""
    
    # Get OAuth defaults from environment
    oauth_admin_users = os.getenv('OAUTH_ADMIN_USERS', '').split(',') if os.getenv('OAUTH_ADMIN_USERS') else []
    oauth_user_users = os.getenv('OAUTH_USER_USERS', '*').split(',') if os.getenv('OAUTH_USER_USERS') else ['*']
    
    # Clean up lists
    oauth_admin_users = [u.strip() for u in oauth_admin_users if u.strip()]
    oauth_user_users = [u.strip() for u in oauth_user_users if u.strip()]
    
    print(f'OAuth defaults from environment:')
    print(f'  OAUTH_ADMIN_USERS: {oauth_admin_users}')
    print(f'  OAUTH_USER_USERS: {oauth_user_users}')
    print()
    
    # Connect to storage
    redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
    storage = UnifiedStorage(redis_url=redis_url)
    await storage.initialize_async()
    
    # Get all proxies
    proxies = await storage.list_proxy_targets()
    print(f'Found {len(proxies)} proxies to check')
    print()
    
    fixed_count = 0
    for proxy in proxies:
        needs_update = False
        changes = []
        
        # Check and fix auth_required_users
        if proxy.auth_required_users is None:
            old_value = proxy.auth_required_users
            proxy.auth_required_users = oauth_admin_users if oauth_admin_users else ["*"]
            changes.append(f'  auth_required_users: {old_value} -> {proxy.auth_required_users}')
            needs_update = True
            
        # Check and fix oauth_admin_users
        if proxy.oauth_admin_users is None:
            old_value = proxy.oauth_admin_users
            proxy.oauth_admin_users = oauth_admin_users
            changes.append(f'  oauth_admin_users: {old_value} -> {proxy.oauth_admin_users}')
            needs_update = True
            
        # Check and fix oauth_user_users
        if proxy.oauth_user_users is None:
            old_value = proxy.oauth_user_users
            proxy.oauth_user_users = oauth_user_users
            changes.append(f'  oauth_user_users: {old_value} -> {proxy.oauth_user_users}')
            needs_update = True
            
        # Check and fix resource_scopes
        if proxy.resource_scopes is None or len(proxy.resource_scopes) == 0:
            old_value = proxy.resource_scopes
            proxy.resource_scopes = ["admin", "user", "mcp"]
            changes.append(f'  resource_scopes: {old_value} -> {proxy.resource_scopes}')
            needs_update = True
            
        if needs_update:
            print(f'Fixing {proxy.proxy_hostname}:')
            for change in changes:
                print(change)
            
            # Save the fixed proxy
            await storage.store_proxy_target(proxy.proxy_hostname, proxy)
            fixed_count += 1
            print(f'  ✓ Updated')
            print()
        else:
            print(f'{proxy.proxy_hostname}: Already has OAuth defaults')
    
    print()
    print(f'Summary: Fixed {fixed_count} proxies out of {len(proxies)} total')
    
    # Verify the fix by re-loading one proxy
    if proxies:
        test_proxy = proxies[0]
        reloaded = await storage.get_proxy_target(test_proxy.proxy_hostname)
        print()
        print(f'Verification - {test_proxy.proxy_hostname}:')
        print(f'  auth_required_users: {reloaded.auth_required_users}')
        print(f'  oauth_admin_users: {reloaded.oauth_admin_users}')
        print(f'  oauth_user_users: {reloaded.oauth_user_users}')
        print(f'  resource_scopes: {reloaded.resource_scopes}')

if __name__ == "__main__":
    asyncio.run(fix_oauth_defaults())