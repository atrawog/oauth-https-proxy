#!/usr/bin/env python3
"""Enable OAuth for simple-oauth.atratest.org proxy"""

import asyncio
import os
from src.storage.redis_storage import RedisStorage

async def enable_oauth():
    redis_url = 'redis://:qY7bKz48mw@localhost:6379/0'
    storage = RedisStorage(redis_url=redis_url)
    await storage.initialize_async()
    proxy = await storage.get_proxy('simple-oauth.atratest.org')
    if proxy:
        proxy['auth_enabled'] = True
        proxy['auth_type'] = 'oauth'
        proxy['auth_proxy'] = 'auth.atratest.org'
        proxy['auth_mode'] = 'forward'
        proxy['auth_required_users'] = ['*']  # Allow all GitHub users
        proxy['auth_pass_headers'] = True
        proxy['auth_excluded_paths'] = ['/health', '/.well-known/*', '/mcp']  # Exclude MCP endpoint
        # Add OAuth scope configuration for MCP
        proxy['oauth_admin_users'] = ['atrawog']  # Admin users
        proxy['oauth_user_users'] = ['*']  # All GitHub users get user scope
        proxy['oauth_mcp_users'] = ['*']  # All GitHub users get MCP scope
        # Add protected resource metadata
        proxy['resource_scopes'] = ['admin', 'user', 'mcp']
        proxy['resource_description'] = 'Simple MCP Server with OAuth Authentication'
        proxy['resource_docs_url'] = 'https://simple-oauth.atratest.org/docs'
        await storage.set_proxy('simple-oauth.atratest.org', proxy)
        # Trigger proxy update event
        await storage.set_event({'type': 'proxy_updated', 'proxy_hostname': 'simple-oauth.atratest.org'})
        print('OAuth enabled for simple-oauth.atratest.org')
        print('Configuration:')
        print(f'  - Auth enabled: {proxy.get("auth_enabled")}')
        print(f'  - Auth type: {proxy.get("auth_type")}')
        print(f'  - Auth proxy: {proxy.get("auth_proxy")}')
        print(f'  - Required users: {proxy.get("auth_required_users")}')
        print(f'  - Excluded paths: {proxy.get("auth_excluded_paths")}')
        print(f'  - Admin users: {proxy.get("oauth_admin_users")}')
        print(f'  - User scope users: {proxy.get("oauth_user_users")}')
        print(f'  - MCP scope users: {proxy.get("oauth_mcp_users")}')
    else:
        print('Proxy not found')
    await storage.close()

if __name__ == '__main__':
    asyncio.run(enable_oauth())