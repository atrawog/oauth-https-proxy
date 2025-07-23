#!/usr/bin/env python3
"""
Migrate proxy targets to use new service names after docker-compose refactoring.

Service name changes:
- mcp-oauth-dynamicclient → mcp-oauth-server
- echo-stateful → mcp-echo-stateful  
- fetcher → mcp-fetcher
- mcp-echo-streamablehttp-server-stateless → mcp-echo-stateless
"""

import redis
import json
import os
from typing import Dict, Any

# Get Redis connection from environment
REDIS_URL = os.environ.get('REDIS_URL', 'redis://:password@localhost:6379/0')

# Service name mappings
SERVICE_MAPPINGS = {
    'mcp-oauth-dynamicclient': 'mcp-oauth-server',
    'echo-stateful': 'mcp-echo-stateful',
    'fetcher': 'mcp-fetcher',
    'mcp-echo-streamablehttp-server-stateless': 'mcp-echo-stateless'
}

def update_proxy_target(target_url: str) -> str:
    """Update target URL with new service names."""
    for old_name, new_name in SERVICE_MAPPINGS.items():
        if f'http://{old_name}:' in target_url:
            return target_url.replace(f'http://{old_name}:', f'http://{new_name}:')
    return target_url

def main():
    """Main migration function."""
    print("🔄 Migrating proxy targets to new service names...")
    
    # Connect to Redis
    r = redis.from_url(REDIS_URL, decode_responses=True)
    
    # Get all proxy targets
    proxy_keys = r.keys('proxy:*')
    updated_count = 0
    
    for key in proxy_keys:
        if not key.startswith('proxy:hash:'):  # Skip hash keys
            proxy_data = r.get(key)
            if proxy_data:
                try:
                    proxy = json.loads(proxy_data)
                    old_target = proxy.get('target_url', '')
                    new_target = update_proxy_target(old_target)
                    
                    if old_target != new_target:
                        proxy['target_url'] = new_target
                        r.set(key, json.dumps(proxy))
                        hostname = key.replace('proxy:', '')
                        print(f"✅ Updated {hostname}:")
                        print(f"   {old_target} → {new_target}")
                        updated_count += 1
                except json.JSONDecodeError:
                    print(f"⚠️  Skipping invalid JSON in {key}")
    
    print(f"\n✨ Migration complete! Updated {updated_count} proxy targets.")
    
    # Show current proxy targets
    print("\n📋 Current proxy targets:")
    for key in proxy_keys:
        if not key.startswith('proxy:hash:'):
            proxy_data = r.get(key)
            if proxy_data:
                try:
                    proxy = json.loads(proxy_data)
                    hostname = key.replace('proxy:', '')
                    target = proxy.get('target_url', 'unknown')
                    print(f"   {hostname}: {target}")
                except:
                    pass

if __name__ == '__main__':
    main()