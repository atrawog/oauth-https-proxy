#!/usr/bin/env python3
"""Show proxy targets owned by a specific token or all tokens."""

import sys
import os
import json
from datetime import datetime
from tabulate import tabulate
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

def show_token_proxies(token_name: str = None):
    """Show proxy targets owned by tokens."""
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    # If token name provided
    target_token_hash = None
    if token_name:
        token_key = f"token:{token_name}"
        token_data = storage.redis_client.hgetall(token_key)
        
        if not token_data:
            print(f"Error: Token '{token_name}' not found")
            return False
        
        target_token_hash = token_data.get('hash')
        print(f"\n=== Proxy targets owned by token '{token_name}' ===\n")
    else:
        print("\n=== All Proxy Targets by Token ===\n")
    
    # Collect all proxy targets
    proxy_targets = []
    proxy_cursor = 0
    
    while True:
        proxy_cursor, proxy_keys = storage.redis_client.scan(
            proxy_cursor, match="proxy:*", count=100
        )
        
        for proxy_key in proxy_keys:
            proxy_json = storage.redis_client.get(proxy_key)
            if proxy_json:
                proxy = json.loads(proxy_json)
                owner_hash = proxy.get('owner_token_hash')
                
                # Filter by token if specified
                if token_name and owner_hash != target_token_hash:
                    continue
                
                # Get token name from hash
                token_display = "Unknown"
                created_by = proxy.get('created_by', 'Unknown')
                
                if owner_hash:
                    # Try to find token by hash
                    token_data = storage.get_api_token(owner_hash)
                    if token_data:
                        token_display = token_data.get('name', 'Unknown')
                
                # Parse created date
                created_at = proxy.get('created_at')
                if created_at:
                    created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    created_display = created_dt.strftime('%Y-%m-%d')
                else:
                    created_display = "Unknown"
                
                proxy_targets.append({
                    'Hostname': proxy.get('hostname', 'Unknown'),
                    'Target URL': proxy.get('target_url', 'Unknown'),
                    'Certificate': proxy.get('cert_name', 'N/A'),
                    'Enabled': '✓' if proxy.get('enabled', True) else '✗',
                    'Created': created_display,
                    'Token': token_display,
                    'Created By': created_by
                })
        
        if proxy_cursor == 0:
            break
    
    if not proxy_targets:
        if token_name:
            print(f"No proxy targets found for token '{token_name}'")
        else:
            print("No proxy targets found")
        return True
    
    # Sort by token name, then hostname
    proxy_targets.sort(key=lambda x: (x['Token'], x['Hostname']))
    
    # Display results
    if token_name:
        # Single token view - don't show token column
        for proxy in proxy_targets:
            del proxy['Token']
    
    print(tabulate(proxy_targets, headers='keys', tablefmt='grid'))
    print(f"\nTotal proxy targets: {len(proxy_targets)}")
    
    # Summary by token if showing all
    if not token_name:
        token_counts = defaultdict(int)
        for proxy in proxy_targets:
            token_counts[proxy['Token']] += 1
        
        print("\n=== Summary by Token ===")
        for token, count in sorted(token_counts.items()):
            print(f"  {token}: {count} proxy target(s)")
    
    # Count disabled targets
    disabled = [p for p in proxy_targets if p['Enabled'] == '✗']
    if disabled:
        print(f"\n⚠ Note: {len(disabled)} proxy target(s) are disabled")
    
    return True


if __name__ == "__main__":
    token_name = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not show_token_proxies(token_name):
        sys.exit(1)