#!/usr/bin/env python3
"""List all API tokens."""

import sys
import os
import json
from datetime import datetime
from tabulate import tabulate

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

def list_tokens():
    """List all API tokens with their details."""
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    # Get all token keys (using name-based keys)
    token_keys = []
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="token:*", count=100)
        token_keys.extend(keys)
        if cursor == 0:
            break
    
    if not token_keys:
        print("No tokens found.")
        return
    
    # Collect token data
    tokens = []
    for key in token_keys:
        try:
            # Get token data from hash
            token_data = storage.redis_client.hgetall(key)
            if token_data:
                token_hash = token_data.get('hash', '')
                # Count certificates owned by this token
                cert_count = 0
                cert_cursor = 0
                while True:
                    cert_cursor, cert_keys = storage.redis_client.scan(
                        cert_cursor, match="cert:*", count=100
                    )
                    for cert_key in cert_keys:
                        cert_json = storage.redis_client.get(cert_key)
                        if cert_json:
                            try:
                                cert = json.loads(cert_json)
                                if cert.get('owner_token_hash') == token_hash:
                                    cert_count += 1
                            except json.JSONDecodeError:
                                # Skip invalid JSON
                                pass
                    if cert_cursor == 0:
                        break
                
                # Count proxy targets owned by this token
                proxy_count = 0
                proxy_cursor = 0
                while True:
                    proxy_cursor, proxy_keys = storage.redis_client.scan(
                        proxy_cursor, match="proxy:*", count=100
                    )
                    for proxy_key in proxy_keys:
                        proxy_json = storage.redis_client.get(proxy_key)
                        if proxy_json:
                            try:
                                proxy = json.loads(proxy_json)
                                if proxy.get('owner_token_hash') == token_hash:
                                    proxy_count += 1
                            except json.JSONDecodeError:
                                # Skip invalid JSON
                                pass
                    if proxy_cursor == 0:
                        break
                
                name = token_data.get('name', 'Unknown')
                # Show FULL token - user explicitly wants full visibility
                token_display = token_data.get('token', 'N/A')
                
                tokens.append({
                    'Name': name,
                    'Token': token_display,
                    'Email': token_data.get('cert_email') or '(not set)',
                    'Created': datetime.fromisoformat(
                        token_data.get('created_at', '')
                    ).strftime('%Y-%m-%d %H:%M') if token_data.get('created_at') else 'Unknown',
                    'Certs': cert_count,
                    'Proxies': proxy_count,
                    'Type': 'Admin' if name == 'ADMIN' else 'User'
                })
        except Exception as e:
            print(f"Error processing token {key}: {e}")
    
    # Sort by creation date
    tokens.sort(key=lambda x: x['Created'], reverse=True)
    
    # Display results
    print(f"\n=== API Tokens ({len(tokens)} total) ===\n")
    if tokens:
        print(tabulate(tokens, headers='keys', tablefmt='grid'))
    
    print(f"\nTotal tokens: {len(tokens)}")


if __name__ == "__main__":
    list_tokens()