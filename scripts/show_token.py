#!/usr/bin/env python3
"""Show full API token by name."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_certmanager.storage import RedisStorage

def show_token(token_name: str):
    """Show full API token by name."""
    if not token_name:
        print("Error: Token name is required")
        return False
    
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    # Get token by name
    token_data = storage.get_api_token_by_name(token_name)
    
    if not token_data:
        print(f"Error: Token '{token_name}' not found")
        return False
    
    full_token = token_data.get('token')
    if not full_token:
        print(f"Error: Token data corrupted for '{token_name}'")
        return False
    
    print(f"=== Token Details ===")
    print(f"Name: {token_name}")
    print(f"Token: {full_token}")
    print(f"Created: {token_data.get('created_at')}")
    print(f"\nUse this token to:")
    print(f"- Login to the web GUI at http://localhost:80")
    print(f"- Make API calls with Authorization: Bearer {full_token}")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python show_token.py <token_name>")
        sys.exit(1)
    
    token_name = sys.argv[1]
    if not show_token(token_name):
        sys.exit(1)