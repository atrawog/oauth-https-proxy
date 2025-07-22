#!/usr/bin/env python3
"""Cleanup test tokens created for testing."""

import os
import sys

# Add the parent directory to sys.path
sys.path.insert(0, '/app')

from src.storage import RedisStorage

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

def cleanup_test_tokens():
    """Cleanup test tokens."""
    print("\n" + "="*60)
    print("Cleaning Up Test Tokens")
    print("="*60)
    
    cleaned = 0
    
    # Try to read from file first
    if os.path.exists('/tmp/test_tokens.txt'):
        print("\nReading test tokens from file...")
        with open('/tmp/test_tokens.txt', 'r') as f:
            for line in f:
                if '|' in line:
                    name, token = line.strip().split('|', 1)
                    token_data = storage.get_api_token_by_name(name)
                    if token_data:
                        if storage.delete_api_token_by_name(name):
                            print(f"✅ Deleted: {name}")
                            cleaned += 1
                        else:
                            print(f"❌ Failed to delete: {name}")
        os.remove('/tmp/test_tokens.txt')
    
    # Also clean up any tokens with test prefix
    print("\nScanning for test tokens by prefix...")
    for key in storage.redis_client.scan_iter(match="token:test-*"):
        name = key.split(":", 1)[1]
        if storage.delete_api_token_by_name(name):
            print(f"✅ Deleted: {name}")
            cleaned += 1
    
    print(f"\n{'='*60}")
    print(f"Cleaned up {cleaned} test tokens")
    print("="*60)

if __name__ == "__main__":
    cleanup_test_tokens()