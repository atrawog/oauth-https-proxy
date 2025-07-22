#!/usr/bin/env python3
"""Test settings functionality for ALL existing tokens."""

import os
import sys
import json
import requests
from tabulate import tabulate

# Add the parent directory to sys.path
sys.path.insert(0, '/app')

from src.storage import RedisStorage

# Configuration
BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:80")

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

def test_all_tokens():
    """Test settings for all tokens."""
    print("\n" + "="*80)
    print("TESTING SETTINGS FOR ALL TOKENS")
    print("="*80)
    
    # Get all tokens from Redis
    all_tokens = []
    token_errors = []
    
    # Scan for token keys
    print("\n1. Scanning Redis for all tokens...")
    try:
        # Get tokens by name key
        for key in storage.redis_client.scan_iter(match="token:*"):
            if not key.startswith("token:"):
                continue
            
            token_name = key.split(":", 1)[1]
            token_data = storage.redis_client.hgetall(key)
            
            if token_data and 'token' in token_data:
                all_tokens.append({
                    'name': token_name,
                    'token': token_data['token'],
                    'cert_email': token_data.get('cert_email', ''),
                    'created_at': token_data.get('created_at', 'Unknown')
                })
        
        # Also check auth keys for orphaned tokens
        for key in storage.redis_client.scan_iter(match="auth:token:*"):
            token_json = storage.redis_client.get(key)
            if token_json:
                try:
                    data = json.loads(token_json)
                    # Check if we already have this token
                    if not any(t['name'] == data.get('name') for t in all_tokens):
                        all_tokens.append({
                            'name': data.get('name', 'Unknown'),
                            'token': data.get('token', 'Missing'),
                            'cert_email': data.get('cert_email', ''),
                            'created_at': data.get('created_at', 'Unknown')
                        })
                except:
                    pass
        
        print(f"   Found {len(all_tokens)} tokens")
        
    except Exception as e:
        print(f"   ❌ Error scanning Redis: {e}")
        return
    
    if not all_tokens:
        print("   No tokens found in Redis!")
        return
    
    # Display all tokens
    print("\n2. Token Summary:")
    table_data = []
    for t in all_tokens:
        table_data.append([
            t['name'],
            t['token'][:20] + '...' if len(t['token']) > 20 else t['token'],
            t['cert_email'] or '(not set)',
            t['created_at'][:16] if len(t['created_at']) > 16 else t['created_at']
        ])
    
    print(tabulate(table_data, headers=['Name', 'Token Preview', 'Email', 'Created'], tablefmt='grid'))
    
    # Test each token
    print("\n3. Testing /token/info endpoint for each token:")
    print("-" * 80)
    
    success_count = 0
    for token_info in all_tokens:
        name = token_info['name']
        token = token_info['token']
        expected_email = token_info['cert_email']
        
        print(f"\nTesting token: {name}")
        print(f"   Token: {token[:40]}...")
        
        if not token or token == 'Missing':
            print("   ❌ SKIP - Invalid token data")
            token_errors.append(f"{name}: Invalid token data")
            continue
        
        # Test the endpoint
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(f"{BASE_URL}/token/info", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ SUCCESS - Status: {response.status_code}")
                print(f"      Returned name: {data.get('name')}")
                print(f"      Returned email: {data.get('cert_email') or '(not set)'}")
                print(f"      Hash preview: {data.get('hash_preview')}")
                
                # Verify data matches
                if data.get('name') != name:
                    print(f"      ⚠️  WARNING: Name mismatch! Expected: {name}, Got: {data.get('name')}")
                
                returned_email = data.get('cert_email') or ''
                if returned_email != expected_email:
                    print(f"      ⚠️  WARNING: Email mismatch! Expected: {expected_email or '(not set)'}, Got: {returned_email or '(not set)'}")
                
                success_count += 1
            else:
                print(f"   ❌ FAILED - Status: {response.status_code}")
                print(f"      Response: {response.text}")
                token_errors.append(f"{name}: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
            token_errors.append(f"{name}: {str(e)}")
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"\nTotal tokens found: {len(all_tokens)}")
    print(f"Successful tests: {success_count}")
    print(f"Failed tests: {len(token_errors)}")
    
    if token_errors:
        print("\nErrors:")
        for error in token_errors:
            print(f"   - {error}")
    
    # Test edge cases
    print("\n4. Testing Edge Cases:")
    print("-" * 80)
    
    # Test with invalid token
    print("\n   a) Testing with invalid token:")
    headers = {"Authorization": "Bearer invalid_token_12345"}
    response = requests.get(f"{BASE_URL}/token/info", headers=headers)
    print(f"      Status: {response.status_code} (Expected: 401)")
    
    # Test without Bearer prefix
    if all_tokens:
        print("\n   b) Testing without Bearer prefix:")
        headers = {"Authorization": all_tokens[0]['token']}
        response = requests.get(f"{BASE_URL}/token/info", headers=headers)
        print(f"      Status: {response.status_code} (Expected: 403)")
    
    # Test email update for a token without email
    tokens_without_email = [t for t in all_tokens if not t['cert_email']]
    if tokens_without_email:
        print(f"\n   c) Testing email update for token without email ({tokens_without_email[0]['name']}):")
        token = tokens_without_email[0]['token']
        headers = {"Authorization": f"Bearer {token}"}
        
        new_email = f"test-{tokens_without_email[0]['name']}@example.com"
        response = requests.put(
            f"{BASE_URL}/token/email",
            headers=headers,
            json={"cert_email": new_email}
        )
        if response.status_code == 200:
            print(f"      ✅ Email update successful")
            # Verify it was saved
            response2 = requests.get(f"{BASE_URL}/token/info", headers=headers)
            if response2.status_code == 200:
                data = response2.json()
                if data.get('cert_email') == new_email:
                    print(f"      ✅ Email verified: {new_email}")
                else:
                    print(f"      ❌ Email not updated correctly")
        else:
            print(f"      ❌ Email update failed: {response.status_code}")
    
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    test_all_tokens()