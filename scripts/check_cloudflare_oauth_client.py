#!/usr/bin/env python3
import redis
import os
import json
import sys

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
# If running outside container, use the exposed port
if 'redis' not in redis_url:
    redis_url = 'redis://:4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589@localhost:16379/0'
r = redis.from_url(redis_url)

# Check for the Cloudflare OAuth client
client_id = "y1hjisvFENM6Bk8J"
client_key = f"oauth:client:{client_id}"

print(f"Checking for Cloudflare OAuth client: {client_id}")
client_data = r.get(client_key)

if client_data:
    print("\nClient found!")
    client_json = json.loads(client_data)
    print(json.dumps(client_json, indent=2))
    
    # Check redirect URIs
    redirect_uris = json.loads(client_json.get('redirect_uris', '[]'))
    print(f"\nRedirect URIs: {redirect_uris}")
    
    # Check if the IP-based redirect URI is registered
    target_uri = "http://5.9.28.62:8080/callback"
    if target_uri in redirect_uris:
        print(f"✓ {target_uri} is registered")
    else:
        print(f"✗ {target_uri} is NOT registered")
        print("\nThis might be causing the Internal Error!")
else:
    print("\nClient NOT found in Redis!")
    print("This client might have been registered directly with Cloudflare's OAuth server.")
    
# List all OAuth clients in Redis
print("\n\nAll OAuth clients in Redis:")
oauth_keys = sorted([k.decode() for k in r.keys('oauth:client:*')])
for key in oauth_keys:
    client_id_from_key = key.split(':')[-1]
    print(f"  {client_id_from_key}")