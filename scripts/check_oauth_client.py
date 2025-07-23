#!/usr/bin/env python3
import redis
import os
import json
import sys

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
r = redis.from_url(redis_url)

# Check for specific client
client_id = "client_omiZ88cO1HF5d79UDmIUPg"
client_key = f"oauth:client:{client_id}"

print(f"Checking for client: {client_id}")
client_data = r.get(client_key)

if client_data:
    print("\nClient found!")
    client_json = json.loads(client_data)
    print(json.dumps(client_json, indent=2))
    
    # Check redirect URIs
    redirect_uris = json.loads(client_json.get('redirect_uris', '[]'))
    print(f"\nRedirect URIs: {redirect_uris}")
    
    # Check if urn:ietf:wg:oauth:2.0:oob is in the list
    oob_uri = "urn:ietf:wg:oauth:2.0:oob"
    if oob_uri in redirect_uris:
        print(f"✓ {oob_uri} is registered")
    else:
        print(f"✗ {oob_uri} is NOT registered")
else:
    print("\nClient NOT found!")
    
# List all OAuth clients
print("\n\nAll OAuth clients:")
oauth_keys = sorted([k.decode() for k in r.keys('oauth:client:*')])
for key in oauth_keys:
    print(f"  {key}")