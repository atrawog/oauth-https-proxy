#!/usr/bin/env python3
import redis
import os
import json
import sys

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
r = redis.from_url(redis_url)

# Client to update
client_id = "client_omiZ88cO1HF5d79UDmIUPg"
client_key = f"oauth:client:{client_id}"

print(f"Updating client: {client_id}")

# Get existing client data
client_data = r.get(client_key)
if not client_data:
    print("Client not found!")
    sys.exit(1)

client_json = json.loads(client_data)
print("Current client data:")
print(json.dumps(client_json, indent=2))

# Parse existing redirect URIs
redirect_uris = json.loads(client_json.get('redirect_uris', '[]'))
print(f"\nCurrent redirect URIs: {redirect_uris}")

# Add the out-of-band URI
oob_uri = "urn:ietf:wg:oauth:2.0:oob"
if oob_uri not in redirect_uris:
    redirect_uris.append(oob_uri)
    print(f"Adding {oob_uri} to redirect URIs")
    
    # Update the client data
    client_json['redirect_uris'] = json.dumps(redirect_uris)
    
    # Save back to Redis
    r.set(client_key, json.dumps(client_json))
    print("\nClient updated successfully!")
    
    # Verify the update
    updated_data = r.get(client_key)
    updated_json = json.loads(updated_data)
    updated_uris = json.loads(updated_json.get('redirect_uris', '[]'))
    print(f"Updated redirect URIs: {updated_uris}")
else:
    print(f"{oob_uri} is already registered")