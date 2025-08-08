#!/usr/bin/env python3
"""Test token creation and storage."""

import os
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

api_url = os.getenv("API_URL", "http://localhost")
admin_token = os.getenv("ADMIN_TOKEN")

print(f"Base URL: {api_url}")
print(f"Admin token: {admin_token[:20]}..." if admin_token else "No admin token")

# Create a test token
token_name = "debug-test-token"
token_email = "debug@test.com"

print(f"\nCreating token '{token_name}'...")
response = httpx.post(
    f"{api_url}/tokens/",
    headers={"Authorization": f"Bearer {admin_token}"},
    json={"name": token_name, "cert_email": token_email}
)

print(f"Response status: {response.status_code}")
if response.status_code == 200:
    data = response.json()
    print(f"Token created: {data}")
    new_token = data["token"]
    
    # Test the new token
    print(f"\nTesting new token authentication...")
    test_response = httpx.get(
        f"{api_url}/tokens/info",
        headers={"Authorization": f"Bearer {new_token}"}
    )
    print(f"Auth test status: {test_response.status_code}")
    if test_response.status_code == 200:
        print(f"Token info: {test_response.json()}")
    else:
        print(f"Auth error: {test_response.text}")
    
    # List tokens
    print(f"\nListing all tokens...")
    list_response = httpx.get(
        f"{api_url}/tokens/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print(f"List status: {list_response.status_code}")
    if list_response.status_code == 200:
        tokens = list_response.json()
        print(f"Found {len(tokens)} tokens")
        for token in tokens:
            print(f"  - {token['name']} ({token.get('cert_email', 'no email')})")
    
    # Clean up
    print(f"\nCleaning up...")
    delete_response = httpx.delete(
        f"{api_url}/tokens/{token_name}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    print(f"Delete status: {delete_response.status_code}")
else:
    print(f"Error: {response.text}")