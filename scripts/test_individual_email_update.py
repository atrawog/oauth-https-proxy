#!/usr/bin/env python3
"""Test individual token email update."""

import sys
import requests

BASE_URL = "http://localhost:80"

if len(sys.argv) < 2:
    print("Usage: test_individual_email_update.py <token>")
    sys.exit(1)

token = sys.argv[1]
print(f"\nTesting email update for token: {token[:40]}...")

headers = {"Authorization": f"Bearer {token}"}

# First get current info
response = requests.get(f"{BASE_URL}/token/info", headers=headers)
if response.status_code == 200:
    info = response.json()
    print(f"Current info:")
    print(f"  Name: {info.get('name')}")
    print(f"  Email: {info.get('cert_email') or '(not set)'}")
else:
    print(f"Failed to get token info: {response.status_code}")
    sys.exit(1)

# Try to update email
new_email = f"updated-{info.get('name')}@example.com"
print(f"\nUpdating email to: {new_email}")

response = requests.put(
    f"{BASE_URL}/token/email",
    headers=headers,
    json={"cert_email": new_email}
)

print(f"Response status: {response.status_code}")
print(f"Response: {response.text}")

if response.status_code == 200:
    # Verify update
    response2 = requests.get(f"{BASE_URL}/token/info", headers=headers)
    if response2.status_code == 200:
        info2 = response2.json()
        print(f"\nAfter update:")
        print(f"  Name: {info2.get('name')}")
        print(f"  Email: {info2.get('cert_email') or '(not set)'}")
        if info2.get('cert_email') == new_email:
            print("✅ Email successfully updated!")
        else:
            print("❌ Email not updated correctly")