#!/usr/bin/env python3
"""Debug gui.atradev.org certificate issue."""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

redis_url = os.getenv('REDIS_URL')
storage = RedisStorage(redis_url)

print("=== DEBUGGING GUI CERTIFICATE ===\n")

# 1. Check Redis directly with scan
print("1. Scanning Redis for any gui-related keys...")
cursor = 0
gui_keys = []
while True:
    cursor, keys = storage.redis_client.scan(cursor, match="*gui*", count=100)
    gui_keys.extend(keys)
    if cursor == 0:
        break

print(f"Found {len(gui_keys)} keys containing 'gui':")
for key in gui_keys:
    print(f"  - {key}")
    
# 2. Check specific certificate key
cert_key = "cert:proxy-gui-atradev-org"
print(f"\n2. Checking specific key: {cert_key}")
cert_json = storage.redis_client.get(cert_key)
if cert_json:
    cert_data = json.loads(cert_json)
    print(f"  ✓ Certificate found!")
    print(f"  Domains: {cert_data.get('domains', [])}")
    print(f"  Status: {cert_data.get('status')}")
    print(f"  Email: {cert_data.get('email')}")
else:
    print(f"  ✗ Certificate NOT found in Redis")
    
# 3. Check proxy target
proxy_key = "proxy:gui.atradev.org"
print(f"\n3. Checking proxy target: {proxy_key}")
proxy_json = storage.redis_client.get(proxy_key)
if proxy_json:
    proxy_data = json.loads(proxy_json)
    print(f"  ✓ Proxy found!")
    print(f"  Target URL: {proxy_data.get('target_url')}")
    print(f"  Cert Name: {proxy_data.get('cert_name')}")
    print(f"  HTTPS Enabled: {proxy_data.get('enable_https')}")
else:
    print(f"  ✗ Proxy NOT found")
    
# 4. Check Redis TTL
print(f"\n4. Checking Redis TTL for cert key...")
ttl = storage.redis_client.ttl(cert_key)
if ttl > 0:
    print(f"  Key has TTL: {ttl} seconds")
elif ttl == -1:
    print(f"  Key has no TTL (persistent)")
elif ttl == -2:
    print(f"  Key does not exist")
else:
    print(f"  TTL status: {ttl}")
    
# 5. Check for any certificate with gui.atradev.org domain
print(f"\n5. Searching all certificates for gui.atradev.org domain...")
all_certs = storage.list_certificates()
found = False
for cert in all_certs:
    if "gui.atradev.org" in cert.domains:
        print(f"  ✓ Found certificate: {cert.cert_name}")
        print(f"  Domains: {cert.domains}")
        print(f"  Status: {cert.status}")
        found = True
        
if not found:
    print(f"  ✗ No certificate found with gui.atradev.org domain")
    
# 6. Check for alternate key patterns
print(f"\n6. Checking alternate key patterns...")
alt_patterns = [
    "cert:gui.atradev.org",
    "cert:gui-atradev-org",
    "certificate:proxy-gui-atradev-org",
    "certificate:gui.atradev.org"
]
for pattern in alt_patterns:
    value = storage.redis_client.get(pattern)
    if value:
        print(f"  ✓ Found with key: {pattern}")
        try:
            data = json.loads(value)
            print(f"    Type: {type(data)}")
            if isinstance(data, dict):
                print(f"    Keys: {list(data.keys())[:5]}...")
        except:
            print(f"    Raw value: {value[:100]}...")
    else:
        print(f"  ✗ Not found: {pattern}")