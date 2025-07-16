#!/usr/bin/env python3
import redis
import os
import json

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
r = redis.from_url(redis_url)

cert_name = "proxy-derstandard-atradev-org"

# Check for status key
status_key = f"cert_gen_status:{cert_name}"
status_data = r.get(status_key)

if status_data:
    status = json.loads(status_data)
    print(f"Certificate generation status for {cert_name}:")
    print(f"  Status: {status.get('status')}")
    print(f"  Message: {status.get('message')}")
else:
    print(f"No generation status found for {cert_name}")

# Check if certificate exists
cert_key = f"cert:{cert_name}"
cert_data = r.get(cert_key)

if cert_data:
    cert = json.loads(cert_data)
    print(f"\nCertificate exists:")
    print(f"  Domains: {cert.get('domains')}")
    print(f"  Status: {cert.get('status')}")
else:
    print(f"\nCertificate {cert_name} does not exist in Redis")