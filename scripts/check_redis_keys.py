#!/usr/bin/env python3
import redis
import os

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
r = redis.from_url(redis_url)

proxy_keys = sorted([k.decode() for k in r.keys('proxy:*')])
cert_keys = sorted([k.decode() for k in r.keys('cert:*')])

print("Proxy keys:")
for key in proxy_keys:
    print(f"  {key}")

print("\nCertificate keys:")
for key in cert_keys:
    print(f"  {key}")