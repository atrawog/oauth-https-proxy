#!/usr/bin/env python3
"""Check for gui certificates."""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import RedisStorage

redis_url = os.getenv('REDIS_URL')
storage = RedisStorage(redis_url)

# List all certificates
certs = storage.list_certificates()
print(f"Total certificates: {len(certs)}")
print()

# Search for gui-related certificates
gui_certs = []
for cert in certs:
    if 'gui' in cert.cert_name.lower() or any('gui' in d.lower() for d in cert.domains):
        gui_certs.append(cert)
        print(f"Found GUI certificate: {cert.cert_name}")
        print(f"  Domains: {cert.domains}")
        print(f"  Status: {cert.status}")
        print(f"  Expires: {cert.expires_at}")
        print()

if not gui_certs:
    print("No GUI certificates found in storage")
    
# Check directly in Redis for proxy-gui-atradev-org
print("\nChecking Redis directly for proxy-gui-atradev-org...")
key = "cert:proxy-gui-atradev-org"
value = storage.redis_client.get(key)
if value:
    print(f"Found in Redis: {key}")
    cert_data = json.loads(value)
    print(f"  Domains: {cert_data.get('domains', [])}")
    print(f"  Status: {cert_data.get('status')}")
else:
    print(f"Not found in Redis: {key}")

# Check where the certificate might be loaded from
print("\nChecking HTTPS server certificates...")
from src.https_server import HTTPSServer
from src.certificate_manager import CertificateManager

manager = CertificateManager()
https_server = HTTPSServer(manager)

# Check if certificate is in SSL contexts
if hasattr(https_server, 'ssl_contexts'):
    print(f"SSL contexts loaded: {len(https_server.ssl_contexts)}")
    if 'gui.atradev.org' in https_server.ssl_contexts:
        print("  ✓ gui.atradev.org has SSL context loaded")