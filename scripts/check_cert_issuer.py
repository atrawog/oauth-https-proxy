#!/usr/bin/env python
"""Check certificate issuer from Redis."""

import os
import redis
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend

redis_url = os.getenv('REDIS_URL')
r = redis.from_url(redis_url, decode_responses=True)

cert_json = r.get('cert:proxy-fetcher-atradev-org')
if cert_json:
    cert_data = json.loads(cert_json)
    cert_pem = cert_data.get('fullchain_pem', '')
    
    # Parse certificate
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    
    # Get issuer
    issuer = cert.issuer.rfc4514_string()
    print(f'Issuer: {issuer}')
    print(f'ACME URL: {cert_data.get("acme_directory_url")}')
    
    # Check if staging
    if 'STAGING' in issuer:
        print('WARNING: Certificate is still from STAGING!')
    else:
        print('Certificate is from PRODUCTION')
else:
    print('Certificate not found')