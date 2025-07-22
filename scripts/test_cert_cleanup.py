#!/usr/bin/env python3
"""Test certificate cleanup functionality."""

import sys
import os
import json
import redis
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

def test_cert_cleanup():
    """Test that deleting a certificate cleans up proxy targets."""
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        print("Error: REDIS_URL must be set in .env")
        return False
    
    client = redis.from_url(redis_url, decode_responses=True)
    
    # Create a mock certificate
    cert_name = "test-cleanup-cert"
    cert_data = {
        "cert_name": cert_name,
        "domains": ["test-cleanup.example.com"],
        "email": "test@example.com",
        "status": "active",
        "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "expires_at": "2025-12-31T00:00:00+00:00",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "fullchain_pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"
    }
    
    print(f"Creating mock certificate: {cert_name}")
    client.set(f"cert:{cert_name}", json.dumps(cert_data))
    
    # Update the test proxy to use this certificate
    proxy_key = "proxy:test-cleanup.atradev.org"
    proxy_json = client.get(proxy_key)
    if proxy_json:
        proxy_data = json.loads(proxy_json)
        proxy_data['cert_name'] = cert_name
        client.set(proxy_key, json.dumps(proxy_data))
        print(f"Updated proxy 'test-cleanup.atradev.org' to use certificate '{cert_name}'")
    else:
        print("Error: test-cleanup.atradev.org proxy not found")
        return False
    
    # Verify the proxy has the certificate reference
    proxy_json = client.get(proxy_key)
    proxy_data = json.loads(proxy_json)
    print(f"Before deletion - Proxy cert_name: {proxy_data.get('cert_name')}")
    
    # Now we'll use the manager to delete the certificate, which should trigger cleanup
    
    print(f"\nDeleting certificate '{cert_name}' via manager.delete_certificate()...")
    # Import the manager module to call delete_certificate directly
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.certmanager.manager import CertificateManager
    
    manager = CertificateManager()
    success = manager.delete_certificate(cert_name)
    
    if success:
        print("Certificate deleted successfully")
    else:
        print(f"Failed to delete certificate")
        return False
    
    # Check if the proxy's cert_name was cleared
    proxy_json = client.get(proxy_key)
    if proxy_json:
        proxy_data = json.loads(proxy_json)
        cert_name_after = proxy_data.get('cert_name')
        print(f"After deletion - Proxy cert_name: {cert_name_after}")
        
        if cert_name_after is None:
            print("\n✅ SUCCESS: Certificate deletion properly cleaned up proxy target!")
            return True
        else:
            print(f"\n❌ FAILED: Proxy still has cert_name: {cert_name_after}")
            return False
    else:
        print("Error: Proxy not found after deletion")
        return False


if __name__ == "__main__":
    if not test_cert_cleanup():
        sys.exit(1)