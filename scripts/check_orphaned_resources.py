#!/usr/bin/env python3
"""Check for orphaned resources and report them."""

import os
import sys
import json

sys.path.insert(0, '/app')

from src.storage import RedisStorage

def check_orphaned_resources():
    """Check for orphaned certificates and proxy targets."""
    redis_url = os.getenv('REDIS_URL')
    storage = RedisStorage(redis_url)
    
    # Get all valid token hashes
    valid_token_hashes = set()
    for key in storage.redis_client.scan_iter(match="token:*"):
        data = storage.redis_client.hgetall(key)
        if data and 'hash' in data:
            valid_token_hashes.add(data['hash'])
    
    # Check certificates
    orphaned_certs = []
    valid_certs = 0
    
    for key in storage.redis_client.scan_iter(match="cert:*"):
        cert_json = storage.redis_client.get(key)
        if cert_json:
            cert = json.loads(cert_json)
            owner_hash = cert.get('owner_token_hash')
            
            if not owner_hash or owner_hash not in valid_token_hashes:
                cert_name = key.split(':', 1)[1]
                orphaned_certs.append({
                    'name': cert_name,
                    'domains': cert.get('domains', []),
                    'owner_hash': owner_hash or 'NO_OWNER'
                })
            else:
                valid_certs += 1
    
    # Check proxy targets
    orphaned_proxies = []
    valid_proxies = 0
    
    for key in storage.redis_client.scan_iter(match="proxy:*"):
        proxy_json = storage.redis_client.get(key)
        if proxy_json:
            proxy = json.loads(proxy_json)
            owner_hash = proxy.get('owner_token_hash')
            
            if not owner_hash or owner_hash not in valid_token_hashes:
                hostname = key.split(':', 1)[1]
                orphaned_proxies.append({
                    'hostname': hostname,
                    'target': proxy.get('target_url', 'Unknown'),
                    'owner_hash': owner_hash or 'NO_OWNER'
                })
            else:
                valid_proxies += 1
    
    # Report findings
    has_orphans = len(orphaned_certs) > 0 or len(orphaned_proxies) > 0
    
    if has_orphans:
        print("⚠️  ORPHANED RESOURCES DETECTED!")
        print(f"\nTokens: {len(valid_token_hashes)}")
        print(f"Valid certificates: {valid_certs}")
        print(f"Valid proxy targets: {valid_proxies}")
        
        if orphaned_certs:
            print(f"\n❌ Orphaned certificates: {len(orphaned_certs)}")
            for cert in orphaned_certs[:5]:  # Show first 5
                print(f"  - {cert['name']} (domains: {', '.join(cert['domains'])})")
            if len(orphaned_certs) > 5:
                print(f"  ... and {len(orphaned_certs) - 5} more")
        
        if orphaned_proxies:
            print(f"\n❌ Orphaned proxy targets: {len(orphaned_proxies)}")
            for proxy in orphaned_proxies[:5]:  # Show first 5
                print(f"  - {proxy['hostname']} -> {proxy['target']}")
            if len(orphaned_proxies) > 5:
                print(f"  ... and {len(orphaned_proxies) - 5} more")
        
        print("\n💡 To clean up orphaned resources, run:")
        print("   just cleanup-orphaned-certs delete")
        
        return False
    else:
        print("✅ No orphaned resources found!")
        print(f"\nTokens: {len(valid_token_hashes)}")
        print(f"Certificates: {valid_certs}")
        print(f"Proxy targets: {valid_proxies}")
        return True


if __name__ == "__main__":
    if not check_orphaned_resources():
        sys.exit(1)