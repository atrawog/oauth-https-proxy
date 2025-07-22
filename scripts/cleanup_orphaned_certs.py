#!/usr/bin/env python3
"""Clean up orphaned certificates that belong to deleted tokens."""

import os
import sys
import json
from tabulate import tabulate

sys.path.insert(0, '/app')

from src.storage import RedisStorage

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

def cleanup_orphaned_certs(dry_run=True):
    """Find and optionally clean up orphaned certificates."""
    print("\n" + "="*80)
    print("ORPHANED CERTIFICATE CLEANUP")
    print("="*80)
    
    # Get all valid token hashes
    valid_token_hashes = set()
    print("\n1. Collecting valid token hashes...")
    for key in storage.redis_client.scan_iter(match="token:*"):
        data = storage.redis_client.hgetall(key)
        if data and 'hash' in data:
            valid_token_hashes.add(data['hash'])
    
    print(f"   Found {len(valid_token_hashes)} valid tokens")
    
    # Check all certificates
    print("\n2. Checking certificates...")
    orphaned = []
    valid = []
    
    for key in storage.redis_client.scan_iter(match="cert:*"):
        cert_name = key.split(":", 1)[1]
        cert_json = storage.redis_client.get(key)
        if cert_json:
            cert = json.loads(cert_json)
            owner_hash = cert.get('owner_token_hash')
            
            if not owner_hash or owner_hash not in valid_token_hashes:
                orphaned.append({
                    'name': cert_name,
                    'domains': cert.get('domains', []),
                    'owner_hash': owner_hash or 'NO_OWNER',
                    'created': cert.get('issued_at', 'Unknown')
                })
            else:
                valid.append(cert_name)
    
    print(f"   Valid certificates: {len(valid)}")
    print(f"   Orphaned certificates: {len(orphaned)}")
    
    if orphaned:
        print("\n3. Orphaned certificates to clean up:")
        table_data = []
        for cert in orphaned:
            table_data.append([
                cert['name'][:40] + '...' if len(cert['name']) > 40 else cert['name'],
                ', '.join(cert['domains'])[:40] + '...' if len(', '.join(cert['domains'])) > 40 else ', '.join(cert['domains']),
                cert['owner_hash'][:16] + '...' if len(cert['owner_hash']) > 16 else cert['owner_hash']
            ])
        
        print(tabulate(table_data, headers=['Certificate', 'Domains', 'Owner Hash'], tablefmt='grid'))
        
        if dry_run:
            print("\n⚠️  DRY RUN MODE - No certificates deleted")
            print("   To actually delete, run with --delete flag")
        else:
            print("\n4. Deleting orphaned certificates...")
            deleted = 0
            for cert in orphaned:
                if storage.delete_certificate(cert['name']):
                    print(f"   ✅ Deleted: {cert['name']}")
                    deleted += 1
                else:
                    print(f"   ❌ Failed to delete: {cert['name']}")
            
            print(f"\n   Total deleted: {deleted}/{len(orphaned)}")
    else:
        print("\n✅ No orphaned certificates found!")
    
    # Also check for orphaned proxy targets
    print("\n5. Checking proxy targets...")
    orphaned_proxies = []
    for key in storage.redis_client.scan_iter(match="proxy:*"):
        hostname = key.split(":", 1)[1]
        proxy_json = storage.redis_client.get(key)
        if proxy_json:
            proxy = json.loads(proxy_json)
            owner_hash = proxy.get('owner_token_hash')
            if not owner_hash or owner_hash not in valid_token_hashes:
                orphaned_proxies.append({
                    'hostname': hostname,
                    'target': proxy.get('target_url', 'Unknown'),
                    'owner_hash': owner_hash or 'NO_OWNER'
                })
    
    if orphaned_proxies:
        print(f"   Found {len(orphaned_proxies)} orphaned proxy targets")
        if not dry_run:
            for proxy in orphaned_proxies:
                if storage.delete_proxy_target(proxy['hostname']):
                    print(f"   ✅ Deleted proxy: {proxy['hostname']}")
    else:
        print("   ✅ No orphaned proxy targets found")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    dry_run = '--delete' not in sys.argv
    cleanup_orphaned_certs(dry_run)