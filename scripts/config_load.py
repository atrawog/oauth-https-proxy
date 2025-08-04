#!/usr/bin/env python3
"""Load configuration from YAML backup file to Redis."""

import sys
import os
import json
import yaml
from datetime import datetime
from pathlib import Path
from tabulate import tabulate

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.redis_storage import RedisStorage

def confirm_load(config_data, filename):
    """Show summary and ask for confirmation."""
    counts = config_data['metadata'].get('counts', {})
    timestamp = config_data['metadata'].get('timestamp', 'Unknown')
    
    print(f"\n=== Configuration Summary ===")
    print(f"File: {filename}")
    print(f"Backup created: {timestamp}")
    print("\nItems to restore:")
    
    table_data = []
    for item_type, count in counts.items():
        if count > 0:
            table_data.append({'Type': item_type.replace('_', ' ').title(), 'Count': count})
    
    if table_data:
        print(tabulate(table_data, headers='keys', tablefmt='simple'))
    
    print("\n⚠️  WARNING: This will REPLACE all existing configuration!")
    response = input("\nDo you want to continue? (yes/no): ")
    
    return response.lower() in ['yes', 'y']

def load_config(filename: str, force: bool = False):
    """Load configuration from YAML file to Redis."""
    # Check if filename is absolute path or just filename
    if '/' in filename:
        backup_path = Path(filename)
    else:
        backup_path = Path("./backup") / filename
    
    # Check if file exists
    if not backup_path.exists():
        print(f"Error: Backup file not found: {backup_path}")
        return False
    
    # Connect to Redis
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        print("Error: REDIS_URL must be set in .env")
        return False
    
    storage = RedisStorage(redis_url)
    
    # Load YAML file
    try:
        with open(backup_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading YAML file: {e}")
        return False
    
    # Validate config structure
    if 'metadata' not in config:
        print("Error: Invalid backup file - missing metadata")
        return False
    
    # Show summary and confirm unless forced
    if not force and not confirm_load(config, backup_path):
        print("Load cancelled.")
        return False
    
    print(f"\nLoading configuration from {backup_path}")
    
    # Track results
    results = {
        'tokens': {'loaded': 0, 'failed': 0},
        'certificates': {'loaded': 0, 'failed': 0},
        'proxies': {'loaded': 0, 'failed': 0},
        'routes': {'loaded': 0, 'failed': 0},
        'services': {'loaded': 0, 'failed': 0},
        'instances': {'loaded': 0, 'failed': 0},
        'oauth_clients': {'loaded': 0, 'failed': 0},
        'ports': {'loaded': 0, 'failed': 0},
        'resources': {'loaded': 0, 'failed': 0}
    }
    
    # Clear existing data (optional - could make this configurable)
    if force:
        print("  - Clearing existing configuration...")
        # This is dangerous - only do specific patterns to avoid deleting other data
        patterns = [
            "token:*", "cert:*", "proxy:*", "route:*", 
            "service:*", "instance:*", "oauth:client:*", 
            "port:*", "resource:*"
        ]
        for pattern in patterns:
            cursor = 0
            while True:
                cursor, keys = storage.redis_client.scan(cursor, match=pattern, count=100)
                if keys:
                    storage.redis_client.delete(*keys)
                if cursor == 0:
                    break
    
    # Load tokens
    print("  - Loading tokens...")
    for name, token_data in config.get('tokens', {}).items():
        try:
            key = f"token:{name}"
            storage.redis_client.hset(key, mapping=token_data)
            # Also store by hash for auth lookup
            if 'hash' in token_data:
                storage.redis_client.set(f"token:hash:{token_data['hash']}", name)
            results['tokens']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load token {name}: {e}")
            results['tokens']['failed'] += 1
    
    # Load certificates
    print("  - Loading certificates...")
    for cert_name, cert_data in config.get('certificates', {}).items():
        try:
            key = f"cert:{cert_name}"
            storage.redis_client.set(key, json.dumps(cert_data))
            results['certificates']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load certificate {cert_name}: {e}")
            results['certificates']['failed'] += 1
    
    # Load domain mappings
    print("  - Loading domain mappings...")
    for domain, cert_name in config.get('domain_mappings', {}).items():
        try:
            storage.redis_client.set(f"cert:domain:{domain}", cert_name)
        except Exception as e:
            print(f"    Failed to load domain mapping {domain}: {e}")
    
    # Load proxy targets
    print("  - Loading proxy targets...")
    for hostname, proxy_data in config.get('proxies', {}).items():
        try:
            key = f"proxy:{hostname}"
            storage.redis_client.set(key, json.dumps(proxy_data))
            results['proxies']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load proxy {hostname}: {e}")
            results['proxies']['failed'] += 1
    
    # Load routes
    print("  - Loading routes...")
    for route_id, route_data in config.get('routes', {}).items():
        try:
            key = f"route:{route_id}"
            storage.redis_client.set(key, json.dumps(route_data))
            results['routes']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load route {route_id}: {e}")
            results['routes']['failed'] += 1
    
    # Load services
    print("  - Loading services...")
    for service_name, service_data in config.get('services', {}).items():
        try:
            key = f"service:{service_name}"
            storage.redis_client.set(key, json.dumps(service_data))
            results['services']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load service {service_name}: {e}")
            results['services']['failed'] += 1
    
    # Load instances
    print("  - Loading instances...")
    for instance_name, instance_data in config.get('instances', {}).items():
        try:
            key = f"instance:{instance_name}"
            storage.redis_client.set(key, json.dumps(instance_data))
            results['instances']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load instance {instance_name}: {e}")
            results['instances']['failed'] += 1
    
    # Load OAuth clients
    print("  - Loading OAuth clients...")
    for client_id, client_data in config.get('oauth_clients', {}).items():
        try:
            key = f"oauth:client:{client_id}"
            storage.redis_client.hset(key, mapping=client_data)
            results['oauth_clients']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load OAuth client {client_id}: {e}")
            results['oauth_clients']['failed'] += 1
    
    # Load port allocations
    print("  - Loading port allocations...")
    for port_key, port_data in config.get('ports', {}).items():
        try:
            key = f"port:{port_key}"
            storage.redis_client.set(key, json.dumps(port_data))
            results['ports']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load port {port_key}: {e}")
            results['ports']['failed'] += 1
    
    # Load port tokens
    for token_name, token_data in config.get('port_tokens', {}).items():
        try:
            key = f"port:token:{token_name}"
            storage.redis_client.hset(key, mapping=token_data)
        except Exception as e:
            print(f"    Failed to load port token {token_name}: {e}")
    
    # Load OAuth resources
    print("  - Loading OAuth resources...")
    for resource_uri, resource_data in config.get('resources', {}).items():
        try:
            key = f"resource:{resource_uri}"
            storage.redis_client.set(key, json.dumps(resource_data))
            results['resources']['loaded'] += 1
        except Exception as e:
            print(f"    Failed to load resource {resource_uri}: {e}")
            results['resources']['failed'] += 1
    
    # Show results
    print("\n=== Load Results ===")
    table_data = []
    total_loaded = 0
    total_failed = 0
    
    for item_type, counts in results.items():
        if counts['loaded'] > 0 or counts['failed'] > 0:
            table_data.append({
                'Type': item_type.replace('_', ' ').title(),
                'Loaded': counts['loaded'],
                'Failed': counts['failed']
            })
            total_loaded += counts['loaded']
            total_failed += counts['failed']
    
    if table_data:
        print(tabulate(table_data, headers='keys', tablefmt='grid'))
    
    if total_failed == 0:
        print(f"\n✅ Configuration loaded successfully!")
        print(f"   Total items restored: {total_loaded}")
    else:
        print(f"\n⚠️  Configuration loaded with errors")
        print(f"   Loaded: {total_loaded}, Failed: {total_failed}")
    
    # Suggest restart
    print("\n💡 Note: You may need to restart services for changes to take effect:")
    print("   just restart")
    
    return total_failed == 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python config_load.py <filename> [--force]")
        print("\nExamples:")
        print("  python config_load.py backup_20241215_120000.yaml")
        print("  python config_load.py backup.yaml --force")
        print("\nOptions:")
        print("  --force   Skip confirmation and clear existing data")
        sys.exit(1)
    
    filename = sys.argv[1]
    force = '--force' in sys.argv
    
    if not load_config(filename, force):
        sys.exit(1)