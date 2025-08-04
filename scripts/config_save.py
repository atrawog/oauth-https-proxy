#!/usr/bin/env python3
"""Save complete configuration including certificates to YAML backup file."""

import sys
import os
import json
import yaml
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.redis_storage import RedisStorage

def save_config(filename: str = None):
    """Save all configuration from Redis to YAML file."""
    # Default filename with timestamp
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"backup_{timestamp}.yaml"
    
    # Ensure backup directory exists
    backup_dir = Path("./backup")
    backup_dir.mkdir(exist_ok=True)
    
    # Full path for backup file
    backup_path = backup_dir / filename
    
    # Connect to Redis
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        print("Error: REDIS_URL must be set in .env")
        return False
    
    storage = RedisStorage(redis_url)
    
    # Configuration data structure
    config = {
        'metadata': {
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'description': 'MCP HTTP Proxy configuration backup'
        },
        'tokens': {},
        'certificates': {},
        'proxies': {},
        'routes': {},
        'services': {},
        'instances': {},
        'oauth_clients': {},
        'ports': {},
        'resources': {},
        'domain_mappings': {}
    }
    
    print(f"Saving configuration to {backup_path}")
    
    # Save tokens
    print("  - Saving tokens...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="token:*", count=100)
        for key in keys:
            token_data = storage.redis_client.hgetall(key)
            if token_data:
                name = token_data.get('name', key.split(':', 1)[1])
                config['tokens'][name] = dict(token_data)
        if cursor == 0:
            break
    
    # Save certificates (with full PEM data)
    print("  - Saving certificates...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="cert:*", count=100)
        for key in keys:
            # Skip domain mappings
            if ':domain:' in key:
                continue
            
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type != 'string':
                continue
                
            cert_json = storage.redis_client.get(key)
            if cert_json:
                try:
                    cert_data = json.loads(cert_json)
                    cert_name = cert_data.get('cert_name', key.split(':', 1)[1])
                    config['certificates'][cert_name] = cert_data
                except json.JSONDecodeError:
                    print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Save domain mappings
    print("  - Saving domain mappings...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="cert:domain:*", count=100)
        for key in keys:
            cert_name = storage.redis_client.get(key)
            if cert_name:
                domain = key.split(':', 2)[2]
                config['domain_mappings'][domain] = cert_name
        if cursor == 0:
            break
    
    # Save proxy targets
    print("  - Saving proxy targets...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="proxy:*", count=100)
        for key in keys:
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type != 'string':
                continue
                
            proxy_json = storage.redis_client.get(key)
            if proxy_json:
                try:
                    proxy_data = json.loads(proxy_json)
                    hostname = proxy_data.get('hostname', key.split(':', 1)[1])
                    config['proxies'][hostname] = proxy_data
                except json.JSONDecodeError:
                    print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Save routes
    print("  - Saving routes...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="route:*", count=100)
        for key in keys:
            # Skip route index keys
            if ':priority:' in key or ':unique:' in key:
                continue
            
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type != 'string':
                continue
                
            route_json = storage.redis_client.get(key)
            if route_json:
                try:
                    route_data = json.loads(route_json)
                    route_id = route_data.get('route_id', key.split(':', 1)[1])
                    config['routes'][route_id] = route_data
                except json.JSONDecodeError:
                    print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Save services
    print("  - Saving services...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="docker_service:*", count=100)
        for key in keys:
            # Skip status keys
            if ':status' in key or ':stats' in key:
                continue
            
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type != 'string':
                continue
                
            service_json = storage.redis_client.get(key)
            if service_json:
                try:
                    service_data = json.loads(service_json)
                    service_name = service_data.get('service_name', key.split(':', 1)[1])
                    config['services'][service_name] = service_data
                except json.JSONDecodeError:
                    print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Save instances
    print("  - Saving instances...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="instance:*", count=100)
        for key in keys:
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type != 'string':
                continue
                
            instance_json = storage.redis_client.get(key)
            if instance_json:
                try:
                    instance_data = json.loads(instance_json)
                    # Ensure we have a dict
                    if isinstance(instance_data, dict):
                        instance_name = instance_data.get('name', key.split(':', 1)[1])
                        config['instances'][instance_name] = instance_data
                    else:
                        print(f"    Warning: Non-dict data for {key}: {type(instance_data)}")
                except json.JSONDecodeError:
                    print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Save OAuth clients
    print("  - Saving OAuth clients...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="oauth:client:*", count=100)
        for key in keys:
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type == 'hash':
                client_data = storage.redis_client.hgetall(key)
                if client_data:
                    client_id = client_data.get('client_id', key.split(':', 2)[2])
                    config['oauth_clients'][client_id] = dict(client_data)
            else:
                print(f"    Warning: Expected hash for {key}, got {key_type}")
        if cursor == 0:
            break
    
    # Save port allocations
    print("  - Saving port allocations...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="port:*", count=100)
        for key in keys:
            if ':token:' in key:
                # Port access token
                # Check key type before accessing
                key_type = storage.redis_client.type(key)
                if key_type == 'hash':
                    token_data = storage.redis_client.hgetall(key)
                    if token_data:
                        token_name = key.split(':', 2)[2]
                        if 'port_tokens' not in config:
                            config['port_tokens'] = {}
                        config['port_tokens'][token_name] = dict(token_data)
                else:
                    print(f"    Warning: Expected hash for {key}, got {key_type}")
            else:
                # Port allocation
                # Check key type before accessing
                key_type = storage.redis_client.type(key)
                if key_type == 'string':
                    port_json = storage.redis_client.get(key)
                    if port_json:
                        try:
                            port_data = json.loads(port_json)
                            port_key = key.split(':', 1)[1]
                            config['ports'][port_key] = port_data
                        except json.JSONDecodeError:
                            print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Save OAuth resources
    print("  - Saving OAuth resources...")
    cursor = 0
    while True:
        cursor, keys = storage.redis_client.scan(cursor, match="resource:*", count=100)
        for key in keys:
            # Check key type before accessing
            key_type = storage.redis_client.type(key)
            if key_type != 'string':
                continue
                
            resource_json = storage.redis_client.get(key)
            if resource_json:
                try:
                    resource_data = json.loads(resource_json)
                    resource_uri = resource_data.get('uri', key.split(':', 1)[1])
                    config['resources'][resource_uri] = resource_data
                except json.JSONDecodeError:
                    print(f"    Warning: Invalid JSON for {key}")
        if cursor == 0:
            break
    
    # Count items
    counts = {
        'tokens': len(config['tokens']),
        'certificates': len(config['certificates']),
        'proxies': len(config['proxies']),
        'routes': len(config['routes']),
        'services': len(config['services']),
        'instances': len(config['instances']),
        'oauth_clients': len(config['oauth_clients']),
        'ports': len(config['ports']),
        'resources': len(config['resources'])
    }
    
    config['metadata']['counts'] = counts
    
    # Write to YAML file
    try:
        with open(backup_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"\n✅ Configuration saved to {backup_path}")
        print("\nSummary:")
        for item_type, count in counts.items():
            if count > 0:
                print(f"  - {item_type}: {count}")
        
        # Show file size
        size = backup_path.stat().st_size
        if size > 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        elif size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} bytes"
        
        print(f"\nBackup file size: {size_str}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error saving configuration: {e}")
        return False


if __name__ == "__main__":
    # Optional filename argument
    filename = sys.argv[1] if len(sys.argv) > 1 else None
    
    if not save_config(filename):
        sys.exit(1)