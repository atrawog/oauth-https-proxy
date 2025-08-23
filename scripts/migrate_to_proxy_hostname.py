#!/usr/bin/env python3
"""
COMPLETE MIGRATION TO proxy_hostname EVERYWHERE.
This script migrates ALL references from hostname to proxy_hostname.
"""

import os
import re
import sys
from pathlib import Path

def migrate_file(filepath):
    """Migrate a single file to use proxy_hostname."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # CORE MODEL CHANGES
    if 'class ProxyTarget' in content:
        # Change the model field
        content = re.sub(r'\bhostname:\s*str\b', 'proxy_hostname: str', content)
        content = re.sub(r'\.hostname\b', '.proxy_hostname', content)
    
    # STORAGE KEYS - Change all Redis key patterns
    content = re.sub(r'f"proxy:{hostname}"', 'f"proxy:{proxy_hostname}"', content)
    content = re.sub(r'f"proxy:{([^}]+)\.hostname}"', r'f"proxy:{\1.proxy_hostname}"', content)
    content = re.sub(r'"proxy:" \+ hostname', '"proxy:" + proxy_hostname', content)
    content = re.sub(r'f"instance:state:{hostname}"', 'f"instance:state:{proxy_hostname}"', content)
    content = re.sub(r'f"route:{hostname}:', 'f"route:{proxy_hostname}:', content)
    content = re.sub(r'f"cert:proxy-{hostname}"', 'f"cert:proxy-{proxy_hostname}"', content)
    
    # API ENDPOINTS - Change all path parameters
    content = re.sub(r'{hostname}', '{proxy_hostname}', content)
    content = re.sub(r'\(hostname:\s*str', '(proxy_hostname: str', content)
    content = re.sub(r'hostname:\s*str\s*=\s*Path', 'proxy_hostname: str = Path', content)
    content = re.sub(r'hostname\s*=\s*Path', 'proxy_hostname = Path', content)
    
    # REQUEST/RESPONSE MODELS
    content = re.sub(r'\brequest\.hostname\b', 'request.proxy_hostname', content)
    content = re.sub(r'\btarget\.hostname\b', 'target.proxy_hostname', content)
    content = re.sub(r'\bproxy\.hostname\b', 'proxy.proxy_hostname', content)
    content = re.sub(r'hostname\s*=\s*request\.hostname', 'proxy_hostname = request.proxy_hostname', content)
    
    # FUNCTION PARAMETERS
    content = re.sub(r'def ([^(]+)\(([^)]*)hostname:\s*str', r'def \1(\2proxy_hostname: str', content)
    content = re.sub(r'async def ([^(]+)\(([^)]*)hostname:\s*str', r'async def \1(\2proxy_hostname: str', content)
    content = re.sub(r'\(hostname\s*=\s*', '(proxy_hostname=', content)
    content = re.sub(r',\s*hostname\s*=\s*', ', proxy_hostname=', content)
    
    # VARIABLE ASSIGNMENTS
    content = re.sub(r'^(\s*)hostname\s*=\s*', r'\1proxy_hostname = ', content, flags=re.MULTILINE)
    content = re.sub(r'(\s+)hostname\s*=\s*event\.get\(', r'\1proxy_hostname = event.get(', content)
    content = re.sub(r'(\s+)hostname\s*=\s*proxy\.get\(', r'\1proxy_hostname = proxy.get(', content)
    
    # EVENT DATA
    content = re.sub(r'"hostname":\s*hostname', '"proxy_hostname": proxy_hostname', content)
    content = re.sub(r'event\.get\(["\']hostname["\']\)', 'event.get("proxy_hostname")', content)
    content = re.sub(r'event\[["\']hostname["\']\]', 'event["proxy_hostname"]', content)
    
    # LOGGING
    content = re.sub(r'for {hostname}', 'for {proxy_hostname}', content)
    content = re.sub(r'Proxy {hostname}', 'Proxy {proxy_hostname}', content)
    content = re.sub(r'hostname={hostname}', 'proxy_hostname={proxy_hostname}', content)
    content = re.sub(r'hostname\s*=\s*hostname(?![_\w])', 'proxy_hostname=proxy_hostname', content)
    
    # DICTIONARY KEYS
    content = re.sub(r'\["hostname"\]', '["proxy_hostname"]', content)
    content = re.sub(r"'hostname':", "'proxy_hostname':", content)
    content = re.sub(r'"hostname":', '"proxy_hostname":', content)
    
    # LIST/SET OPERATIONS
    content = re.sub(r'hostnames\b', 'proxy_hostnames', content)
    content = re.sub(r'hostname_list\b', 'proxy_hostname_list', content)
    content = re.sub(r'skip_hostnames\b', 'skip_proxy_hostnames', content)
    
    # SPECIAL CASES - Don't change these
    # 1. Environment variables should stay as is
    content = re.sub(r'proxy_hostname_HEADER', 'HOSTNAME_HEADER', content)  # Revert if changed
    # 2. HTTP headers (Host header) should not change
    content = re.sub(r'proxy_hostname:\s*header', 'hostname: header', content)  # Revert if changed
    # 3. preserve_host_header should stay
    content = re.sub(r'preserve_proxy_hostname_header', 'preserve_host_header', content)  # Revert if changed
    
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    src_dir = Path('/home/atrawog/oauth-https-proxy/src')
    
    # Get all Python files
    python_files = list(src_dir.rglob('*.py'))
    
    print(f"Found {len(python_files)} Python files to migrate")
    
    modified_files = []
    for filepath in python_files:
        if '__pycache__' in str(filepath):
            continue
        
        try:
            if migrate_file(filepath):
                modified_files.append(filepath)
                print(f"✓ Migrated: {filepath.relative_to(src_dir.parent)}")
        except Exception as e:
            print(f"✗ Error migrating {filepath}: {e}")
    
    print(f"\n{'='*60}")
    print(f"Migration complete: {len(modified_files)} files modified")
    print(f"{'='*60}")
    
    if modified_files:
        print("\nModified files:")
        for f in sorted(modified_files):
            print(f"  - {f.relative_to(src_dir.parent)}")

if __name__ == "__main__":
    main()