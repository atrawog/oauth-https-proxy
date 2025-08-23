#!/usr/bin/env python3
"""Fix remaining hostname references in proxy routers."""

import re
from pathlib import Path

def fix_file(filepath):
    """Fix hostname references in a file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix all get_proxy_target(hostname) calls
    content = re.sub(r'get_proxy_target\(hostname\)', 'get_proxy_target(proxy_hostname)', content)
    
    # Fix all store_proxy_target(hostname, ...) calls
    content = re.sub(r'store_proxy_target\(hostname,', 'store_proxy_target(proxy_hostname,', content)
    
    # Fix all delete_proxy_target(hostname) calls
    content = re.sub(r'delete_proxy_target\(hostname\)', 'delete_proxy_target(proxy_hostname)', content)
    
    # Fix all update_proxy_target(hostname, ...) calls
    content = re.sub(r'update_proxy_target\(hostname,', 'update_proxy_target(proxy_hostname,', content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    # Fix all files in proxy routers directory
    proxy_dir = Path('/home/atrawog/oauth-https-proxy/src/api/routers/proxy')
    
    fixed_files = []
    for filepath in proxy_dir.glob('*.py'):
        if fix_file(filepath):
            fixed_files.append(filepath.name)
            print(f"✓ Fixed: {filepath.name}")
    
    if fixed_files:
        print(f"\n✅ Fixed {len(fixed_files)} files")
    else:
        print("✅ No files needed fixing")

if __name__ == "__main__":
    main()