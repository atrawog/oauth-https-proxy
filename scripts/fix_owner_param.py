#!/usr/bin/env python3
"""Fix owner_param references to use proxy_hostname."""

import re
from pathlib import Path

def fix_file(filepath):
    """Fix owner_param references in a file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix owner_param="hostname" to owner_param="proxy_hostname"
    content = re.sub(r'owner_param="hostname"', 'owner_param="proxy_hostname"', content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    # Fix all Python files in src directory
    src_dir = Path('/home/atrawog/oauth-https-proxy/src')
    
    fixed_files = []
    for filepath in src_dir.rglob('*.py'):
        if fix_file(filepath):
            fixed_files.append(filepath.relative_to(src_dir.parent))
            print(f"✓ Fixed: {filepath.relative_to(src_dir.parent)}")
    
    if fixed_files:
        print(f"\n✅ Fixed {len(fixed_files)} files")
    else:
        print("✅ No files needed fixing")

if __name__ == "__main__":
    main()