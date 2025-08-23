#!/usr/bin/env python3
"""Final cleanup to ensure proxy_hostname is used EVERYWHERE correctly."""

import re
from pathlib import Path

def fix_file(filepath):
    """Fix any remaining hostname issues."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix multiple proxy_ prefixes
    content = re.sub(r'proxy_proxy_proxy_hostname', 'proxy_hostname', content)
    content = re.sub(r'proxy_proxy_hostname', 'proxy_hostname', content)
    
    # Fix validators that still reference 'hostname'
    content = re.sub(r"@field_validator\('hostname'\)", "@field_validator('proxy_hostname')", content)
    content = re.sub(r'@field_validator\("hostname"\)', '@field_validator("proxy_hostname")', content)
    
    # Fix any remaining standalone hostname references in function signatures
    content = re.sub(r'def (\w+)\(hostname:', r'def \1(proxy_hostname:', content)
    content = re.sub(r'async def (\w+)\(hostname:', r'async def \1(proxy_hostname:', content)
    
    # Fix Redis keys that might still use hostname
    content = re.sub(r'f"(\w+):{hostname}', r'f"\1:{proxy_hostname}', content)
    
    # Fix any missed event.get('hostname')
    content = re.sub(r"event\.get\(['\"]hostname['\"]\)", 'event.get("proxy_hostname")', content)
    content = re.sub(r"event\[['\"]hostname['\"]\]", 'event["proxy_hostname"]', content)
    
    # Fix any dictionary key references
    content = re.sub(r"'hostname':", "'proxy_hostname':", content)
    content = re.sub(r'"hostname":', '"proxy_hostname":', content)
    
    # Fix model field names in ProxyTarget that got double-changed
    if 'class ProxyTarget' in content:
        # Make sure the model field is proxy_hostname
        content = re.sub(r'^\s+hostname:\s+str', '    proxy_hostname: str', content, flags=re.MULTILINE)
    
    # Fix any references in logging
    content = re.sub(r'{hostname}', '{proxy_hostname}', content)
    content = re.sub(r'hostname=hostname\b', 'proxy_hostname=proxy_hostname', content)
    
    # Special cases - preserve Host header references
    content = re.sub(r'proxy_hostname[Hh]eader', 'host_header', content)
    content = re.sub(r'preserve_proxy_hostname_header', 'preserve_host_header', content)
    
    # Fix HTTP headers that shouldn't change
    content = re.sub(r"headers\['proxy_hostname'\]", "headers['Host']", content)
    content = re.sub(r'headers\.get\("proxy_hostname"\)', 'headers.get("Host")', content)
    content = re.sub(r"headers\.get\('proxy_hostname'\)", "headers.get('Host')", content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def validate_file(filepath):
    """Check if file still has problematic hostname references."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    issues = []
    
    # Check for standalone hostname (not in comments, not Host header, not preserve_host_header)
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        # Skip comments and docstrings
        if '#' in line:
            line = line[:line.index('#')]
        if not line.strip():
            continue
            
        # Check for problematic patterns
        if re.search(r'\bhostname\b', line):
            # Allow specific exceptions
            if any(x in line for x in ['Host', 'host_header', 'preserve_host', 'X-Forwarded-Host', 'proxy_hostname']):
                continue
            issues.append((i, line.strip()))
    
    return issues

def main():
    src_dir = Path('/home/atrawog/oauth-https-proxy/src')
    python_files = list(src_dir.rglob('*.py'))
    
    print("Running final cleanup...")
    
    # Fix files
    fixed_files = []
    for filepath in python_files:
        if '__pycache__' in str(filepath):
            continue
        try:
            if fix_file(filepath):
                fixed_files.append(filepath)
                print(f"✓ Fixed: {filepath.relative_to(src_dir.parent)}")
        except Exception as e:
            print(f"✗ Error fixing {filepath}: {e}")
    
    print(f"\nFixed {len(fixed_files)} files")
    
    # Validate all files
    print("\nValidating all files...")
    files_with_issues = {}
    
    for filepath in python_files:
        if '__pycache__' in str(filepath):
            continue
        try:
            issues = validate_file(filepath)
            if issues:
                files_with_issues[filepath] = issues
        except Exception as e:
            print(f"✗ Error validating {filepath}: {e}")
    
    if files_with_issues:
        print(f"\n⚠️  Found {len(files_with_issues)} files with remaining hostname references:")
        for filepath, issues in files_with_issues.items():
            print(f"\n{filepath.relative_to(src_dir.parent)}:")
            for line_num, line in issues[:5]:  # Show first 5 issues
                print(f"  Line {line_num}: {line[:80]}")
            if len(issues) > 5:
                print(f"  ... and {len(issues) - 5} more")
    else:
        print("\n✅ ALL FILES VALIDATED - No hostname references found!")
        print("✅ Migration to proxy_hostname is COMPLETE!")

if __name__ == "__main__":
    main()