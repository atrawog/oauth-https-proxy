#!/usr/bin/env python3
"""Fix all hard-coded values in scripts to comply with CLAUDE.md."""

import os
import re
import glob

def fix_file(filepath):
    """Fix hard-coded values in a single file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix os.getenv with defaults
    patterns = [
        (r"os\.getenv\('API_URL', 'http://localhost:80'\)", 
         "os.getenv('API_URL')"),
        (r"os\.getenv\('REDIS_URL', 'redis://localhost:6379/0'\)", 
         "os.getenv('REDIS_URL')"),
        (r"os\.getenv\('HTTP_PORT', '80'\)", 
         "os.getenv('HTTP_PORT')"),
        (r"os\.getenv\('HTTPS_PORT', '443'\)", 
         "os.getenv('HTTPS_PORT')"),
        (r"os\.getenv\('LOG_LEVEL', 'info'\)\.lower\(\)", 
         "os.getenv('LOG_LEVEL').lower()"),
        (r"os\.getenv\(([^,]+), [^)]+\)", 
         r"os.getenv(\1)"),  # Generic pattern for any os.getenv with default
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    
    # Add check for required env vars after os.getenv calls
    if "os.getenv('API_URL')" in content and "if not api_url:" not in content:
        # Find where api_url is assigned
        match = re.search(r"(\s*)api_url = os\.getenv\('API_URL'\)", content)
        if match:
            indent = match.group(1)
            check = f"\n{indent}if not api_url:\n{indent}    print(\"Error: API_URL must be set in .env\")\n{indent}    return False"
            content = re.sub(
                r"(api_url = os\.getenv\('API_URL'\))",
                r"\1" + check,
                content
            )
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed: {filepath}")
        return True
    return False

def main():
    """Fix all Python scripts."""
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    fixed_count = 0
    
    for filepath in glob.glob(os.path.join(scripts_dir, "*.py")):
        if os.path.basename(filepath) != "fix_hardcoded_values.py":
            if fix_file(filepath):
                fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    main()