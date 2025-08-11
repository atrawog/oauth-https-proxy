#!/usr/bin/env python3
"""Fix auth imports to use absolute imports instead of relative imports."""

import os
import re
from pathlib import Path

def fix_auth_imports(filepath: Path):
    """Fix auth imports in a single file."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Replace relative auth imports with absolute imports
    # Pattern: from ...auth import -> from src.api.auth import
    content = re.sub(
        r'from \.\.\.auth import',
        'from src.api.auth import',
        content
    )
    
    # Also handle from ..auth for files one level up
    content = re.sub(
        r'from \.\.auth import',
        'from src.api.auth import',
        content
    )
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Fixed {filepath.name}")
        return True
    return False

def main():
    """Fix all auth imports in v1 routers."""
    
    base_dir = Path('/home/atrawog/AI/atrawog/mcp-http-proxy')
    
    # Find all Python files in v1 routers
    v1_dir = base_dir / 'src/api/routers/v1'
    
    fixed_count = 0
    for filepath in v1_dir.rglob('*.py'):
        if fix_auth_imports(filepath):
            fixed_count += 1
    
    print(f"\n✓ Fixed {fixed_count} files")

if __name__ == '__main__':
    main()