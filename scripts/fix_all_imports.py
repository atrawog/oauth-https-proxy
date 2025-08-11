#!/usr/bin/env python3
"""Fix all relative imports in v1 routers to use absolute imports."""

import re
from pathlib import Path

def fix_imports(filepath: Path):
    """Fix imports in a router file."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix imports that go up 4 levels (from v1/subdirectory/)
    patterns = [
        (r'from \.\.\.\.docker\.', 'from src.docker.'),
        (r'from \.\.\.\.proxy\.', 'from src.proxy.'),
        (r'from \.\.\.\.shared\.', 'from src.shared.'),
        (r'from \.\.\.\.storage', 'from src.storage'),
        (r'from \.\.\.\.certmanager', 'from src.certmanager'),
        (r'from \.\.\.\.resources', 'from src.resources'),
        (r'from \.\.\.\.oauth', 'from src.oauth'),
    ]
    
    # Fix imports that go up 3 levels (from v1/)
    patterns.extend([
        (r'from \.\.\.docker\.', 'from src.docker.'),
        (r'from \.\.\.proxy\.', 'from src.proxy.'),
        (r'from \.\.\.shared\.', 'from src.shared.'),
        (r'from \.\.\.storage', 'from src.storage'),
        (r'from \.\.\.certmanager', 'from src.certmanager'),
        (r'from \.\.\.resources', 'from src.resources'),
        (r'from \.\.\.oauth', 'from src.oauth'),
    ])
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Fixed {filepath.relative_to(Path('/home/atrawog/AI/atrawog/mcp-http-proxy'))}")
        return True
    return False

def main():
    """Fix all imports in v1 routers."""
    
    base_dir = Path('/home/atrawog/AI/atrawog/mcp-http-proxy')
    v1_dir = base_dir / 'src/api/routers/v1'
    
    fixed_count = 0
    
    # Process all Python files in v1 directory and subdirectories
    for filepath in v1_dir.rglob('*.py'):
        if fix_imports(filepath):
            fixed_count += 1
    
    print(f"\n✓ Fixed {fixed_count} files total")

if __name__ == '__main__':
    main()