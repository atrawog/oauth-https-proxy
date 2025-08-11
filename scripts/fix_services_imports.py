#!/usr/bin/env python3
"""Fix relative imports in services routers to use absolute imports."""

import re
from pathlib import Path

def fix_service_imports(filepath: Path):
    """Fix imports in a services router file."""
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix docker imports
    content = re.sub(
        r'from \.\.\.\.docker\.',
        'from src.docker.',
        content
    )
    
    # Fix proxy imports
    content = re.sub(
        r'from \.\.\.\.proxy\.',
        'from src.proxy.',
        content
    )
    
    # Fix shared imports
    content = re.sub(
        r'from \.\.\.\.shared\.',
        'from src.shared.',
        content
    )
    
    # Fix storage imports
    content = re.sub(
        r'from \.\.\.\.storage',
        'from src.storage',
        content
    )
    
    # Fix certmanager imports
    content = re.sub(
        r'from \.\.\.\.certmanager',
        'from src.certmanager',
        content
    )
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Fixed {filepath.name}")
        return True
    return False

def main():
    """Fix all imports in services routers."""
    
    base_dir = Path('/home/atrawog/AI/atrawog/mcp-http-proxy')
    services_dir = base_dir / 'src/api/routers/v1/services'
    
    fixed_count = 0
    for filepath in services_dir.glob('*.py'):
        if fix_service_imports(filepath):
            fixed_count += 1
    
    print(f"\n✓ Fixed {fixed_count} service files")

if __name__ == '__main__':
    main()