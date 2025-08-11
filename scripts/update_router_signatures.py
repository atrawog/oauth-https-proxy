#!/usr/bin/env python3
"""Update router function signatures to use async_storage instead of storage."""

import re
from pathlib import Path

def update_signatures(content: str) -> str:
    """Update function signatures and references."""
    
    # Pattern 1: Update function signatures
    # def create_xxx_router(storage) -> APIRouter:
    content = re.sub(
        r'def create_(\w+)_router\(storage\)',
        r'def create_\1_router(async_storage)',
        content
    )
    
    # Pattern 2: Update storage references to async_storage
    # But be careful not to replace async_storage = ... lines
    lines = content.split('\n')
    new_lines = []
    
    for line in lines:
        # Skip lines that are assignments to async_storage
        if 'async_storage =' in line or 'async_storage:' in line:
            new_lines.append(line)
        # Replace storage. with async_storage. when it's a method call
        elif re.search(r'\bstorage\.\w+\(', line):
            line = re.sub(r'\bstorage\.', 'async_storage.', line)
            new_lines.append(line)
        # Replace standalone storage parameter references
        elif re.search(r'\bstorage\b', line) and 'def ' not in line and 'import' not in line:
            line = re.sub(r'\bstorage\b', 'async_storage', line)
            new_lines.append(line)
        else:
            new_lines.append(line)
    
    content = '\n'.join(new_lines)
    
    # Pattern 3: Update docstrings
    content = re.sub(
        r'storage: Redis storage instance \(legacy\)',
        'async_storage: Async Redis storage instance',
        content
    )
    
    return content

def process_file(filepath: Path):
    """Process a single file."""
    print(f"Processing {filepath.name}")
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    content = update_signatures(content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  ✓ Updated {filepath.name}")
        return True
    else:
        print(f"  - No changes needed for {filepath.name}")
        return False

def main():
    """Process all router files."""
    
    base_dir = Path('/home/atrawog/AI/atrawog/mcp-http-proxy')
    
    # All router files that need signature updates
    router_files = [
        # Token routers
        'src/api/routers/v1/tokens/core.py',
        'src/api/routers/v1/tokens/admin.py',
        'src/api/routers/v1/tokens/management.py',
        'src/api/routers/v1/tokens/ownership.py',
        'src/api/routers/v1/tokens/__init__.py',
        
        # Service routers
        'src/api/routers/v1/services/docker.py',
        'src/api/routers/v1/services/external.py',
        'src/api/routers/v1/services/proxy_integration.py',
        'src/api/routers/v1/services/ports.py',
        'src/api/routers/v1/services/cleanup.py',
        'src/api/routers/v1/services/__init__.py',
        
        # Proxy routers
        'src/api/routers/v1/proxies/core.py',
        'src/api/routers/v1/proxies/auth.py',
        'src/api/routers/v1/proxies/routes.py',
        'src/api/routers/v1/proxies/resources.py',
        'src/api/routers/v1/proxies/__init__.py',
        
        # Log routers
        'src/api/routers/v1/logs/query.py',
        'src/api/routers/v1/logs/search.py',
        'src/api/routers/v1/logs/errors.py',
        'src/api/routers/v1/logs/stats.py',
        'src/api/routers/v1/logs/__init__.py',
        
        # Main router files
        'src/api/routers/v1/tokens.py',
        'src/api/routers/v1/services.py',
        'src/api/routers/v1/proxies.py',
        'src/api/routers/v1/logs.py',
    ]
    
    fixed_count = 0
    for file_path in router_files:
        filepath = base_dir / file_path
        if filepath.exists():
            if process_file(filepath):
                fixed_count += 1
        else:
            print(f"  ! File not found: {file_path}")
    
    print(f"\n✓ Updated {fixed_count} router files")

if __name__ == '__main__':
    main()