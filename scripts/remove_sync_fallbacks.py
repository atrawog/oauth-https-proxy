#!/usr/bin/env python3
"""Remove sync storage fallbacks and make everything async-only."""

import os
import re
from pathlib import Path

def remove_sync_fallbacks(content: str) -> str:
    """Remove sync storage fallbacks from Python code."""
    
    # Pattern 1: Get async storage and remove conditional checks
    # Before: async_storage = request.app.state.async_storage if hasattr(request.app.state, 'async_storage') else None
    # After: async_storage = request.app.state.async_storage
    content = re.sub(
        r'async_storage = request\.app\.state\.async_storage if hasattr\(request\.app\.state, [\'"]async_storage[\'"]\) else None',
        'async_storage = request.app.state.async_storage',
        content
    )
    
    # Pattern 2: Remove if async_storage else storage patterns
    # This is more complex - need to handle multiline
    lines = content.split('\n')
    new_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check for if async_storage: pattern
        if 'if async_storage:' in line or 'if self.async_storage:' in line:
            # Look for the else clause
            indent = len(line) - len(line.lstrip())
            
            # Collect the async branch
            async_lines = []
            i += 1
            while i < len(lines) and (lines[i].strip() == '' or len(lines[i]) - len(lines[i].lstrip()) > indent):
                async_lines.append(lines[i])
                i += 1
            
            # Check if next line is else:
            if i < len(lines) and lines[i].strip().startswith('else:'):
                # Skip the else branch
                i += 1
                while i < len(lines) and (lines[i].strip() == '' or len(lines[i]) - len(lines[i].lstrip()) > indent):
                    i += 1
                
                # Add only the async lines (dedented)
                for async_line in async_lines:
                    if async_line.strip():
                        # Dedent by one level (usually 4 spaces)
                        if async_line.startswith('    ' * 2):
                            new_lines.append(async_line[4:])
                        else:
                            new_lines.append(async_line)
                    else:
                        new_lines.append(async_line)
            else:
                # No else clause, keep the if statement but simplify
                new_lines.append(line)
                new_lines.extend(async_lines)
        else:
            new_lines.append(line)
            i += 1
    
    content = '\n'.join(new_lines)
    
    # Pattern 3: Replace storage parameter with async_storage in function calls
    # This needs careful handling to not break APIs
    
    # Pattern 4: Update function signatures that take storage parameter
    # Change storage to async_storage in router creation functions
    content = re.sub(
        r'def create_\w+_router\(storage\)',
        'def create_\\g<0>_router(async_storage)',
        content
    )
    
    return content

def process_file(filepath: Path):
    """Process a single Python file."""
    print(f"Processing {filepath}")
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    content = remove_sync_fallbacks(content)
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  ✓ Updated {filepath}")
    else:
        print(f"  - No changes needed for {filepath}")

def main():
    """Process all Python files with sync fallbacks."""
    
    # Files identified with sync fallbacks
    files = [
        'src/api/routers/v1/tokens/management.py',
        'src/api/routers/v1/tokens/admin.py',
        'src/api/routers/v1/tokens/ownership.py',
        'src/api/routers/v1/tokens/core.py',
        'src/api/routers/v1/services/proxy_integration.py',
        'src/api/routers/v1/services/external.py',
        'src/api/routers/v1/services/docker.py',
        'src/api/routers/v1/proxies/auth.py',
        'src/api/routers/v1/proxies/routes.py',
        'src/api/routers/v1/proxies/resources.py',
        'src/api/routers/v1/proxies/core.py',
        'src/api/routers/v1/certificates.py',
    ]
    
    base_dir = Path('/home/atrawog/AI/atrawog/mcp-http-proxy')
    
    for file in files:
        filepath = base_dir / file
        if filepath.exists():
            process_file(filepath)
        else:
            print(f"File not found: {filepath}")

if __name__ == '__main__':
    main()