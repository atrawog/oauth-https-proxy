#!/usr/bin/env python3
"""Fix certificates router to remove sync fallbacks."""

import re
from pathlib import Path

def fix_async_fallbacks(content: str) -> str:
    """Remove all async storage fallbacks from a file."""
    
    # Pattern 1: Replace async_storage = ... if hasattr ... else None
    content = re.sub(
        r'async_storage = request\.app\.state\.async_storage if hasattr\(request\.app\.state, [\'"]async_storage[\'"]\) else None',
        'async_storage = request.app.state.async_storage',
        content
    )
    
    # Pattern 2: Replace if async_storage: blocks with just the async branch
    lines = content.split('\n')
    new_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check for if async_storage: pattern
        if re.search(r'\s+if async_storage:', line):
            indent_level = len(line) - len(line.lstrip())
            base_indent = ' ' * indent_level
            
            # Skip the if line
            i += 1
            
            # Collect the async branch
            async_lines = []
            while i < len(lines):
                current_line = lines[i]
                if current_line.strip() == '':
                    async_lines.append(current_line)
                    i += 1
                elif len(current_line) - len(current_line.lstrip()) > indent_level:
                    async_lines.append(current_line)
                    i += 1
                else:
                    break
            
            # Check if we have an else clause
            if i < len(lines) and lines[i].strip() == 'else:':
                # Skip else line
                i += 1
                # Skip entire else block
                while i < len(lines):
                    current_line = lines[i]
                    if current_line.strip() == '':
                        i += 1
                    elif len(current_line) - len(current_line.lstrip()) > indent_level:
                        i += 1
                    else:
                        break
                
                # Add dedented async lines
                for async_line in async_lines:
                    if async_line.strip():
                        # Remove one level of indentation
                        if async_line.startswith(base_indent + '    '):
                            new_lines.append(async_line[4:])
                        else:
                            new_lines.append(async_line)
                    else:
                        new_lines.append(async_line)
            else:
                # No else clause, keep the if statement
                new_lines.append(line)
                new_lines.extend(async_lines)
        else:
            new_lines.append(line)
            i += 1
    
    return '\n'.join(new_lines)

def main():
    """Process the certificates router file."""
    
    filepath = Path('/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/certificates.py')
    
    print(f"Processing {filepath.name}")
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    content = fix_async_fallbacks(content)
    
    # Also update references to cert_manager.get_certificate to use async_storage
    content = re.sub(
        r'cert_manager\.get_certificate\(',
        'await async_storage.get_certificate(',
        content
    )
    
    # Update references to storage.store_certificate
    content = re.sub(
        r'storage\.store_certificate\(',
        'await async_storage.store_certificate(',
        content
    )
    
    # Update references to storage.list_certificates
    content = re.sub(
        r'storage\.list_certificates\(',
        'await async_storage.list_certificates(',
        content
    )
    
    # Update references to storage.delete_certificate
    content = re.sub(
        r'storage\.delete_certificate\(',
        'await async_storage.delete_certificate(',
        content
    )
    
    # Update references to storage.get_api_token
    content = re.sub(
        r'storage\.get_api_token\(',
        'await async_storage.get_api_token(',
        content
    )
    
    # Update references to storage.redis_client
    content = re.sub(
        r'storage\.redis_client\.',
        'async_storage.redis_client.',
        content
    )
    
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  ✓ Fixed {filepath.name}")
    else:
        print(f"  - No changes needed for {filepath.name}")

if __name__ == '__main__':
    main()