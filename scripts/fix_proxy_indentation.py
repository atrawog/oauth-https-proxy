#!/usr/bin/env python3
"""Fix indentation issues in the proxy modules."""

import re
from pathlib import Path


def fix_indentation(content):
    """Fix indentation issues in router files."""
    
    lines = content.split('\n')
    fixed_lines = []
    
    for line in lines:
        # Fix router decorator indentation (should have 4 spaces)
        if line.strip().startswith('@router.'):
            fixed_lines.append('    ' + line.strip())
        # Remove duplicate return statements
        elif line.strip() == 'return router' and fixed_lines and fixed_lines[-1].strip() == 'return router':
            continue  # Skip duplicate
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def process_file(file_path):
    """Process a single file to fix indentation."""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Fix indentation
    fixed = fix_indentation(content)
    
    # Remove trailing duplicate return router statements
    if fixed.endswith('\n    return router\n    \n    return router'):
        fixed = fixed.replace('\n    return router\n    \n    return router', '\n    \n    return router')
    
    with open(file_path, 'w') as f:
        f.write(fixed)
    
    print(f"✅ Fixed {file_path.name}")


def main():
    """Main function to fix all proxy module files."""
    
    module_dir = Path('src/api/routers/v1/proxies')
    
    # Process each module file
    for file_path in module_dir.glob('*.py'):
        if file_path.name != '__init__.py':
            process_file(file_path)
    
    print("\n✨ All proxy modules fixed!")


if __name__ == "__main__":
    main()