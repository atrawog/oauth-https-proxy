#!/usr/bin/env python3
"""Fix tokens/core.py to remove all sync fallbacks."""

import re

def fix_tokens_core():
    """Remove all sync fallbacks from tokens/core.py."""
    
    filepath = '/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/tokens/core.py'
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Pattern 1: Replace async_storage = ... if hasattr ... else None
        if 'async_storage = request.app.state.async_storage if hasattr' in line:
            new_lines.append('        async_storage = request.app.state.async_storage\n')
            i += 1
            continue
        
        # Pattern 2: Remove if async_storage: blocks with else clauses
        if re.match(r'\s+if async_storage:', line):
            indent_level = len(line) - len(line.lstrip())
            base_indent = ' ' * indent_level
            
            # Skip the if line
            i += 1
            
            # Collect the async branch
            async_lines = []
            while i < len(lines):
                if lines[i].strip() == '':
                    async_lines.append(lines[i])
                    i += 1
                elif len(lines[i]) - len(lines[i].lstrip()) > indent_level:
                    # This line is inside the if block
                    async_lines.append(lines[i])
                    i += 1
                else:
                    break
            
            # Check if we have an else clause
            if i < len(lines) and lines[i].strip() == 'else:':
                # Skip else line
                i += 1
                # Skip entire else block
                while i < len(lines):
                    if lines[i].strip() == '':
                        i += 1
                    elif len(lines[i]) - len(lines[i].lstrip()) > indent_level:
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
    
    # Write the fixed content
    with open(filepath, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed {filepath}")

if __name__ == '__main__':
    fix_tokens_core()