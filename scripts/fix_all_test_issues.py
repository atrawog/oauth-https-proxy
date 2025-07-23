#!/usr/bin/env python3
"""Fix all remaining test issues to ensure consistent approach."""

import os
import re
from pathlib import Path


def fix_syntax_errors(content):
    """Fix syntax errors from automated replacements."""
    # Fix malformed assertions with split()
    content = re.sub(
        r'assert response\.status_code == (\d+), (\d+), (\d+)\.split\(","\)\[0\]\.strip\(\)',
        r'assert response.status_code == \1',
        content
    )
    
    # Fix any remaining malformed multi-status assertions
    content = re.sub(
        r'assert response\.status_code in \[(\d+), (\d+), (\d+)\]\.split\(","\)\[0\]\.strip\(\)',
        r'assert response.status_code == \1',
        content
    )
    
    # Remove standalone "return token" lines
    content = re.sub(r'^\s*return token\s*$', '', content, flags=re.MULTILINE)
    
    return content


def fix_indentation_issues(content):
    """Fix class method indentation issues."""
    lines = content.split('\n')
    fixed_lines = []
    in_class = False
    class_indent = 0
    
    for i, line in enumerate(lines):
        # Detect class definition
        if line.strip().startswith('class ') and line.strip().endswith(':'):
            in_class = True
            class_indent = len(line) - len(line.lstrip())
            fixed_lines.append(line)
            continue
        
        # Fix method definitions that are not indented properly
        if in_class and re.match(r'^\s*def test_', line):
            # Ensure it's indented 4 spaces from class
            proper_indent = ' ' * (class_indent + 4)
            line = proper_indent + line.strip()
        
        # Fix fixture definitions
        if in_class and re.match(r'^\s*@pytest\.fixture', line):
            # Look ahead to fix the def line too
            proper_indent = ' ' * (class_indent + 4)
            line = proper_indent + line.strip()
            
        fixed_lines.append(line)
        
        # Reset when we leave the class
        if in_class and line and not line[0].isspace():
            in_class = False
    
    return '\n'.join(fixed_lines)


def remove_redis_imports(content):
    """Remove Redis imports from tests."""
    # Remove redis import lines
    content = re.sub(r'^import redis\s*$', '', content, flags=re.MULTILINE)
    content = re.sub(r'^from redis import .*$', '', content, flags=re.MULTILINE)
    
    # Clean up multiple blank lines
    content = re.sub(r'\n\n\n+', '\n\n', content)
    
    return content


def fix_vague_assertions(content):
    """Fix remaining vague assertions to be specific."""
    fixes = [
        # Fix "accept X or Y" patterns
        (r'assert response\.status_code in \[200, 201\]',
         'assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"'),
         
        (r'assert response\.status_code in \[200, 204\]',
         'assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"'),
         
        (r'assert response\.status_code in \[401, 403\]',
         'assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"'),
         
        (r'assert response\.status_code in \[400, 401\]',
         'assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"'),
         
        # Fix "might be X or Y" patterns with specific expectations
        (r'# Might already exist\s*\n\s*assert response\.status_code in \[200, 201, 409\]',
         '# Should create new or conflict if exists\n        assert response.status_code in [200, 409], f"Expected 200 or 409, got {response.status_code}: {response.text}"'),
         
        # Fix cleanup responses
        (r'assert cleanup_response\.status_code in \[200, 204\]',
         'assert cleanup_response.status_code in [200, 204], f"Cleanup failed: {cleanup_response.status_code}"'),
         
        # Fix delete responses
        (r'assert delete_response\.status_code in \[200, 204\]',
         'assert delete_response.status_code in [200, 204], f"Delete failed: {delete_response.status_code}"'),
    ]
    
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content)
    
    return content


def add_missing_auth_fixtures(content):
    """Ensure auth_token fixture is available in test classes."""
    # Check if conftest.py already provides auth_token
    if '@pytest.fixture' in content and 'def auth_token' in content:
        # Remove duplicate auth_token fixtures from test files
        content = re.sub(
            r'@pytest\.fixture\s*\n\s*def auth_token\(.*?\).*?\n.*?return.*?\n',
            '',
            content,
            flags=re.DOTALL
        )
    
    return content


def main():
    """Fix all test files."""
    test_dir = Path("/home/atrawog/AI/atrawog/mcp-http-proxy/tests")
    
    print("Fixing all test issues...")
    
    for test_file in test_dir.glob("test_*.py"):
        print(f"\nProcessing {test_file.name}...")
        
        try:
            content = test_file.read_text()
            original = content
            
            # Apply all fixes
            content = fix_syntax_errors(content)
            content = fix_indentation_issues(content)
            content = remove_redis_imports(content)
            content = fix_vague_assertions(content)
            content = add_missing_auth_fixtures(content)
            
            if content != original:
                test_file.write_text(content)
                print(f"  ✓ Fixed {test_file.name}")
            else:
                print(f"  - No changes needed for {test_file.name}")
                
        except Exception as e:
            print(f"  ✗ Error processing {test_file.name}: {e}")
    
    print("\nDone! All test files have been processed.")


if __name__ == "__main__":
    main()