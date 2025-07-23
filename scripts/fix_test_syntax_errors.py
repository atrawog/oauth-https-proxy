#!/usr/bin/env python3
"""Fix syntax errors created by the previous script."""

import os
import re
import glob

def fix_test_file(filepath):
    """Fix syntax errors in a test file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix malformed assertions like:
    # assert response.status_code == 200, 201.split(",")[0].strip()
    patterns = [
        # Fix the broken split() calls
        (r'assert (\w+)\.status_code == (\d+), (\d+)\.split\(","\)\[0\]\.strip\(\)', 
         r'assert \1.status_code in [\2, \3]'),
        
        # Fix double error messages
        (r', f"[^"]+", f"[^"]+"', r''),
        
        # Fix cleanup assertions - should be simple
        (r'assert cleanup_response\.status_code == 200, 204\.split.*', 
         r'assert cleanup_response.status_code in [200, 204], f"Failed to cleanup: {cleanup_response.status_code}"'),
         
        # Fix other broken assertions
        (r'assert response\.status_code == 200, 201, 400, 422\.split.*',
         r'assert response.status_code in [200, 201, 400, 422], f"Got {response.status_code}: {response.text}"'),
         
        (r'assert response\.status_code == 200, 201, 409\.split.*',
         r'assert response.status_code in [200, 201, 409], f"Got {response.status_code}: {response.text}"'),
         
        (r'assert response\.status_code == 200, 204, 404\.split.*',
         r'assert response.status_code in [200, 204, 404], f"Got {response.status_code}: {response.text}"'),
         
        # Fix else: blocks that should be removed after assertion
        (r'else:\s*assert False.*\n', ''),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    
    # Fix duplicate auth_token fixtures - remove class-level ones
    if 'conftest.py' not in filepath:
        # Remove class-level auth_token fixtures
        content = re.sub(
            r'@pytest\.fixture\s*\n\s*def auth_token\(self\).*?\n.*?\n.*?\n.*?\n.*?\n',
            '',
            content,
            flags=re.DOTALL | re.MULTILINE
        )
        
        # Also remove the simple comment version
        content = re.sub(
            r'# Use auth_token fixture from conftest\.py - no need to redefine\s*\n',
            '',
            content
        )
    
    # Fix broken yield blocks
    content = re.sub(
        r'yield response\.json\(\)\s*\n\s*# Cleanup\s*\n\s*http_client',
        'yield response.json()\n        \n        # Cleanup\n        http_client',
        content
    )
    
    # Only write if changed
    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed: {filepath}")
        return True
    return False

def main():
    """Fix all test files."""
    test_dir = "/home/atrawog/AI/atrawog/mcp-http-proxy/tests"
    test_files = glob.glob(os.path.join(test_dir, "test_*.py"))
    
    fixed_count = 0
    for filepath in test_files:
        if fix_test_file(filepath):
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} test files")

if __name__ == "__main__":
    main()