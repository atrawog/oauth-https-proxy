#!/usr/bin/env python3
"""Fix ALL test issues - remove pytest.skip, fix vague assertions, remove Redis access."""

import os
import re
import glob

def fix_test_file(filepath):
    """Fix all issues in a test file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original = content
    
    # 1. Remove ALL pytest.skip calls - these hide real failures!
    # Replace with assertions that FAIL HARD
    patterns = [
        # Skip with message
        (r'pytest\.skip\("([^"]+)"\)', r'assert False, "FAILURE: \1"'),
        (r"pytest\.skip\('([^']+)'\)", r'assert False, "FAILURE: \1"'),
        (r'pytest\.skip\(f"([^"]+)"\)', r'assert False, f"FAILURE: \1"'),
        (r"pytest\.skip\(f'([^']+)'\)", r'assert False, f"FAILURE: \1"'),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    
    # 2. Fix vague status_code assertions - be SPECIFIC!
    # Common patterns to fix:
    vague_patterns = [
        # [401, 403] -> 401 (always unauthorized, not forbidden)
        (r'assert response\.status_code in \[401, 403\]', 
         'assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"'),
        
        # [200, 201] for creation -> 200 (or 201 for explicit creation endpoints)
        (r'assert response\.status_code in \[200, 201\]',
         'assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"'),
        
        # [200, 204] for deletion -> 204
        (r'assert response\.status_code in \[200, 204\]',
         'assert response.status_code == 204, f"Expected 204 No Content, got {response.status_code}"'),
         
        # [400, 409] for conflicts -> 409
        (r'assert response\.status_code in \[400, 409\]',
         'assert response.status_code == 409, f"Expected 409 Conflict, got {response.status_code}: {response.text}"'),
         
        # [400, 422] for validation -> 422
        (r'assert response\.status_code in \[400, 422\]',
         'assert response.status_code == 422, f"Expected 422 Unprocessable Entity, got {response.status_code}: {response.text}"'),
         
        # Generic cleanup for any remaining
        (r'assert (\w+)\.status_code in \[([^\]]+)\]',
         r'assert \1.status_code == \2.split(",")[0].strip(), f"Got {\1.status_code}: {\1.text}"'),
    ]
    
    for pattern, replacement in vague_patterns:
        content = re.sub(pattern, replacement, content)
    
    # 3. Remove direct Redis access - tests should ONLY use API!
    if 'redis_client.' in content and 'conftest.py' not in filepath:
        # Mark these tests as needing rewrite
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            if 'redis_client.' in line and not line.strip().startswith('#'):
                new_lines.append(f'        # FIXME: Direct Redis access! {line.strip()}')
                new_lines.append('        assert False, "Test uses direct Redis access - rewrite to use API only!"')
            else:
                new_lines.append(line)
        content = '\n'.join(new_lines)
    
    # 4. Fix fixture cleanup that uses except: pass
    content = re.sub(
        r'except.*:\s*pass\s*#.*cleanup',
        'except Exception as e:\n            assert False, f"Cleanup failed: {e}"',
        content,
        flags=re.IGNORECASE
    )
    
    # 5. Fix if statements that skip on status codes
    content = re.sub(
        r'if response\.status_code in \[(\d+), (\d+)\]:\s*yield',
        r'assert response.status_code == \1, f"Expected \1, got {response.status_code}: {response.text}"\n        yield',
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
    print("\nRemaining manual fixes needed:")
    print("1. Remove duplicate auth_token fixtures - use the one from conftest.py")
    print("2. Rewrite any tests that directly access Redis to use API instead")
    print("3. Update cleanup assertions to be more specific (200 vs 204)")

if __name__ == "__main__":
    main()