#!/usr/bin/env python3
"""Fix assertion syntax errors from previous fixes."""

import re
from pathlib import Path


def fix_duplicate_messages(content):
    """Fix assertions with duplicate error messages."""
    # Fix patterns like: assert condition, "msg1", "msg2"
    content = re.sub(
        r'assert (.+?), (f"[^"]+"), (f"[^"]+")',
        r'assert \1, \2',
        content
    )
    
    # Fix patterns where the second message is simpler
    content = re.sub(
        r'assert (.+?), (f"[^"]+".+?\}[^"]*"), (f"Got .+?")',
        r'assert \1, \2',
        content
    )
    
    return content


def main():
    """Fix assertion syntax in all test files."""
    test_dir = Path("/home/atrawog/AI/atrawog/mcp-http-proxy/tests")
    
    print("Fixing assertion syntax errors...")
    
    for test_file in test_dir.glob("test_*.py"):
        try:
            content = test_file.read_text()
            original = content
            
            content = fix_duplicate_messages(content)
            
            if content != original:
                test_file.write_text(content)
                print(f"  ✓ Fixed {test_file.name}")
            else:
                print(f"  - No changes needed for {test_file.name}")
                
        except Exception as e:
            print(f"  ✗ Error processing {test_file.name}: {e}")
    
    print("\nDone!")


if __name__ == "__main__":
    main()