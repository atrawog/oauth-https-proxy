#!/usr/bin/env python3
"""Script to update all auth imports and dependencies to use the new flexible auth system."""

import os
import re
from pathlib import Path


def update_file(file_path):
    """Update a single file to use the new auth system."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Update imports
    content = re.sub(
        r'from src\.api\.auth import .*',
        'from src.auth import AuthDep, AuthResult',
        content
    )
    content = re.sub(
        r'from \.\.auth import .*',
        'from src.auth import AuthDep, AuthResult',
        content
    )
    content = re.sub(
        r'from \.\.\.auth import .*',
        'from src.auth import AuthDep, AuthResult',
        content
    )
    
    # Update require_admin dependencies
    content = re.sub(
        r'_: dict = Depends\(require_admin\)',
        'auth: AuthResult = Depends(AuthDep(admin=True))',
        content
    )
    
    # Update require_auth dependencies
    content = re.sub(
        r'token_info: dict = Depends\(require_auth\)',
        'auth: AuthResult = Depends(AuthDep())',
        content
    )
    
    # Update require_auth_header dependencies
    content = re.sub(
        r'token_hash: str = Depends\(require_auth_header\)',
        'auth: AuthResult = Depends(AuthDep())',
        content
    )
    
    # Update get_current_token_info dependencies
    content = re.sub(
        r'token_info: Tuple\[.*?\] = Depends\(get_current_token_info\)',
        'auth: AuthResult = Depends(AuthDep())',
        content
    )
    
    # Update get_token_info_from_header dependencies
    content = re.sub(
        r'token_info: .*? = Depends\(get_token_info_from_header\)',
        'auth: AuthResult = Depends(AuthDep())',
        content
    )
    
    # Update get_optional_token_info dependencies
    content = re.sub(
        r'token_info: .*? = Depends\(get_optional_token_info\)',
        'auth: Optional[AuthResult] = Depends(AuthDep())',
        content
    )
    
    # Update require_proxy_owner dependencies
    content = re.sub(
        r'_: None = Depends\(require_proxy_owner\)',
        'auth: AuthResult = Depends(AuthDep(check_owner=True))',
        content
    )
    
    # Update require_route_owner dependencies
    content = re.sub(
        r'_: None = Depends\(require_route_owner\)',
        'auth: AuthResult = Depends(AuthDep(check_owner=True))',
        content
    )
    
    # Update token_info['hash'] references
    content = re.sub(r"token_info\['hash'\]", 'auth.token_hash', content)
    
    # Update token_info['name'] references
    content = re.sub(r"token_info\['name'\]", 'auth.principal', content)
    
    # Update token_info.get('name') references
    content = re.sub(r"token_info\.get\('name'\)", 'auth.principal', content)
    
    # Update token_info.get('cert_email') references
    content = re.sub(r"token_info\.get\('cert_email'\)", "auth.metadata.get('cert_email')", content)
    
    # Update ADMIN checks
    content = re.sub(
        r"token_info\.get\('name'\) == 'ADMIN'",
        "auth.metadata.get('is_admin', False)",
        content
    )
    content = re.sub(
        r"token_info\.get\('name'\) != 'ADMIN'",
        "not auth.metadata.get('is_admin', False)",
        content
    )
    content = re.sub(
        r"token_name and token_name\.upper\(\) == \"ADMIN\"",
        "auth.metadata.get('is_admin', False)",
        content
    )
    
    # Update token_hash references (standalone)
    content = re.sub(r'\btoken_hash\b(?!:)', 'auth.token_hash', content)
    
    # Update token_name references (standalone)
    content = re.sub(r'\btoken_name\b(?!:)', 'auth.principal', content)
    
    # Add Optional import if needed
    if 'Optional[AuthResult]' in content and 'from typing import' in content:
        # Check if Optional is already imported
        if 'Optional' not in re.search(r'from typing import .*', content).group(0):
            content = re.sub(
                r'(from typing import )(.*)',
                r'\1Optional, \2',
                content
            )
    
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"Updated: {file_path}")
        return True
    return False


def main():
    """Update all router files."""
    # List of directories to update
    directories = [
        'src/api/routers/v1',
    ]
    
    updated_files = []
    
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            print(f"Directory not found: {directory}")
            continue
        
        # Find all Python files
        for py_file in dir_path.rglob('*.py'):
            if update_file(py_file):
                updated_files.append(py_file)
    
    print(f"\nUpdated {len(updated_files)} files")
    
    # Also update specific files that import auth
    additional_files = [
        'src/api/auth_config.py',
        'src/api/unified_auth.py',
        'src/api/auth_middleware.py'
    ]
    
    for file_path in additional_files:
        if Path(file_path).exists():
            if update_file(file_path):
                print(f"Updated: {file_path}")


if __name__ == '__main__':
    main()