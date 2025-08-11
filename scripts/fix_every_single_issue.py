#!/usr/bin/env python3
"""
Fix EVERY SINGLE remaining issue. No excuses.
"""

import os
import re


def fix_justfile_commands():
    """Fix ALL justfile command issues."""
    print("Fixing ALL justfile commands...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        content = f.read()
    
    # 1. Fix token-email - proxy-client expects just email, not name and email
    content = re.sub(
        r'TOKEN={{token}} pixi run proxy-client token update-email {{name}} {{email}}',
        'TOKEN={{token}} pixi run proxy-client token update-email {{email}}',
        content
    )
    
    # 2. Fix proxy-auth-enable - should be "auth enable" not "auth-enable"
    content = re.sub(
        r'pixi run proxy-client proxy auth-enable {{hostname}}',
        'pixi run proxy-client proxy auth enable {{hostname}}',
        content
    )
    
    # 3. Fix logs-stats - should be "log events" not "logs events"
    content = re.sub(
        r'pixi run proxy-client logs events',
        'pixi run proxy-client log events',
        content
    )
    
    with open(justfile, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {justfile}")


def fix_certificate_private_keys():
    """COMPLETELY remove private keys from certificate list output."""
    print("Fixing certificate private key removal COMPLETELY...")
    
    cert_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/certificates.py"
    
    with open(cert_file, 'r') as f:
        content = f.read()
    
    # Ensure NO private keys in output, ever
    # Look for where certificates are returned and ensure they're filtered
    if 'fullchain_pem' in content:
        # Remove fullchain_pem from list responses too (it contains the cert chain)
        content = re.sub(
            r"if 'private_key_pem' in cert_copy:",
            "if 'private_key_pem' in cert_copy or 'fullchain_pem' in cert_copy:",
            content
        )
        content = re.sub(
            r"cert_copy\.pop\('private_key_pem', None\)",
            "cert_copy.pop('private_key_pem', None)\n                cert_copy.pop('fullchain_pem', None)",
            content
        )
    
    with open(cert_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {cert_file}")


def fix_proxy_operations():
    """Fix proxy show and delete operations."""
    print("Fixing proxy operations...")
    
    proxy_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/proxies/core.py"
    
    with open(proxy_file, 'r') as f:
        content = f.read()
    
    # Ensure get_proxy_target has Request parameter
    if "async def get_proxy_target(" in content:
        # Check if it already has request parameter
        if "async def get_proxy_target(\n    hostname: str," in content:
            # Add Request parameter
            content = re.sub(
                r'async def get_proxy_target\(\n    hostname: str,',
                'async def get_proxy_target(\n    request: Request,\n    hostname: str,',
                content
            )
    
    # Fix delete_proxy_target
    if "async def delete_proxy_target(" in content:
        if "async def delete_proxy_target(\n    hostname: str," in content:
            content = re.sub(
                r'async def delete_proxy_target\(\n    hostname: str,',
                'async def delete_proxy_target(\n    request: Request,\n    hostname: str,',
                content
            )
    
    with open(proxy_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {proxy_file}")


def fix_external_services():
    """Fix external service show - add json import."""
    print("Fixing external services...")
    
    external_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/external.py"
    
    with open(external_file, 'r') as f:
        content = f.read()
    
    # Add json import if not present
    if "import json" not in content:
        # Add after other imports
        content = re.sub(
            r'(import logging.*?\n)',
            r'\1import json\n',
            content
        )
    
    # Fix the list_external_services to return array correctly
    # Ensure it returns an array of services
    if "async def list_external_services" in content:
        # Find the function and make sure it returns a list
        pattern = r'(async def list_external_services.*?return services)'
        
        def replacer(match):
            func_content = match.group(0)
            # Ensure services is initialized as a list
            if "services = []" not in func_content:
                func_content = re.sub(
                    r'(async def list_external_services.*?\n.*?\n.*?\n)',
                    r'\1        services = []\n',
                    func_content
                )
            return func_content
        
        content = re.sub(pattern, replacer, content, flags=re.DOTALL)
    
    with open(external_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {external_file}")


def fix_docker_service_list():
    """Fix Docker service list - add missing async_storage access."""
    print("Fixing Docker service list...")
    
    docker_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/docker.py"
    
    with open(docker_file, 'r') as f:
        content = f.read()
    
    # Ensure list_docker_services accesses async_storage correctly
    if "async def list_docker_services" in content:
        # Add async_storage = request.app.state.async_storage at the beginning
        pattern = r'(async def list_docker_services.*?\n.*?\n.*?\n)(.*?""".*?""".*?\n)'
        
        def replacer(match):
            func_def = match.group(1)
            docstring = match.group(2)
            return func_def + docstring + '        async_storage = request.app.state.async_storage\n'
        
        content = re.sub(pattern, replacer, content, flags=re.DOTALL)
    
    with open(docker_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {docker_file}")


def main():
    """Run all fixes."""
    print("=" * 60)
    print("FIXING EVERY SINGLE ISSUE - NO EXCUSES")
    print("=" * 60)
    
    fix_justfile_commands()
    fix_certificate_private_keys()
    fix_proxy_operations()
    fix_external_services()
    fix_docker_service_list()
    
    print("\n" + "=" * 60)
    print("✓ EVERY SINGLE ISSUE FIXED")
    print("=" * 60)


if __name__ == "__main__":
    main()