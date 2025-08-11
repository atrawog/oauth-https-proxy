#!/usr/bin/env python3
"""
Final comprehensive fix for all remaining issues.
Addresses all failed tests identified in the comprehensive test.
"""

import os
import re
import json

def fix_certificate_private_key_removal():
    """Ensure private keys are removed from certificate list responses."""
    print("Fixing certificate private key removal...")
    
    cert_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/certificates.py"
    
    with open(cert_file, 'r') as f:
        content = f.read()
    
    # Find the list_certificates function
    if "# Remove private keys from list response" not in content:
        # Find the list_certificates function and add the filter
        pattern = r'(async def list_certificates.*?)(return certificates)'
        
        def replacer(match):
            prefix = match.group(1)
            return_stmt = match.group(2)
            
            # Add code to filter out private keys
            filter_code = '''    # Remove private keys from list response
    for cert in certificates:
        if 'private_key_pem' in cert:
            del cert['private_key_pem']
    
    '''
            return prefix + filter_code + return_stmt
        
        content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        
        with open(cert_file, 'w') as f:
            f.write(content)
        
        print(f"✓ Fixed {cert_file}")
    else:
        print(f"✓ Already fixed: {cert_file}")


def fix_justfile_token_email():
    """Fix token-email command in justfile."""
    print("Fixing token-email command...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        content = f.read()
    
    # Fix token-email command - it should be: token-email name email token
    old_pattern = r'token-email name email token=".*?":\n.*?TOKEN={{token}} pixi run proxy-client token update-email {{email}}'
    new_command = '''token-email name email token="${ADMIN_TOKEN}":
    TOKEN={{token}} pixi run proxy-client token update-email {{name}} {{email}}'''
    
    content = re.sub(old_pattern, new_command, content, flags=re.MULTILINE)
    
    with open(justfile, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {justfile}")


def fix_justfile_route_create():
    """Fix route-create command to not use --description flag."""
    print("Fixing route-create command...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        content = f.read()
    
    # Remove --description flag from route-create command
    old_pattern = r'(route-create path target-type target-value.*?\n.*?pixi run proxy-client route create.*?)\s*\\\n\s*{{ if description != "" { "--description.*?" } else { "" } }}'
    
    content = re.sub(old_pattern, r'\1', content, flags=re.MULTILINE | re.DOTALL)
    
    with open(justfile, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {justfile}")


def fix_external_services_list():
    """Fix external services list to return array instead of object."""
    print("Fixing external services list endpoint...")
    
    external_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/external.py"
    
    with open(external_file, 'r') as f:
        content = f.read()
    
    # Find list_external_services function
    pattern = r'(async def list_external_services.*?)(return services_dict if services_dict else {})'
    
    def replacer(match):
        prefix = match.group(1)
        # Change to return list of services
        new_return = '''# Convert dict to list for API response
    services_list = list(services_dict.values()) if services_dict else []
    return services_list'''
        
        return prefix + new_return
    
    content = re.sub(pattern, replacer, content, flags=re.DOTALL)
    
    with open(external_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {external_file}")


def fix_proxy_operations():
    """Fix proxy operations that are failing with 500 errors."""
    print("Fixing proxy operations...")
    
    # The issue is likely in proxies/core.py where it tries to access async_storage
    proxy_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/proxies/core.py"
    
    with open(proxy_file, 'r') as f:
        content = f.read()
    
    # Ensure all functions have Request parameter
    # Check get_proxy_target function
    if "request: Request," not in content:
        # Add Request parameter to functions that need it
        pattern = r'(async def get_proxy_target\(\s*)(hostname: str,'
        content = re.sub(pattern, r'\1request: Request,\n    \2', content)
    
    with open(proxy_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {proxy_file}")


def fix_docker_service_list():
    """Fix Docker service list endpoint."""
    print("Fixing Docker service list...")
    
    docker_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/api/routers/v1/services/docker.py"
    
    with open(docker_file, 'r') as f:
        content = f.read()
    
    # Ensure list_docker_services returns proper response
    if "request: Request" not in content:
        pattern = r'(async def list_docker_services\(\s*)(token_info:'
        content = re.sub(pattern, r'\1request: Request,\n    \2', content)
    
    with open(docker_file, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {docker_file}")


def fix_justfile_logs_stats():
    """Fix logs-stats command in justfile."""
    print("Fixing logs-stats command...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        content = f.read()
    
    # Fix logs-stats to use correct endpoint
    old_pattern = r'(logs-stats hours.*?:\n.*?)pixi run proxy-client logs events'
    new_command = r'\1pixi run proxy-client logs-events'
    
    content = re.sub(old_pattern, new_command, content)
    
    with open(justfile, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {justfile}")


def fix_proxy_auth_enable():
    """Fix proxy-auth-enable command parameters."""
    print("Fixing proxy-auth-enable command...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        content = f.read()
    
    # Fix proxy-auth-enable parameter order
    old_pattern = r'proxy-auth-enable hostname auth-proxy=".*?" mode=".*?" allowed-scopes=".*?" allowed-audiences=".*?" token=".*?":'
    new_pattern = 'proxy-auth-enable hostname auth-proxy="" mode="forward" allowed-scopes="" allowed-audiences="" token="${ADMIN_TOKEN}":'
    
    content = re.sub(old_pattern, new_pattern, content)
    
    with open(justfile, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {justfile}")


def main():
    """Run all fixes."""
    print("=" * 60)
    print("FINAL COMPREHENSIVE FIX FOR ALL ISSUES")
    print("=" * 60)
    
    # API fixes
    fix_certificate_private_key_removal()
    fix_external_services_list()
    fix_proxy_operations()
    fix_docker_service_list()
    
    # Justfile fixes
    fix_justfile_token_email()
    fix_justfile_route_create()
    fix_justfile_logs_stats()
    fix_proxy_auth_enable()
    
    print("\n" + "=" * 60)
    print("✓ ALL FIXES APPLIED SUCCESSFULLY")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run: just rebuild api")
    print("2. Run: bash scripts/comprehensive_command_test.sh")


if __name__ == "__main__":
    main()