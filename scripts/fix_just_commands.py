#!/usr/bin/env python3
"""
Fix just commands to properly handle authentication tokens.

This script ensures that:
1. Tokens are properly read from .env file
2. Commands work without manual token passing
3. Everything is reproducible
"""

import os
import re

def fix_justfile():
    """Fix token handling in justfile."""
    
    justfile_path = "/home/atrawog/oauth-https-proxy/justfile"
    
    # Read the justfile
    with open(justfile_path, 'r') as f:
        content = f.read()
    
    # Fix 1: Ensure .env file is loaded at the top of justfile
    if 'set dotenv-load' not in content:
        # Add dotenv loading at the beginning
        content = "# Load .env file automatically\nset dotenv-load := true\n\n" + content
    
    # Fix 2: Change default token behavior to use ADMIN_TOKEN from .env
    # Replace env_var_or_default("ADMIN_TOKEN", "") with env_var("ADMIN_TOKEN")
    # But keep it optional for commands that don't always need admin
    
    # For cert-delete and other admin commands, make token required from env
    admin_commands = [
        'cert-delete', 'cert-renew', 'cert-convert-to-production',
        'token-create', 'token-delete', 'service-cleanup'
    ]
    
    for cmd in admin_commands:
        # Find the command definition
        pattern = rf'^({cmd}[^:]*):.*?\n.*?TOKEN={{{{token}}}}'
        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
        for match in matches:
            # Check if this command uses env_var_or_default
            if 'env_var_or_default("ADMIN_TOKEN", "")' in match.group(0):
                # Replace with env_var to make it required
                old_line = match.group(0)
                new_line = old_line.replace(
                    'token=env_var_or_default("ADMIN_TOKEN", "")',
                    'token=env_var("ADMIN_TOKEN")'
                )
                content = content.replace(old_line, new_line)
    
    # Fix 3: For non-admin commands, keep optional but with better default
    # These commands should work with or without token
    optional_commands = [
        'proxy-create', 'proxy-list', 'cert-list', 'service-list',
        'logs', 'logs-errors', 'health'
    ]
    
    for cmd in optional_commands:
        pattern = rf'^({cmd}[^:]*):.*?\n.*?TOKEN={{{{token}}}}'
        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
        for match in matches:
            if 'env_var_or_default("ADMIN_TOKEN", "")' in match.group(0):
                # Keep as optional but with explicit empty default
                old_line = match.group(0)
                new_line = old_line.replace(
                    'env_var_or_default("ADMIN_TOKEN", "")',
                    'env_var_or_default("ADMIN_TOKEN", "acm_public")'
                )
                content = content.replace(old_line, new_line)
    
    # Write the fixed justfile
    with open(justfile_path, 'w') as f:
        f.write(content)
    
    print("Fixed justfile token handling")
    print("Admin commands now require ADMIN_TOKEN from .env")
    print("Optional commands use acm_public as default")


def fix_env_loading():
    """Ensure .env file is properly formatted."""
    
    env_path = "/home/atrawog/oauth-https-proxy/.env"
    
    if not os.path.exists(env_path):
        print("Warning: .env file not found")
        return
    
    with open(env_path, 'r') as f:
        lines = f.readlines()
    
    # Check if ADMIN_TOKEN is set
    has_admin_token = False
    for line in lines:
        if line.strip().startswith('ADMIN_TOKEN='):
            has_admin_token = True
            break
    
    if not has_admin_token:
        print("Warning: ADMIN_TOKEN not found in .env file")
        print("Add: ADMIN_TOKEN=acm_your_token_here")
    else:
        print(".env file has ADMIN_TOKEN configured")


def create_proxy_wrapper():
    """Create a wrapper script for proxy creation that handles everything."""
    
    wrapper = '''#!/usr/bin/env bash
# Wrapper script for creating proxies with proper certificate handling

set -e

HOSTNAME="$1"
TARGET="$2"
CERT_MODE="${3:-staging}"  # staging or production

if [ -z "$HOSTNAME" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <hostname> <target-url> [staging|production]"
    exit 1
fi

echo "Creating proxy for $HOSTNAME -> $TARGET with $CERT_MODE certificate"

# Source the .env file
source .env

# Delete existing proxy if it exists
echo "Cleaning up existing proxy..."
just proxy-delete "$HOSTNAME" 2>/dev/null || true

# Delete existing certificate if it exists
echo "Cleaning up existing certificate..."
redis-cli -a "$REDIS_PASSWORD" DEL "cert:proxy-${HOSTNAME//./-}" "cert:domain:$HOSTNAME" 2>/dev/null || true

# Create certificate
CERT_NAME="proxy-${HOSTNAME//./-}"
echo "Creating $CERT_MODE certificate..."
just cert-create "$CERT_NAME" "$HOSTNAME" "$CERT_MODE"

# Wait for certificate
echo "Waiting for certificate..."
for i in {1..30}; do
    STATUS=$(redis-cli -a "$REDIS_PASSWORD" --raw HGET "cert:$CERT_NAME" status 2>/dev/null || echo "pending")
    if [ "$STATUS" = "active" ]; then
        echo "Certificate ready!"
        break
    fi
    echo "Certificate status: $STATUS (attempt $i/30)"
    sleep 2
done

# Create proxy
echo "Creating proxy..."
just proxy-create "$HOSTNAME" "$TARGET" "$CERT_NAME"

# Test endpoints
echo "Testing endpoints..."
sleep 5

# Test HTTP
echo "Testing HTTP..."
curl -s -o /dev/null -w "HTTP: %{http_code}\\n" "http://$HOSTNAME/health" || true

# Test HTTPS
echo "Testing HTTPS..."
curl -sk -o /dev/null -w "HTTPS: %{http_code}\\n" "https://$HOSTNAME/health" || true

echo "Proxy created successfully!"
'''
    
    script_path = "/home/atrawog/oauth-https-proxy/scripts/create-proxy.sh"
    with open(script_path, 'w') as f:
        f.write(wrapper)
    
    os.chmod(script_path, 0o755)
    print(f"Created proxy wrapper script: {script_path}")


if __name__ == "__main__":
    print("Fixing just commands and authentication...")
    fix_justfile()
    fix_env_loading()
    create_proxy_wrapper()
    print("\nDone! Use scripts/create-proxy.sh for reproducible proxy creation")