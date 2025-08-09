#!/usr/bin/env python3
"""
Fix justfile issues:
1. Add default recipe
2. Fix section headers on same line as recipes  
3. Add proper spacing
"""

import re

def fix_justfile():
    with open('/home/atrawog/AI/atrawog/mcp-http-proxy/justfile', 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    output = []
    
    # Add header with variables first
    output.extend([
        '# HTTP Proxy with Protected Resources - Refactored Modular Justfile',
        '# This is a refactored version with modular approach and API-first design',
        '',
        '# Variables',
        'container_name := "mcp-http-proxy-api-1"',
        'default_api_url := "http://localhost:80"',
        'staging_cert_email := env_var_or_default("TEST_EMAIL", env_var_or_default("ACME_EMAIL", "test@example.com"))',
        '',
        '# Load environment from .env',
        'set dotenv-load := true',
        'set dotenv-required',
        'set positional-arguments := true',
        'set allow-duplicate-recipes',
        '# Export all variables as environment variables',
        'set export := true',
        'set quiet',
        '',
        '# Default recipe - show available commands',
        '[private]',
        'default:',
        '    @just --list',
        ''
    ])
    
    i = 0
    in_header = True
    
    while i < len(lines):
        line = lines[i]
        
        # Skip initial empty lines and old header stuff
        if in_header:
            if line.startswith('# ============') or line.startswith('# CERTIFICATE'):
                in_header = False
            else:
                i += 1
                continue
        
        # Check if this is a section header on same line as recipe
        if '# ============' in line and ':' in line:
            # Split the line - recipe definition and section header
            parts = line.split('# ============')
            recipe_def = parts[0].strip()
            
            # Add section header first
            output.append('')
            output.append('# ' + '=' * 76)
            # Try to get section name from next line or context
            if i > 0:
                prev_lines = lines[max(0, i-5):i]
                for prev in reversed(prev_lines):
                    if prev.startswith('# ') and '=' not in prev and prev.strip() != '#':
                        section_name = prev.replace('#', '').strip()
                        output.append(f'# {section_name}')
                        break
                else:
                    # Guess from recipe name
                    if recipe_def.startswith('cert-'):
                        output.append('# CERTIFICATE MANAGEMENT')
                    elif recipe_def.startswith('config-'):
                        output.append('# CONFIGURATION MANAGEMENT')
                    elif recipe_def.startswith('service-'):
                        if 'port' in recipe_def:
                            output.append('# PORT MANAGEMENT')
                        elif any(x in recipe_def for x in ['external', 'register', 'unregister']):
                            output.append('# EXTERNAL SERVICE MANAGEMENT')
                        else:
                            output.append('# DOCKER SERVICE MANAGEMENT')
                    elif recipe_def.startswith('logs'):
                        output.append('# LOGGING AND MONITORING')
                    elif recipe_def.startswith('oauth-'):
                        output.append('# OAUTH MANAGEMENT')
                    elif recipe_def.startswith('proxy-resource'):
                        output.append('# PROTECTED RESOURCE MANAGEMENT')
                    elif recipe_def.startswith('proxy-'):
                        output.append('# PROXY MANAGEMENT')
                    elif recipe_def.startswith('route-'):
                        output.append('# ROUTE MANAGEMENT')
                    elif recipe_def.startswith('token-'):
                        output.append('# TOKEN MANAGEMENT')
                    elif recipe_def.startswith('test'):
                        output.append('# TESTING')
                    elif recipe_def in ['up', 'down', 'restart', 'rebuild', 'shell', 'redis-cli', 'health', 'help']:
                        output.append('# SYSTEM MANAGEMENT')
                    else:
                        output.append('# UTILITY')
            output.append('# ' + '=' * 76)
            output.append('')
            
            # Add the recipe definition (without the section header)
            if recipe_def:
                output.append(recipe_def + ':')
        elif line.startswith('# ============'):
            # Standalone section header - keep it
            if i + 1 < len(lines) and lines[i + 1].startswith('#'):
                output.append('')
                output.append(line)
                output.append(lines[i + 1])
                output.append(lines[i + 2] if i + 2 < len(lines) and lines[i + 2].startswith('#') else '# ' + '=' * 76)
                output.append('')
                i += 3
                continue
        else:
            # Regular line - keep as is, but skip redundant variable declarations at the end
            if line.startswith('container_name :=') or line.startswith('default_api_url :=') or line.startswith('staging_cert_email :='):
                # Skip if we're near the end (these are duplicates)
                if i > len(lines) - 20:
                    i += 1
                    continue
            elif line.startswith('set '):
                # Skip if we're near the end (these are duplicates)
                if i > len(lines) - 20:
                    i += 1
                    continue
            output.append(line)
        
        i += 1
    
    # Clean up output - remove duplicate empty lines
    final_output = []
    prev_empty = False
    for line in output:
        if line.strip() == '':
            if not prev_empty:
                final_output.append(line)
                prev_empty = True
        else:
            final_output.append(line)
            prev_empty = False
    
    # Write the fixed justfile
    with open('/home/atrawog/AI/atrawog/mcp-http-proxy/justfile', 'w') as f:
        f.write('\n'.join(final_output))
    
    print("Fixed justfile issues:")
    print("✓ Added default recipe that shows --list")
    print("✓ Fixed section headers on same lines as recipes")
    print("✓ Removed duplicate variable declarations")
    print("✓ Cleaned up formatting")

if __name__ == '__main__':
    fix_justfile()