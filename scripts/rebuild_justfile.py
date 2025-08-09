#!/usr/bin/env python3
"""
Rebuild justfile with proper structure and alphabetical sorting.
"""

import re
from collections import defaultdict

def parse_recipes(filename):
    """Parse all recipes from the justfile."""
    with open(filename, 'r') as f:
        content = f.read()
    
    recipes = []
    current_recipe = []
    recipe_name = None
    
    lines = content.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check if this is a recipe definition line
        # Could be simple like "help:" or complex like "cert-create name domain email="" token="" staging="false":" 
        if re.match(r'^[a-z][a-z0-9-]*(\s+[^:]+)?:', line):
            # Save previous recipe if exists
            if recipe_name and current_recipe:
                recipes.append((recipe_name, '\n'.join(current_recipe)))
            
            # Extract recipe name
            recipe_name = line.split(':')[0].split()[0]
            # Handle case where section header is on same line
            if '# ============' in line:
                line = line.split('# ============')[0].rstrip() + ':'
            current_recipe = [line]
        elif recipe_name:
            # Continue collecting recipe lines
            # Stop at empty line followed by a new recipe or section header
            if line == '' and i + 1 < len(lines):
                next_line = lines[i + 1]
                if re.match(r'^[a-z]', next_line) or next_line.startswith('# ==='):
                    # End of recipe
                    recipes.append((recipe_name, '\n'.join(current_recipe)))
                    recipe_name = None
                    current_recipe = []
                else:
                    current_recipe.append(line)
            else:
                current_recipe.append(line)
        
        i += 1
    
    # Save last recipe
    if recipe_name and current_recipe:
        # Remove trailing empty lines
        while current_recipe and current_recipe[-1] == '':
            current_recipe.pop()
        recipes.append((recipe_name, '\n'.join(current_recipe)))
    
    return recipes

def categorize_recipes(recipes):
    """Categorize recipes by their prefix."""
    categories = defaultdict(list)
    
    for name, content in recipes:
        # Add description comment if missing
        lines = content.split('\n')
        first_line = lines[0]
        
        # Determine category
        if name.startswith('cert-'):
            category = 'CERTIFICATE MANAGEMENT'
            if name == 'cert-create':
                lines[0] = first_line.split(':')[0] + ':  # Create a new certificate'
            elif name == 'cert-delete':
                lines[0] = first_line.split(':')[0] + ':  # Delete certificate'
            elif name == 'cert-list':
                lines[0] = first_line.split(':')[0] + ':  # List certificates (requires authentication)'
            elif name == 'cert-show':
                lines[0] = first_line.split(':')[0] + ':  # Show certificate details'
        elif name.startswith('config-'):
            category = 'CONFIGURATION MANAGEMENT'
            if name == 'config-save':
                lines[0] = first_line.split(':')[0] + ':  # Save full configuration to YAML backup'
            elif name == 'config-load':
                lines[0] = first_line.split(':')[0] + ':  # Load configuration from YAML backup'
        elif name.startswith('service-port'):
            category = 'PORT MANAGEMENT'
        elif name.startswith('service-') and any(x in name for x in ['external', 'register', 'unregister', 'update-external', 'list-all']):
            category = 'EXTERNAL SERVICE MANAGEMENT'
        elif name.startswith('service-'):
            category = 'DOCKER SERVICE MANAGEMENT'
        elif name.startswith('logs'):
            category = 'LOGGING AND MONITORING'
        elif name.startswith('oauth-'):
            category = 'OAUTH MANAGEMENT'
        elif name.startswith('proxy-resource'):
            category = 'PROTECTED RESOURCE MANAGEMENT'
        elif name.startswith('proxy-'):
            category = 'PROXY MANAGEMENT'
        elif name.startswith('route-'):
            category = 'ROUTE MANAGEMENT'
        elif name.startswith('token-'):
            category = 'TOKEN MANAGEMENT'
        elif name.startswith('test'):
            category = 'TESTING'
        elif name in ['up', 'down', 'restart', 'rebuild', 'shell', 'redis-cli', 'health', 'help']:
            category = 'SYSTEM MANAGEMENT'
            if name == 'help':
                lines[0] = 'help:  # Show all available commands'
            elif name == 'up':
                lines[0] = 'up:  # Start all services'
            elif name == 'down':
                lines[0] = 'down:  # Stop all services'
            elif name == 'restart':
                lines[0] = 'restart: down up  # Restart all services'
            elif name == 'health':
                lines[0] = 'health:  # Check system health'
            elif name == 'shell':
                lines[0] = 'shell:  # Open shell in container'
            elif name == 'redis-cli':
                lines[0] = 'redis-cli:  # Access Redis CLI'
            elif name == 'rebuild':
                lines[0] = first_line.split(':')[0] + ':  # Rebuild a specific service'
        else:
            category = 'UTILITY'
        
        content = '\n'.join(lines)
        categories[category].append((name, content))
    
    # Sort recipes within each category
    for category in categories:
        categories[category].sort(key=lambda x: x[0])
    
    return categories

def build_justfile(categories):
    """Build the complete justfile content."""
    output = []
    
    # Add header
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
    ])
    
    # Add categories in order
    category_order = [
        'SYSTEM MANAGEMENT',
        'TOKEN MANAGEMENT',
        'CERTIFICATE MANAGEMENT',
        'PROXY MANAGEMENT',
        'PROTECTED RESOURCE MANAGEMENT',
        'ROUTE MANAGEMENT',
        'DOCKER SERVICE MANAGEMENT',
        'PORT MANAGEMENT',
        'EXTERNAL SERVICE MANAGEMENT',
        'OAUTH MANAGEMENT',
        'LOGGING AND MONITORING',
        'CONFIGURATION MANAGEMENT',
        'TESTING',
        'UTILITY',
    ]
    
    for category in category_order:
        if category not in categories or not categories[category]:
            continue
        
        output.extend([
            '',
            '# ' + '=' * 76,
            f'# {category}',
            '# ' + '=' * 76,
        ])
        
        for name, content in categories[category]:
            output.append('')
            output.append(content)
    
    return '\n'.join(output)

def main():
    # Parse recipes from backup
    recipes = parse_recipes('/home/atrawog/AI/atrawog/mcp-http-proxy/justfile.backup')
    
    # Categorize and sort
    categories = categorize_recipes(recipes)
    
    # Build new justfile
    content = build_justfile(categories)
    
    # Write result
    with open('/home/atrawog/AI/atrawog/mcp-http-proxy/justfile', 'w') as f:
        f.write(content)
    
    print("✓ Rebuilt justfile with:")
    print("  - Default recipe that shows --list")
    print("  - Properly separated section headers")
    print("  - Alphabetically sorted commands")
    print("  - Descriptive comments for main commands")

if __name__ == '__main__':
    main()