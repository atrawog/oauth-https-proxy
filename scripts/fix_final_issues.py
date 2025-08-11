#!/usr/bin/env python3
"""
Fix the final remaining issues.
"""

import os
import re


def fix_token_email():
    """Fix token-email command to use correct syntax."""
    print("Fixing token-email command...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        content = f.read()
    
    # Fix token-email command - remove --email flag
    content = re.sub(
        r'TOKEN={{token}} pixi run proxy-client token update-email {{name}} --email {{email}}',
        'TOKEN={{token}} pixi run proxy-client token update-email {{name}} {{email}}',
        content
    )
    
    with open(justfile, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed {justfile}")


def fix_async_cert_manager():
    """Add get_certificate method to AsyncCertificateManager."""
    print("Fixing AsyncCertificateManager...")
    
    manager_file = "/home/atrawog/AI/atrawog/mcp-http-proxy/src/certmanager/async_manager.py"
    
    with open(manager_file, 'r') as f:
        content = f.read()
    
    # Add get_certificate method if it doesn't exist
    if "async def get_certificate" not in content:
        # Find a good place to add it - after get_certificate_status
        pattern = r'(async def get_certificate_status.*?return status_data)'
        
        def replacer(match):
            original = match.group(0)
            new_method = '''
    
    async def get_certificate(self, cert_name: str) -> Optional[Dict]:
        """Get certificate by name.
        
        Args:
            cert_name: Name of the certificate
            
        Returns:
            Certificate data or None if not found
        """
        return await self.storage.get_certificate(cert_name)'''
            
            return original + new_method
        
        content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        
        with open(manager_file, 'w') as f:
            f.write(content)
        
        print(f"✓ Fixed {manager_file}")
    else:
        print(f"✓ Already has get_certificate: {manager_file}")


def fix_logs_stats():
    """Fix logs-stats command to use correct command."""
    print("Fixing logs-stats command...")
    
    justfile = "/home/atrawog/AI/atrawog/mcp-http-proxy/justfile"
    
    with open(justfile, 'r') as f:
        lines = f.readlines()
    
    # Find and fix logs-stats command
    for i, line in enumerate(lines):
        if line.startswith('logs-stats hours='):
            if i + 1 < len(lines):
                # Check the command - should be "logs events"
                lines[i + 1] = '    TOKEN={{token}} pixi run proxy-client logs events --hours {{hours}}\n'
            break
    
    with open(justfile, 'w') as f:
        f.writelines(lines)
    
    print(f"✓ Fixed {justfile}")


def main():
    """Run all fixes."""
    print("=" * 60)
    print("FIXING FINAL REMAINING ISSUES")
    print("=" * 60)
    
    fix_token_email()
    fix_async_cert_manager()
    fix_logs_stats()
    
    print("\n" + "=" * 60)
    print("✓ ALL FINAL ISSUES FIXED")
    print("=" * 60)


if __name__ == "__main__":
    main()