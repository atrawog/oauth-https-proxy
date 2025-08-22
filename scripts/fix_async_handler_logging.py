#!/usr/bin/env python3
"""
Fix mixed logging in proxy/async_handler.py.
Replace old logger with unified async logger properly.
"""

import re

def fix_async_handler_logging():
    file_path = "/home/atrawog/oauth-https-proxy/src/proxy/async_handler.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Step 1: Remove old logging import
    content = content.replace("import logging\n", "")
    
    # Step 2: Replace logger initialization
    old_logger_init = """# Get logger for this module
logger = logging.getLogger(__name__)"""
    
    new_logger_init = """# Use compatibility logger that wraps unified async logger
from ..shared.logger import get_logger_compat
logger = get_logger_compat(__name__)"""
    
    content = content.replace(old_logger_init, new_logger_init)
    
    # Step 3: Add import for fire-and-forget logging functions if not present
    if "from ..shared.logger import" not in content:
        # Find the imports section and add the import
        import_section_end = content.find("\n\n# Get logger")
        if import_section_end > 0:
            content = content[:import_section_end] + "\nfrom ..shared.logger import get_logger_compat, log_info, log_warning, log_error, log_debug" + content[import_section_end:]
    
    # Step 4: For async methods, replace logger calls with await self.unified_logger calls where appropriate
    # Since AsyncProxyHandler has self.unified_logger, we can use it directly in async methods
    
    # Pattern to find async methods with logger calls
    async_method_pattern = r'async def (\w+)\(self[^)]*\):'
    
    # First, let's identify all async methods
    async_methods = re.findall(async_method_pattern, content)
    
    # For each async method, replace logger.* with proper async logging
    for method in async_methods:
        # Find the method body
        method_start = content.find(f"async def {method}(")
        if method_start == -1:
            continue
        
        # Find the next method or class end
        next_method = content.find("\n    async def ", method_start + 1)
        next_sync_method = content.find("\n    def ", method_start + 1)
        class_end = content.find("\nclass ", method_start + 1)
        
        # Determine method end
        method_end = len(content)
        for end in [next_method, next_sync_method, class_end]:
            if end > 0 and end < method_end:
                method_end = end
        
        # Extract method body
        method_body = content[method_start:method_end]
        
        # In the method body, replace logger.info/warning/error/debug with async calls
        # But only if self.unified_logger is available
        if "self.unified_logger" in content:
            # Replace logger.info with await self.unified_logger.info
            method_body = re.sub(
                r'\blogger\.info\(',
                'await self.unified_logger.info(',
                method_body
            )
            method_body = re.sub(
                r'\blogger\.warning\(',
                'await self.unified_logger.warning(',
                method_body
            )
            method_body = re.sub(
                r'\blogger\.error\(',
                'await self.unified_logger.error(',
                method_body
            )
            method_body = re.sub(
                r'\blogger\.debug\(',
                'await self.unified_logger.debug(',
                method_body
            )
        
        # Replace the method in content
        content = content[:method_start] + method_body + content[method_end:]
    
    # Step 5: For synchronous methods or class-level code, use fire-and-forget helpers
    # Replace remaining logger calls outside async methods
    content = re.sub(
        r'\blogger\.info\(',
        'log_info(',
        content
    )
    content = re.sub(
        r'\blogger\.warning\(',
        'log_warning(',
        content
    )
    content = re.sub(
        r'\blogger\.error\(',
        'log_error(',
        content
    )
    content = re.sub(
        r'\blogger\.debug\(',
        'log_debug(',
        content
    )
    
    # Step 6: Ensure all log calls include component="proxy"
    # Add component parameter to log calls that don't have it
    content = re.sub(
        r'log_info\(([^)]+)\)',
        r'log_info(\1, component="proxy")',
        content
    )
    content = re.sub(
        r'log_warning\(([^)]+)\)',
        r'log_warning(\1, component="proxy")',
        content
    )
    content = re.sub(
        r'log_error\(([^)]+)\)',
        r'log_error(\1, component="proxy")',
        content
    )
    content = re.sub(
        r'log_debug\(([^)]+)\)',
        r'log_debug(\1, component="proxy")',
        content
    )
    
    # Fix double component parameters
    content = content.replace(', component="proxy", component="proxy"', ', component="proxy"')
    
    # Write the fixed content
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed mixed logging in {file_path}")
    print("- Removed old logging import")
    print("- Replaced with unified async logger")
    print("- Updated async methods to use await for logging")
    print("- Added fire-and-forget helpers for sync methods")

if __name__ == "__main__":
    fix_async_handler_logging()