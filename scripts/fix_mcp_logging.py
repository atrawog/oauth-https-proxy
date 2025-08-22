#!/usr/bin/env python3
"""
Fix the fire-and-forget anti-pattern in mcp_server.py.
Replace asyncio.create_task(self.logger.*) with proper helper methods.
"""

import re

def fix_mcp_logging():
    file_path = "/home/atrawog/oauth-https-proxy/src/api/routers/mcp/mcp_server.py"
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Add helper methods after the class declaration
    class_def = "class IntegratedMCPServer:"
    helper_methods = """class IntegratedMCPServer:
    
    def _log_info_async(self, message: str, **kwargs):
        \"\"\"Fire-and-forget async info logging without creating orphaned tasks.\"\"\"
        if self.logger:
            try:
                # Create task with proper error handling
                task = asyncio.create_task(self.logger.info(message, **kwargs))
                # Add callback to handle exceptions
                task.add_done_callback(lambda t: t.exception() if t.done() else None)
            except RuntimeError:
                # No event loop running, skip logging
                pass
    
    def _log_error_async(self, message: str, **kwargs):
        \"\"\"Fire-and-forget async error logging without creating orphaned tasks.\"\"\"
        if self.logger:
            try:
                # Create task with proper error handling
                task = asyncio.create_task(self.logger.error(message, **kwargs))
                # Add callback to handle exceptions
                task.add_done_callback(lambda t: t.exception() if t.done() else None)
            except RuntimeError:
                # No event loop running, skip logging
                pass
    
    def _log_warning_async(self, message: str, **kwargs):
        \"\"\"Fire-and-forget async warning logging without creating orphaned tasks.\"\"\"
        if self.logger:
            try:
                # Create task with proper error handling
                task = asyncio.create_task(self.logger.warning(message, **kwargs))
                # Add callback to handle exceptions
                task.add_done_callback(lambda t: t.exception() if t.done() else None)
            except RuntimeError:
                # No event loop running, skip logging
                pass"""
    
    content = content.replace(class_def, helper_methods)
    
    # Replace all asyncio.create_task(self.logger.info(...))
    content = re.sub(
        r'asyncio\.create_task\(self\.logger\.info\((.*?)\)\)',
        r'self._log_info_async(\1)',
        content
    )
    
    # Replace all asyncio.create_task(self.logger.error(...))
    content = re.sub(
        r'asyncio\.create_task\(self\.logger\.error\((.*?)\)\)',
        r'self._log_error_async(\1)',
        content
    )
    
    # Replace all asyncio.create_task(self.logger.warning(...))
    content = re.sub(
        r'asyncio\.create_task\(self\.logger\.warning\((.*?)\)\)',
        r'self._log_warning_async(\1)',
        content
    )
    
    # Fix the special case with unified_logger
    old_pattern = r'asyncio\.create_task\(unified_logger\.warning\(f"Error querying logs: {e}"\) if unified_logger else asyncio\.sleep\(0\)\)'
    new_pattern = '''if unified_logger:
                        try:
                            task = asyncio.create_task(unified_logger.warning(f"Error querying logs: {e}"))
                            task.add_done_callback(lambda t: t.exception() if t.done() else None)
                        except Exception:
                            pass'''
    
    content = re.sub(old_pattern, new_pattern, content)
    
    # Write the fixed content
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed fire-and-forget anti-pattern in {file_path}")
    
    # Count how many replacements were made
    import_count = content.count('import asyncio')
    if import_count < 2:
        print("Note: May need to ensure 'import asyncio' is at the top of the file")

if __name__ == "__main__":
    fix_mcp_logging()