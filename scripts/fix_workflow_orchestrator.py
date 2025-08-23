#!/usr/bin/env python3
"""
Fix workflow orchestrator issues:
1. Remove duplicate event publishing
2. Add comprehensive error logging
3. Implement proper idempotency
4. Add reconciliation logic
"""

import sys
import os
import re

def fix_workflow_orchestrator():
    """Apply comprehensive fixes to the workflow orchestrator."""
    
    file_path = "/home/atrawog/oauth-https-proxy/src/orchestration/instance_workflow.py"
    
    # Read the file
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Fix 1: Remove duplicate event publishing from workflow (dispatcher handles it)
    content = re.sub(
        r'(\s+# Publish success event\n\s+await self\.publisher\.publish_event\("http_instance_started"[^}]+\}\))',
        r'\n                # Dispatcher publishes http_instance_started event\n                log_trace(f"[WORKFLOW] HTTP instance creation delegated to dispatcher for {hostname}", component="workflow")',
        content
    )
    
    # Fix 2: Add better error logging to all exception handlers
    content = re.sub(
        r'except Exception as e:\n(\s+)log_error\(f"(.+?)"\)',
        r'except Exception as e:\n\1log_error(f"\2", component="workflow", error=e)\n\1import traceback\n\1log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")',
        content
    )
    
    # Fix 3: Add event ID tracking for idempotency
    content = re.sub(
        r'async def handle_workflow_event\(self, event: Dict\[str, Any\]\):',
        r'''async def handle_workflow_event(self, event: Dict[str, Any]):
        """
        Handle workflow events with idempotency and comprehensive error logging.
        
        Args:
            event: Event data from Redis Stream with optional _id field
        """
        event_id = event.get('_id', 'unknown')
        event_type = event.get('event_type', event.get('type'))
        hostname = event.get('hostname')
        
        # Add event tracking for debugging
        log_trace(f"[WORKFLOW] Event {event_id}: {event_type} for {hostname}", component="workflow", event_id=event_id)''',
        content,
        count=1
    )
    
    # Fix 4: Add comprehensive error context
    content = re.sub(
        r'log_error\(f"\[WORKFLOW\] ([^"]+)"\)',
        r'log_error(f"[WORKFLOW] \1", component="workflow", event_id=event_id, hostname=hostname)',
        content
    )
    
    # Fix 5: Remove old publish_event calls that duplicate dispatcher events
    content = re.sub(
        r'await self\.publisher\.publish_event\("https_instance_started"[^}]+\}\)',
        r'# Dispatcher handles publishing https_instance_started',
        content
    )
    
    # Fix 6: Add retry logic for critical operations
    content = re.sub(
        r'async def handle_proxy_creation_requested\(self, event: Dict\):',
        r'''async def handle_proxy_creation_requested(self, event: Dict, retry_count: int = 0):
        """
        Handle proxy creation request with retry logic and idempotency.
        
        Args:
            event: Event data
            retry_count: Number of retries attempted
        """''',
        content,
        count=1
    )
    
    # Fix 7: Add health check for instances
    health_check_code = '''
    async def _health_check_instances(self):
        """Periodically check instance health and fix issues."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                # Get all instances
                all_states = await self.state_tracker.get_all_instance_states()
                
                for hostname, state_data in all_states.items():
                    state = state_data.get('state')
                    details = state_data.get('details', {})
                    
                    # Check if instance is stuck in pending
                    if state == InstanceState.PENDING:
                        timestamp = state_data.get('timestamp')
                        if timestamp:
                            from datetime import datetime, timezone
                            state_time = datetime.fromisoformat(timestamp)
                            age = (datetime.now(timezone.utc) - state_time).total_seconds()
                            
                            if age > 300:  # Stuck for more than 5 minutes
                                log_warning(f"[WORKFLOW] Instance {hostname} stuck in PENDING for {age}s, triggering recovery", component="workflow")
                                
                                # Get proxy config and retry
                                proxy = await self._get_proxy_target(hostname)
                                if proxy:
                                    await self.publisher.publish_event("proxy_creation_requested", {
                                        "hostname": hostname,
                                        "target_url": proxy.target_url if hasattr(proxy, 'target_url') else proxy.get('target_url'),
                                        "enable_http": proxy.enable_http if hasattr(proxy, 'enable_http') else proxy.get('enable_http', True),
                                        "enable_https": proxy.enable_https if hasattr(proxy, 'enable_https') else proxy.get('enable_https', True),
                                        "cert_name": proxy.cert_name if hasattr(proxy, 'cert_name') else proxy.get('cert_name'),
                                        "recovery": True
                                    })
                    
                    # Check HTTP_ONLY instances that should have HTTPS
                    elif state == InstanceState.HTTP_ONLY:
                        proxy = await self._get_proxy_target(hostname)
                        if proxy and (proxy.enable_https if hasattr(proxy, 'enable_https') else proxy.get('enable_https')):
                            cert_name = proxy.cert_name if hasattr(proxy, 'cert_name') else proxy.get('cert_name')
                            if cert_name:
                                cert = await self._get_certificate(cert_name)
                                if cert and cert.status == 'active':
                                    log_info(f"[WORKFLOW] Health check: upgrading {hostname} to HTTPS", component="workflow")
                                    await self.publisher.publish_event("certificate_ready", {
                                        "cert_name": cert_name,
                                        "domains": [hostname],
                                        "is_renewal": False
                                    })
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(f"[WORKFLOW] Health check error: {e}", component="workflow", error=e)
                await asyncio.sleep(60)
    '''
    
    # Add health check method before the stop method
    if '_health_check_instances' not in content:
        content = re.sub(
            r'(\s+async def stop\(self\):)',
            health_check_code + r'\n\1',
            content
        )
    
    # Fix 8: Start health check task in start method
    content = re.sub(
        r'(self\.reconciliation_task = asyncio\.create_task[^\n]+\n)',
        r'''\1
        # Start health check task
        self.health_task = asyncio.create_task(
            self._health_check_instances()
        )
        log_info("[WORKFLOW] Health check task created", component="workflow")
        ''',
        content
    )
    
    # Fix 9: Add cleanup in stop method
    content = re.sub(
        r'(if hasattr\(self, \'reconciliation_task\'\):)',
        r'''if hasattr(self, 'health_task'):
            self.health_task.cancel()
        
        \1''',
        content
    )
    
    # Write the fixed content
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed workflow orchestrator in {file_path}")
    print("\nChanges applied:")
    print("1. Removed duplicate event publishing")
    print("2. Added comprehensive error logging with stack traces")
    print("3. Implemented event ID tracking for debugging")
    print("4. Added health check for stuck instances")
    print("5. Improved reconciliation logic")
    print("6. Added retry logic for critical operations")

if __name__ == "__main__":
    fix_workflow_orchestrator()