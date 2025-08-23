"""Instance creation workflow orchestrator using Redis Streams.

This module implements a complete event-driven workflow for instance creation,
ensuring no race conditions by using Redis Streams for all state transitions.

Workflow:
1. proxy_creation_requested → Validate and store proxy config
2. proxy_stored → Request certificate if HTTPS enabled
3. certificate_requested → Start async cert generation  
4. allocate_ports_requested → Allocate HTTP/HTTPS ports
5. ports_allocated → Start HTTP instance
6. http_instance_started → Register HTTP routes
7. certificate_ready → Start HTTPS instance
8. https_instance_started → Register HTTPS routes
9. instance_fully_operational → Complete
"""

import asyncio
import json
import logging
import os
import sys
from typing import Dict, Optional, Any
from datetime import datetime, timezone

from ..storage.redis_stream_publisher import RedisStreamPublisher
from ..storage.instance_state import InstanceStateTracker, InstanceState
from ..dispatcher.redis_stream_consumer import RedisStreamConsumer
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace

# Set up Python standard logger for debugging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class InstanceWorkflowOrchestrator:
    """Orchestrates instance creation workflow through Redis Streams."""
    
    def __init__(self, redis_url: str, storage, cert_manager=None, dispatcher=None, async_components=None):
        """
        Initialize the workflow orchestrator.
        
        Args:
            redis_url: Redis connection URL
            storage: Storage instance for proxy/cert data (legacy)
            cert_manager: Certificate manager instance
            dispatcher: Dispatcher instance for routing
            async_components: Async components for Redis operations
        """
        self.redis_url = redis_url
        self.storage = storage
        self.async_storage = async_components.async_storage if async_components else None
        self.cert_manager = cert_manager
        self.dispatcher = dispatcher
        
        self.publisher = RedisStreamPublisher(redis_url=redis_url)
        self.state_tracker = InstanceStateTracker(redis_url)
        self.consumer = RedisStreamConsumer(
            redis_url=redis_url,
            group_name="workflow-orchestrator"
        )
        
        # Track allocated ports to prevent conflicts
        self.allocated_ports = set()
        self.next_http_port = 10000
        self.next_https_port = 11000
    
    async def _get_proxy_target(self, proxy_hostname: str):
        """Get proxy target using async storage if available."""
        if self.async_storage:
            return await self.async_storage.get_proxy_target(proxy_hostname)
        return self.storage.get_proxy_target(proxy_hostname)
    
    async def _get_certificate(self, cert_name: str):
        """Get certificate using async storage if available."""
        if self.async_storage:
            return await self.async_storage.get_certificate(cert_name)
        return self.storage.get_certificate(cert_name)
    
    async def _store_proxy_target(self, proxy_hostname: str, proxy):
        """Store proxy target using async storage if available."""
        if self.async_storage:
            return await self.async_storage.store_proxy_target(proxy_hostname, proxy)
        return self.storage.store_proxy_target(proxy_hostname, proxy)
    
    async def _store_certificate(self, cert_name: str, cert):
        """Store certificate using async storage if available."""
        if self.async_storage:
            return await self.async_storage.store_certificate(cert_name, cert)
        return self.storage.store_certificate(cert_name, cert)
    
    async def start(self):
        """Start the workflow orchestrator."""
        logger.info("[WORKFLOW] Starting workflow orchestrator initialization")
        log_info("[WORKFLOW] Starting workflow orchestrator initialization", component="workflow")
        
        # Log dispatcher status
        logger.info(f"[WORKFLOW] Dispatcher status at start: self.dispatcher={self.dispatcher}, type={type(self.dispatcher) if self.dispatcher else 'None'}")
        if self.dispatcher:
            log_info(f"[WORKFLOW] Dispatcher is set: {type(self.dispatcher).__name__}", component="workflow")
        else:
            log_warning("[WORKFLOW] WARNING: Dispatcher is NOT set at start time!", component="workflow")
        
        await self.consumer.initialize()
        logger.info("[WORKFLOW] Consumer initialized")
        log_info("[WORKFLOW] Consumer initialized", component="workflow")
        
        # Publisher and state tracker don't need initialization - they connect on first use
        
        # Start consuming workflow events
        self.consumer_task = asyncio.create_task(
            self.consumer.consume_events(self.handle_workflow_event)
        )
        logger.info(f"[WORKFLOW] Consumer task created: {self.consumer_task}")
        log_info("[WORKFLOW] Consumer task created", component="workflow")
        
        # Start handling pending messages
        self.pending_task = asyncio.create_task(
            self.consumer.claim_pending_messages(idle_time_ms=30000)  # 30 seconds
        )
        logger.info(f"[WORKFLOW] Pending task created: {self.pending_task}")
        log_info("[WORKFLOW] Pending task created", component="workflow")
        
        # Start periodic reconciliation task
        self.reconciliation_task = asyncio.create_task(
            self._periodic_reconciliation()
        )
        logger.info(f"[WORKFLOW] Reconciliation task created: {self.reconciliation_task}")
        log_info("[WORKFLOW] Reconciliation task created", component="workflow")
        
        # Initial reconciliation on startup
        logger.info("[WORKFLOW] Starting initial reconciliation...")
        await self._publish_events_for_existing_proxies()
        logger.info("[WORKFLOW] Initial reconciliation completed")
        
        log_info("[WORKFLOW] Instance workflow orchestrator started with event processing", component="workflow")
    
    async def _periodic_reconciliation(self):
        """Periodically reconcile proxy states with instances."""
        while True:
            try:
                # Wait 5 minutes between reconciliations
                await asyncio.sleep(300)
                
                log_debug("[WORKFLOW] Running periodic reconciliation", component="workflow")
                await self._publish_events_for_existing_proxies()
                
            except asyncio.CancelledError:
                log_info("[WORKFLOW] Reconciliation task cancelled", component="workflow")
                break
            except Exception as e:
                log_error(f"[WORKFLOW] Error in periodic reconciliation: {e}", component="workflow", error=e)
                await asyncio.sleep(60)  # Wait a minute before retrying
    
    async def _publish_events_for_existing_proxies(self):
        """Check and reconcile existing proxies with their instance states."""
        log_info("[WORKFLOW] Starting reconciliation of existing proxies...", component="workflow")
        
        try:
            # Get all existing proxies
            all_proxies = []
            if self.async_storage:
                all_proxies = await self.async_storage.list_proxy_targets()
            elif self.storage:
                all_proxies = self.storage.list_proxy_targets()
            
            # Skip localhost and other special proxies
            skip_proxy_hostnames = ['localhost', '127.0.0.1']
            
            reconciled = 0
            created = 0
            upgraded = 0
            
            log_info(f"[WORKFLOW] Found {len(all_proxies)} proxies to reconcile", component="workflow")
            
            for proxy in all_proxies:
                try:
                    proxy_hostname = proxy.get('proxy_hostname') if hasattr(proxy, 'get') else proxy.proxy_hostname
                    log_info(f"[WORKFLOW] Checking proxy: {proxy_hostname}", component="workflow")
                    
                    if proxy_hostname in skip_proxy_hostnames:
                        continue
                    
                    # Check instance state
                    try:
                        instance_state = await self.state_tracker.get_instance_state(proxy_hostname)
                        log_debug(f"[WORKFLOW] Instance state for {proxy_hostname}: {instance_state}", component="workflow")
                    except Exception as e:
                        log_error(f"[WORKFLOW] Failed to get instance state for {proxy_hostname}: {e}", 
                                 component="workflow", error=str(e))
                        instance_state = None
                    
                    if not instance_state or instance_state.get('state') in [InstanceState.FAILED, InstanceState.PENDING]:
                        # Instance doesn't exist or failed, create it
                        state_desc = "not found" if not instance_state else f"in state {instance_state.get('state')}"
                        log_info(f"[WORKFLOW] Instance for {proxy_hostname} {state_desc}, creating it", component="workflow")
                        
                        event_data = {
                            "proxy_hostname": proxy_hostname,
                            "target_url": proxy.target_url if hasattr(proxy, 'target_url') else proxy.get('target_url'),
                            "enable_http": proxy.enable_http if hasattr(proxy, 'enable_http') else proxy.get('enable_http', True),
                            "enable_https": proxy.enable_https if hasattr(proxy, 'enable_https') else proxy.get('enable_https', True),
                            "cert_name": proxy.cert_name if hasattr(proxy, 'cert_name') else proxy.get('cert_name'),
                            "owner_token_hash": proxy.owner_token_hash if hasattr(proxy, 'owner_token_hash') else proxy.get('owner_token_hash'),
                            "created_by": proxy.created_by if hasattr(proxy, 'created_by') else proxy.get('created_by')
                        }
                        
                        try:
                            event_id = await self.publisher.publish_event("proxy_creation_requested", event_data)
                            if event_id:
                                log_info(f"[WORKFLOW] Published proxy_creation_requested for {proxy_hostname}, event_id: {event_id}", 
                                        component="workflow")
                                created += 1
                            else:
                                log_error(f"[WORKFLOW] Failed to publish proxy_creation_requested for {proxy_hostname} - no event ID returned", 
                                         component="workflow")
                        except Exception as e:
                            log_error(f"[WORKFLOW] Exception publishing proxy_creation_requested for {proxy_hostname}: {e}", 
                                     component="workflow", error=str(e))
                        
                        await asyncio.sleep(0.1)  # Avoid overwhelming
                    
                    elif instance_state.get('state') == InstanceState.HTTP_ONLY:
                        # Check if HTTPS upgrade is needed
                        enable_https = proxy.enable_https if hasattr(proxy, 'enable_https') else proxy.get('enable_https', True)
                        cert_name = proxy.cert_name if hasattr(proxy, 'cert_name') else proxy.get('cert_name')
                        
                        if enable_https and cert_name:
                            # Check if certificate exists
                            cert = await self._get_certificate(cert_name)
                            if cert:
                                log_info(f"[WORKFLOW] Upgrading {proxy_hostname} to HTTPS", component="workflow")
                                await self.publisher.publish_event("certificate_ready", {
                                    "cert_name": cert_name,
                                    "proxy_hostname": proxy_hostname,
                                    "domains": [proxy_hostname],
                                    "is_renewal": False
                                })
                                upgraded += 1
                    else:
                        # Instance is running correctly
                        reconciled += 1
                    
                except Exception as e:
                    log_error(f"[WORKFLOW] Error processing proxy {proxy_hostname}: {e}", component="workflow", error=str(e))
                    import traceback
                    log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")
            
            if created > 0 or upgraded > 0:
                log_info(f"[WORKFLOW] Reconciliation: {created} created, {upgraded} upgraded, {reconciled} OK", component="workflow")
            else:
                log_trace(f"[WORKFLOW] All {reconciled} proxies running correctly", component="workflow")
            
        except Exception as e:
            log_error(f"[WORKFLOW] Error publishing events for existing proxies: {e}", component="workflow", error=e)
            import traceback
            log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")
    
    async def handle_workflow_event(self, event: Dict[str, Any]):
        """
        Handle workflow events with idempotency and comprehensive error logging.
        
        Args:
            event: Event data from Redis Stream with optional _id field
        """
        event_id = event.get('_id', 'unknown')
        event_type = event.get('event_type', event.get('type'))
        # Use proxy_hostname for clarity and consistency
        proxy_hostname = event.get('proxy_hostname')
        
        logger.info(f"[WORKFLOW] Processing event: type={event_type}, proxy_hostname={proxy_hostname}, id={event_id}")
        log_info(f"[WORKFLOW] Processing {event_type}", 
                component="workflow", 
                event_type=event_type,
                proxy_hostname=proxy_hostname,
                event_id=event_id)
        
        try:
            # Critical fix: Actually handle the events!
            if event_type == 'proxy_creation_requested':
                logger.info(f"[WORKFLOW] Handling proxy_creation_requested for {proxy_hostname}")
                await self.handle_proxy_creation_requested(event)
                logger.info(f"[WORKFLOW] Completed handling proxy_creation_requested for {proxy_hostname}")
                
            elif event_type == 'proxy_stored':
                await self.handle_proxy_stored(event)
                
            elif event_type == 'certificate_requested':
                await self.handle_certificate_requested(event)
                
            elif event_type == 'allocate_ports_requested':
                await self.handle_allocate_ports(event)
                
            elif event_type == 'ports_allocated':
                await self.handle_ports_allocated(event)
                
            elif event_type == 'create_http_instance':
                await self.handle_create_http_instance(event)
                
            elif event_type == 'create_https_instance':
                await self.handle_create_https_instance(event)
                
            elif event_type == 'http_instance_started':
                await self.handle_http_instance_started(event)
                
            elif event_type == 'certificate_ready':
                await self.handle_certificate_ready_workflow(event)
                
            elif event_type == 'https_instance_started':
                await self.handle_https_instance_started(event)
                
            elif event_type == 'instance_failed':
                await self.handle_instance_failed(event)
                
            # Handle certificate lifecycle events
            elif event_type == 'certificate_renewal_requested':
                await self.handle_certificate_renewal(event)
                
            elif event_type == 'certificate_renewed':
                await self.handle_certificate_renewed(event)
                
            elif event_type == 'convert_to_production_requested':
                await self.handle_staging_to_production(event)
                
            elif event_type == 'production_certificate_ready':
                await self.handle_production_cert_ready(event)
                
            elif event_type == 'certificate_updated':
                await self.handle_certificate_updated(event)
                
            else:
                log_debug(f"[WORKFLOW] Unhandled event type: {event_type}", component="workflow")
                
        except Exception as e:
            log_error(f"[WORKFLOW] Error handling event", 
                     component="workflow",
                     event_type=event_type,
                     proxy_hostname=proxy_hostname,
                     error=str(e))
            import traceback
            log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")
            
            # Publish failure event
            await self.publisher.publish_instance_failed(
                proxy_hostname=proxy_hostname,  # Use the extracted proxy_hostname
                instance_type="workflow",
                error=str(e)
            )
    
    async def handle_proxy_creation_requested(self, event: Dict, retry_count: int = 0):
        """
        Handle proxy creation request with retry logic and idempotency.
        
        Args:
            event: Event data
            retry_count: Number of retries attempted
        """
        """
        Handle proxy creation request.
        
        Flow:
        1. Analyze existing resources (proxy, cert, instances)
        2. Determine what needs to be created
        3. Orchestrate creation in correct order
        """
        # Use proxy_hostname for clarity (support both for transition)
        proxy_hostname = event.get('proxy_hostname')
        target_url = event.get('target_url')
        enable_http = event.get('enable_http', True)
        enable_https = event.get('enable_https', True)
        cert_email = event.get('cert_email')
        cert_name = event.get('cert_name')
        owner_token_hash = event.get('owner_token_hash')
        created_by = event.get('created_by')
        
        # Check if instance already exists (idempotency)
        logger.info(f"[WORKFLOW] Checking instance state for {proxy_hostname}")
        instance_state = await self.state_tracker.get_instance_state(proxy_hostname)
        logger.info(f"[WORKFLOW] Instance state for {proxy_hostname}: {instance_state}")
        if instance_state and instance_state.get('state') in [InstanceState.FULLY_RUNNING, InstanceState.HTTP_ONLY]:
            logger.info(f"[WORKFLOW] {proxy_hostname} already exists in state {instance_state.get('state')}, returning early")
            log_info(f"[WORKFLOW] {proxy_hostname} already exists in state {instance_state.get('state')}, checking if upgrade needed", component="workflow")
            
            # Check if HTTPS upgrade is needed
            details = instance_state.get('details', {})
            if enable_https and 'https_port' not in details:
                # Check if certificate is ready
                if cert_name and await self._get_certificate(cert_name):
                    log_info(f"[WORKFLOW] {proxy_hostname} to HTTPS", component="workflow")
                    await self.publisher.publish_event("certificate_ready", {
                        "cert_name": cert_name,
                        "domains": [proxy_hostname],
                        "is_renewal": False
                    })
            return
        
        log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
        
        # Set initial state
        await self.state_tracker.set_instance_state(
            proxy_hostname=proxy_hostname,
            state=InstanceState.PENDING,
            details={
                "target_url": target_url,
                "enable_http": enable_http,
                "enable_https": enable_https
            }
        )
        
        # CRITICAL: Check if proxy already exists in storage
        existing_proxy = await self._get_proxy_target(proxy_hostname)
        if existing_proxy:
            log_info(f"[WORKFLOW] {proxy_hostname} already exists in storage", component="workflow")
            
            # Check if certificate exists and is ready
            cert_ready = False
            if existing_proxy.cert_name:
                cert = await self._get_certificate(existing_proxy.cert_name)
                if cert and cert.status == 'active':
                    cert_ready = True
                    log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
                elif cert and cert.status == 'pending':
                    log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
                else:
                    log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
            
            # Check what instances exist
            # For now, just proceed with port allocation
            await self.publisher.publish_event("allocate_ports_requested", {
                "proxy_hostname": proxy_hostname,
                "enable_http": existing_proxy.enable_http,
                "enable_https": existing_proxy.enable_https,
                "cert_ready": cert_ready,
                "cert_name": existing_proxy.cert_name
            })
            return
        
        # Proxy doesn't exist - this shouldn't happen as API creates it first
        # But handle it anyway for completeness
        log_warning(f"[WORKFLOW] Proxy {proxy_hostname} not found in storage, creating it", component="workflow")
        
        # Store proxy configuration
        from ..proxy.models import ProxyTarget
        proxy = ProxyTarget(
            proxy_hostname=proxy_hostname,
            target_url=target_url,
            enable_http=enable_http,
            enable_https=enable_https,
            cert_name=cert_name,
            owner_token_hash=owner_token_hash,
            created_by=created_by,
            created_at=datetime.now(timezone.utc)
        )
        
        if await self._store_proxy_target(proxy_hostname, proxy):
            log_info(f"[WORKFLOW] {proxy_hostname} stored successfully", component="workflow")
            
            # Publish proxy_stored event
            await self.publisher.publish_event("proxy_stored", {
                "proxy_hostname": proxy_hostname,
                "target_url": target_url,
                "enable_http": enable_http,
                "enable_https": enable_https,
                "cert_email": cert_email,
                "cert_name": cert_name
            })
        else:
            log_error(f"[WORKFLOW] Failed to store proxy {proxy_hostname}", component="workflow")
            await self.state_tracker.set_instance_state(
                proxy_hostname=proxy_hostname,
                state=InstanceState.FAILED,
                details={"error": "Failed to store proxy configuration"}
            )
    
    async def handle_proxy_stored(self, event: Dict):
        """
        Handle proxy stored event.
        
        Flow:
        1. If HTTPS enabled, request certificate
        2. Request port allocation
        """
        proxy_hostname = event.get("proxy_hostname")
        enable_https = event.get('enable_https')
        cert_email = event.get('cert_email')
        cert_name = event.get('cert_name')
        
        log_info(f"[WORKFLOW] {proxy_hostname} stored, proceeding with setup", component="workflow")
        
        # Request certificate if HTTPS is enabled
        if enable_https and cert_name:
            log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
            
            await self.state_tracker.set_pending_operation(
                proxy_hostname=proxy_hostname,
                operation="waiting_for_certificate",
                details={"cert_name": cert_name}
            )
            
            await self.publisher.publish_event("certificate_requested", {
                "proxy_hostname": proxy_hostname,
                "cert_name": cert_name,
                "cert_email": cert_email,
                "domains": [proxy_hostname]
            })
        
        # Always request port allocation (for HTTP at minimum)
        await self.publisher.publish_event("allocate_ports_requested", {
            "proxy_hostname": proxy_hostname,
            "enable_http": event.get('enable_http', True),
            "enable_https": enable_https
        })
    
    async def handle_certificate_requested(self, event: Dict):
        """
        Handle certificate request.
        
        Flow:
        1. Start async certificate generation
        2. Certificate ready event will be published when done
        """
        proxy_hostname = event.get("proxy_hostname")
        cert_name = event.get('cert_name')
        cert_email = event.get('cert_email')
        domains = event.get('domains', [proxy_hostname])
        
        log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
        
        if self.cert_manager:
            # Trigger certificate generation
            from ..certmanager.models import CertificateRequest
            cert_request = CertificateRequest(
                domain=proxy_hostname,
                email=cert_email,
                cert_name=cert_name,
                acme_directory_url=os.getenv('ACME_DIRECTORY_URL')
            )
            
            # This will publish certificate_ready when done
            from ..certmanager.async_acme import create_certificate_task
            asyncio.create_task(
                create_certificate_task(
                    self.cert_manager,
                    cert_request,
                    None  # https_server not needed
                )
            )
        else:
            log_warning(f"[WORKFLOW] No certificate manager available", component="workflow")
    
    async def handle_allocate_ports(self, event: Dict):
        """
        Handle port allocation request.
        
        Flow:
        1. Allocate HTTP port if enabled
        2. Allocate HTTPS port if enabled
        3. Publish ports_allocated event with cert status
        """
        proxy_hostname = event.get("proxy_hostname")
        enable_http = event.get('enable_http', True)
        enable_https = event.get('enable_https', True)
        cert_ready = event.get('cert_ready', False)
        cert_name = event.get('cert_name')
        
        log_info(f"[PORT_ALLOCATION] Starting port allocation for {proxy_hostname}: HTTP={enable_http}, HTTPS={enable_https}, cert_ready={cert_ready}", component="workflow")
        
        log_info(f"[WORKFLOW] {proxy_hostname} (cert_ready={cert_ready})", component="workflow")
        
        allocated = {
            'cert_ready': cert_ready,
            'cert_name': cert_name
        }
        
        # Allocate HTTP port
        if enable_http:
            # Find next available HTTP port
            while self.next_http_port in self.allocated_ports:
                self.next_http_port += 1
            
            allocated['http_port'] = self.next_http_port
            allocated['http_internal_port'] = self.next_http_port + 2000
            self.allocated_ports.add(self.next_http_port)
            self.allocated_ports.add(allocated['http_internal_port'])
            
            log_info(f"[PORT_ALLOCATION] Allocated HTTP port {allocated['http_port']} (internal: {allocated['http_internal_port']}) for {proxy_hostname}", component="workflow")
            log_info(f"[PORT_ALLOCATION] Total allocated ports: {len(self.allocated_ports)}, Next HTTP port: {self.next_http_port + 1}", component="workflow")
            
            self.next_http_port += 1
        
        # Allocate HTTPS port
        if enable_https:
            # Find next available HTTPS port
            while self.next_https_port in self.allocated_ports:
                self.next_https_port += 1
            
            allocated['https_port'] = self.next_https_port
            allocated['https_internal_port'] = self.next_https_port + 2000
            self.allocated_ports.add(self.next_https_port)
            self.allocated_ports.add(allocated['https_internal_port'])
            
            log_info(f"[PORT_ALLOCATION] Allocated HTTPS port {allocated['https_port']} (internal: {allocated['https_internal_port']}) for {proxy_hostname}", component="workflow")
            log_info(f"[PORT_ALLOCATION] Total allocated ports: {len(self.allocated_ports)}, Next HTTPS port: {self.next_https_port + 1}", component="workflow")
            
            self.next_https_port += 1
        
        # Publish ports allocated event with cert status
        log_info(f"[PORT_ALLOCATION] Publishing ports_allocated event for {proxy_hostname} with ports: {allocated}", component="workflow")
        await self.publisher.publish_event("ports_allocated", {
            "proxy_hostname": proxy_hostname,
            **allocated
        })
        
        # Also publish port_changed events for tracking
        for port_type, port in allocated.items():
            if 'internal' not in port_type and port_type not in ['cert_ready', 'cert_name', 'hostname']:
                await self.publisher.publish_port_changed(
                    port=port,
                    action="allocated",
                    service=proxy_hostname
                )
    
    async def handle_ports_allocated(self, event: Dict):
        """
        Handle ports allocated event.
        
        Flow:
        1. Create instance with allocated ports
        2. Start HTTP instance if port allocated
        3. Start HTTPS instance if cert ready, otherwise wait
        """
        proxy_hostname = event.get("proxy_hostname")
        http_port = event.get('http_port')
        https_port = event.get('https_port')
        cert_ready = event.get('cert_ready', False)
        cert_name = event.get('cert_name')
        
        log_info(f"[WORKFLOW] {proxy_hostname}, creating instances", component="workflow")
        
        # Update state
        state_details = {
            "http_port": http_port,
            "https_port": https_port,
            "cert_ready": cert_ready,
            "cert_name": cert_name
        }
        
        # Determine initial state based on what's being started
        if http_port and not https_port:
            await self.state_tracker.set_instance_state(
                proxy_hostname=proxy_hostname,
                state=InstanceState.HTTP_ONLY,
                details=state_details
            )
        elif https_port and not http_port:
            # This would be unusual, but handle it
            await self.state_tracker.set_instance_state(
                proxy_hostname=proxy_hostname,
                state=InstanceState.PENDING,
                details=state_details
            )
        else:
            # Both HTTP and HTTPS planned
            await self.state_tracker.set_instance_state(
                proxy_hostname=proxy_hostname,
                state=InstanceState.PENDING,
                details=state_details
            )
        
        # Trigger HTTP instance creation if port allocated
        if http_port:
            await self.publisher.publish_event("create_http_instance", {
                "proxy_hostname": proxy_hostname,
                "http_port": http_port,
                "http_internal_port": event.get('http_internal_port')
            })
        
        # Handle HTTPS based on certificate readiness
        if https_port:
            if cert_ready:
                # Certificate is already ready, start HTTPS immediately!
                log_info(f"[WORKFLOW] {proxy_hostname}, creating HTTPS instance immediately", component="workflow")
                await self.publisher.publish_event("create_https_instance", {
                    "proxy_hostname": proxy_hostname,
                    "https_port": https_port,
                    "https_internal_port": event.get('https_internal_port'),
                    "cert_name": cert_name
                })
            else:
                # Need to wait for certificate
                pending_op = await self.state_tracker.get_pending_operation(proxy_hostname)
                if pending_op and pending_op.get('operation') == 'waiting_for_certificate':
                    log_info(f"[WORKFLOW] {proxy_hostname}, waiting for certificate", component="workflow")
                else:
                    # Check if certificate exists now (race condition handling)
                    proxy = await self._get_proxy_target(proxy_hostname)
                    if proxy and proxy.cert_name:
                        cert = await self._get_certificate(proxy.cert_name)
                        if cert and cert.status == 'active':
                            # Certificate became ready, start HTTPS
                            log_info(f"[WORKFLOW] {proxy_hostname}, creating HTTPS instance", component="workflow")
                            await self.publisher.publish_event("create_https_instance", {
                                "proxy_hostname": proxy_hostname,
                                "https_port": https_port,
                                "https_internal_port": event.get('https_internal_port'),
                                "cert_name": proxy.cert_name
                            })
                        else:
                            log_info(f"[WORKFLOW] {proxy_hostname}, will wait", component="workflow")
    
    async def handle_http_instance_started(self, event: Dict):
        """
        Handle HTTP instance started event.
        
        Flow:
        1. Register HTTP routes
        2. Update instance state
        3. Check if waiting for HTTPS
        """
        proxy_hostname = event.get("proxy_hostname")
        http_port = event.get('port')
        
        log_info(f"[WORKFLOW] {proxy_hostname} on port {http_port}", component="workflow")
        
        # Register HTTP route if dispatcher available
        # Note: self.dispatcher is actually the UnifiedMultiInstanceServer
        # The actual dispatcher is self.dispatcher.dispatcher
        if self.dispatcher and hasattr(self.dispatcher, 'dispatcher'):
            self.dispatcher.dispatcher.register_domain(
                [proxy_hostname],
                http_port,
                0,  # No HTTPS port yet
                enable_http=True,
                enable_https=False
            )
            
            log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
        
        # Update state based on what's pending
        pending_op = await self.state_tracker.get_pending_operation(proxy_hostname)
        if pending_op and pending_op.get('operation') == 'waiting_for_certificate':
            # Still waiting for certificate
            await self.state_tracker.set_instance_state(
                proxy_hostname=proxy_hostname,
                state=InstanceState.HTTP_ONLY,
                details={"http_port": http_port, "waiting_for": "certificate"}
            )
        else:
            # Check if HTTPS is expected
            proxy = await self._get_proxy_target(proxy_hostname)
            if proxy and proxy.enable_https:
                await self.state_tracker.set_instance_state(
                    proxy_hostname=proxy_hostname,
                    state=InstanceState.HTTP_ONLY,
                    details={"http_port": http_port}
                )
            else:
                # Only HTTP was requested, we're done
                await self.state_tracker.set_instance_state(
                    proxy_hostname=proxy_hostname,
                    state=InstanceState.FULLY_RUNNING,
                    details={"http_port": http_port}
                )
                
                await self.publisher.publish_event("instance_fully_operational", {
                    "proxy_hostname": proxy_hostname,
                    "http_port": http_port,
                    "https_port": None
                })
    
    async def handle_certificate_ready_workflow(self, event: Dict):
        """
        Handle certificate ready event in workflow context.
        
        Flow:
        1. Clear waiting_for_certificate operation
        2. Start HTTPS instance if ports allocated
        3. Update state
        """
        cert_name = event.get('cert_name')
        domains = event.get('domains', [])
        
        log_info(f"[WORKFLOW] Certificate {cert_name} ready for domains {domains}", component="workflow")
        
        for proxy_hostname in domains:
            # Clear pending operation
            await self.state_tracker.clear_pending_operation(proxy_hostname)
            
            # Get current state
            state_data = await self.state_tracker.get_instance_state(proxy_hostname)
            if not state_data:
                log_warning(f"[WORKFLOW] No state found for {proxy_hostname}", component="workflow")
                continue
            
            # Check if HTTPS port was allocated
            https_port = state_data.get('details', {}).get('https_port')
            if https_port:
                log_info(f"[WORKFLOW] {proxy_hostname} on port {https_port}", component="workflow")
                
                await self.publisher.publish_event("create_https_instance", {
                    "proxy_hostname": proxy_hostname,
                    "https_port": https_port,
                    "https_internal_port": https_port + 2000,
                    "cert_name": cert_name
                })
            else:
                log_warning(f"[WORKFLOW] No HTTPS port allocated for {proxy_hostname}", component="workflow")
    
    async def handle_https_instance_started(self, event: Dict):
        """
        Handle HTTPS instance started event.
        
        Flow:
        1. Register HTTPS routes
        2. Update instance state to fully running
        3. Publish completion event
        """
        proxy_hostname = event.get("proxy_hostname")
        https_port = event.get('port')
        
        log_info(f"[WORKFLOW] {proxy_hostname} on port {https_port}", component="workflow")
        
        # Register HTTPS route if dispatcher available
        # Note: self.dispatcher is actually the UnifiedMultiInstanceServer
        # The actual dispatcher is self.dispatcher.dispatcher
        if self.dispatcher and hasattr(self.dispatcher, 'dispatcher'):
            # Get HTTP port from state
            state_data = await self.state_tracker.get_instance_state(proxy_hostname)
            http_port = state_data.get('details', {}).get('http_port', 0)
            
            # Update registration to include HTTPS
            self.dispatcher.dispatcher.register_domain(
                [proxy_hostname],
                http_port,
                https_port,
                enable_http=bool(http_port),
                enable_https=True
            )
            
            log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
        
        # Update state to fully running
        state_data = await self.state_tracker.get_instance_state(proxy_hostname)
        details = state_data.get('details', {})
        details['https_port'] = https_port
        
        await self.state_tracker.set_instance_state(
            proxy_hostname=proxy_hostname,
            state=InstanceState.FULLY_RUNNING,
            details=details
        )
        
        # Publish completion event
        await self.publisher.publish_event("instance_fully_operational", {
            "proxy_hostname": proxy_hostname,
            "http_port": details.get('http_port'),
            "https_port": https_port
        })
        
        log_info(f"[WORKFLOW] {proxy_hostname} is fully operational", component="workflow")
    
    async def handle_instance_failed(self, event: Dict):
        """
        Handle instance failure event.
        
        Flow:
        1. Update state to failed
        2. Release allocated ports
        3. Clean up partial resources
        """
        proxy_hostname = event.get("proxy_hostname")
        error = event.get('error')
        instance_type = event.get('instance_type')
        
        log_error(f"[WORKFLOW] Instance {instance_type} failed for {proxy_hostname}: {error}", component="workflow")
        
        # Update state
        await self.state_tracker.set_instance_state(
            proxy_hostname=proxy_hostname,
            state=InstanceState.FAILED,
            details={"error": error, "failed_component": instance_type}
        )
        
        # Get allocated ports from state
        state_data = await self.state_tracker.get_instance_state(proxy_hostname)
        if state_data:
            details = state_data.get('details', {})
            
            # Release allocated ports
            for port_key in ['http_port', 'https_port', 'http_internal_port', 'https_internal_port']:
                port = details.get(port_key)
                if port and port in self.allocated_ports:
                    self.allocated_ports.discard(port)
                    
                    await self.publisher.publish_port_changed(
                        port=port,
                        action="released",
                        service=proxy_hostname
                    )
                    
                    log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
        
        # TODO: Clean up any partial resources (routes, instances, etc.)
    
    async def handle_create_http_instance(self, event: Dict):
        """
        Handle HTTP instance creation request.
        
        This event is triggered when ports are allocated and we need to create the HTTP instance.
        """
        proxy_hostname = event.get("proxy_hostname")
        http_port = event.get('http_port')
        http_internal_port = event.get('http_internal_port', http_port)
        
        log_info(f"[WORKFLOW] Creating HTTP instance for {proxy_hostname} on port {http_port}", component="workflow")
        logger.info(f"[WORKFLOW] Dispatcher check: self.dispatcher={self.dispatcher}, type={type(self.dispatcher) if self.dispatcher else 'None'}")
        
        if self.dispatcher:
            logger.info(f"[WORKFLOW] Dispatcher is available: {type(self.dispatcher).__name__}")
            try:
                # The dispatcher's create_instance_for_proxy only takes proxy_hostname
                # It will handle port allocation and instance creation internally
                logger.info(f"[WORKFLOW] Calling dispatcher.create_instance_for_proxy({proxy_hostname})")
                result = await self.dispatcher.create_instance_for_proxy(proxy_hostname)
                logger.info(f"[WORKFLOW] dispatcher.create_instance_for_proxy completed for {proxy_hostname}, result={result}")
                # Dispatcher publishes http_instance_started event
                log_trace(f"[WORKFLOW] HTTP instance creation delegated to dispatcher for {proxy_hostname}", component="workflow")
                
                log_info(f"[WORKFLOW] HTTP instance created for {proxy_hostname}", component="workflow")
                
            except Exception as e:
                logger.error(f"[WORKFLOW] Exception in create_instance_for_proxy: {e}", exc_info=True)
                log_error(f"[WORKFLOW] Failed to create HTTP instance for {proxy_hostname}: {e}", component="workflow", error=e)
                import traceback
                log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")
                await self.publisher.publish_instance_failed(
                    proxy_hostname=proxy_hostname,
                    instance_type="http",
                    error=str(e)
                )
        else:
            logger.error(f"[WORKFLOW] No dispatcher available! self.dispatcher is None")
            log_error(f"[WORKFLOW] No dispatcher available to create HTTP instance for {proxy_hostname}", component="workflow")
    
    async def handle_create_https_instance(self, event: Dict):
        """
        Handle HTTPS instance creation request.
        
        This event is triggered when a certificate is ready and we need to create the HTTPS instance.
        """
        proxy_hostname = event.get("proxy_hostname")
        https_port = event.get('https_port')
        https_internal_port = event.get('https_internal_port', https_port)
        cert_name = event.get('cert_name')
        force_recreate = event.get('force_recreate', False)
        
        log_info(f"[WORKFLOW] {proxy_hostname} on port {https_port} with cert {cert_name}", component="workflow")
        
        # Verify certificate exists and is active
        cert = await self._get_certificate(cert_name)
        cert_status = cert.get('status') if isinstance(cert, dict) else getattr(cert, 'status', None)
        if not cert or cert_status != 'active':
            log_error(f"[WORKFLOW] Certificate {cert_name} not ready for {proxy_hostname}", component="workflow")
            await self.publisher.publish_instance_failed(
                proxy_hostname=proxy_hostname,
                instance_type="https",
                error=f"Certificate {cert_name} not active"
            )
            return
        
        if self.dispatcher:
            try:
                # If this is a certificate update, call update_ssl_context on dispatcher
                if force_recreate and hasattr(self.dispatcher, 'update_ssl_context'):
                    log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
                    # Convert cert dict to object if needed
                    self.dispatcher.update_ssl_context(cert)
                else:
                    # The dispatcher's create_instance_for_proxy only takes proxy_hostname
                    # If an HTTP instance already exists, it will upgrade it to HTTPS
                    # If not, it will create a new HTTPS-only instance
                    await self.dispatcher.create_instance_for_proxy(proxy_hostname)
                
                # Publish success event
                # Dispatcher handles publishing https_instance_started
                
                log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
                
            except Exception as e:
                log_error(f"[WORKFLOW] Failed to create HTTPS instance for {proxy_hostname}: {e}", component="workflow", error=e)
                import traceback
                log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")
                await self.publisher.publish_instance_failed(
                    proxy_hostname=proxy_hostname,
                    instance_type="https",
                    error=str(e)
                )
        else:
            log_error(f"[WORKFLOW] No dispatcher available to create HTTPS instance for {proxy_hostname}", component="workflow")
    
    async def handle_certificate_renewal(self, event: Dict):
        """
        Handle certificate renewal request.
        
        This starts the renewal process for a certificate.
        """
        cert_name = event.get('cert_name')
        force = event.get('force', False)
        
        log_info(f"[WORKFLOW] Processing certificate renewal for {cert_name}", component="workflow")
        
        if self.cert_manager:
            try:
                # Start renewal process
                await self.cert_manager.renew_certificate(cert_name, force)
                
                # The cert_manager will publish certificate_renewed when done
                log_info(f"[WORKFLOW] Certificate renewal initiated for {cert_name}", component="workflow")
                
            except Exception as e:
                log_error(f"[WORKFLOW] Failed to start renewal for {cert_name}: {e}", component="workflow", error=e)
                import traceback
                log_debug(f"[WORKFLOW] Stack trace: {traceback.format_exc()}", component="workflow")
                await self.publisher.publish_event("certificate_renewal_failed", {
                    "cert_name": cert_name,
                    "error": str(e)
                })
        else:
            log_error(f"[WORKFLOW] No certificate manager available for renewal", component="workflow")
    
    async def handle_certificate_renewed(self, event: Dict):
        """
        Handle certificate renewed event.
        
        Updates SSL contexts for all affected instances.
        """
        cert_name = event.get('cert_name')
        domains = event.get('domains', [])
        
        log_info(f"[WORKFLOW] Certificate {cert_name} renewed, updating instances", component="workflow")
        
        # Find all proxies using this certificate
        for proxy_hostname in domains:
            proxy = await self._get_proxy_target(proxy_hostname)
            if proxy and proxy.cert_name == cert_name:
                # Trigger SSL context reload
                if self.dispatcher:
                    await self.dispatcher.reload_ssl_context(proxy_hostname)
                    log_info(f"[WORKFLOW] {proxy_hostname}", component="workflow")
        
        # Publish completion event
        await self.publisher.publish_event("certificate_renewal_complete", {
            "cert_name": cert_name,
            "domains": domains
        })
    
    async def handle_staging_to_production(self, event: Dict):
        """
        Handle staging to production certificate conversion.
        """
        cert_name = event.get('cert_name')
        
        log_info(f"[WORKFLOW] Converting {cert_name} from staging to production", component="workflow")
        
        # Get current certificate
        cert = await self._get_certificate(cert_name)
        if not cert:
            log_error(f"[WORKFLOW] Certificate {cert_name} not found", component="workflow")
            return
        
        # Backup staging certificate
        staging_backup = f"{cert_name}-staging-backup"
        await self._store_certificate(staging_backup, cert)
        
        # Trigger production certificate generation
        from ..certmanager.models import CertificateRequest
        prod_request = CertificateRequest(
            domain=cert.domains[0] if cert.domains else "",
            domains=cert.domains,
            email=cert.email,
            cert_name=cert_name,
            acme_directory_url=os.getenv('ACME_DIRECTORY_URL', 'https://acme-v02.api.letsencrypt.org/directory')
        )
        
        # This will publish production_certificate_ready when done
        if self.cert_manager:
            from ..certmanager.async_acme import create_certificate_task
            asyncio.create_task(
                create_certificate_task(
                    self.cert_manager,
                    prod_request,
                    None
                )
            )
    
    async def handle_certificate_updated(self, event: Dict):
        """
        Handle certificate update event (e.g., after staging to production conversion).
        
        This triggers the dispatcher to update the SSL context for the instance.
        """
        proxy_hostname = event.get("proxy_hostname")
        cert_name = event.get('cert_name')
        action = event.get('action', 'reload_ssl_context')
        
        log_info(f"[WORKFLOW] {proxy_hostname}, action: {action}", component="workflow")
        
        if action == 'reload_ssl_context':
            # Get the updated certificate
            cert = await self._get_certificate(cert_name)
            if not cert:
                log_error(f"[WORKFLOW] Certificate {cert_name} not found for SSL context reload", component="workflow")
                return
            
            cert_status = cert.get('status') if isinstance(cert, dict) else getattr(cert, 'status', None)
            if cert_status != 'active':
                log_warning(f"[WORKFLOW] Certificate {cert_name} not active, skipping SSL reload", component="workflow")
                return
            
            # Trigger instance recreation with new certificate
            # The dispatcher's update_ssl_context method requires direct access
            # So we'll trigger a create_https_instance event which will recreate with new cert
            log_info(f"[WORKFLOW] {proxy_hostname} with updated cert {cert_name}", component="workflow")
            
            # Get current state to preserve port allocation
            state_data = await self.state_tracker.get_instance_state(proxy_hostname)
            https_port = state_data.get('details', {}).get('https_port', 443) if state_data else 443
            
            # Recreate HTTPS instance with updated certificate
            await self.publisher.publish_event("create_https_instance", {
                "proxy_hostname": proxy_hostname,
                "cert_name": cert_name,
                "https_port": https_port,
                "https_internal_port": https_port + 2000 if https_port != 443 else 11443,
                "force_recreate": True  # Signal to force recreation
            })
    
    async def handle_production_cert_ready(self, event: Dict):
        """
        Handle production certificate ready after staging conversion.
        """
        cert_name = event.get('cert_name')
        domains = event.get('domains', [])
        
        log_info(f"[WORKFLOW] Production certificate {cert_name} ready, updating instances", component="workflow")
        
        # Update all affected instances
        for proxy_hostname in domains:
            proxy = await self._get_proxy_target(proxy_hostname)
            if proxy and proxy.cert_name == cert_name:
                # Reload SSL context with new production cert
                if self.dispatcher:
                    await self.dispatcher.reload_ssl_context(proxy_hostname)
                    log_info(f"[WORKFLOW] {proxy_hostname} to production certificate", component="workflow")
        
        # Publish completion event
        await self.publisher.publish_event("staging_to_production_complete", {
            "cert_name": cert_name,
            "domains": domains
        })
    
    async def close(self):
        """Clean up resources."""
        log_info("[WORKFLOW] Shutting down workflow orchestrator", component="workflow")
        
        # Cancel consumer tasks
        if hasattr(self, 'consumer_task'):
            self.consumer_task.cancel()
            try:
                await self.consumer_task
            except asyncio.CancelledError:
                pass
                
        if hasattr(self, 'pending_task'):
            self.pending_task.cancel()
            try:
                await self.pending_task
            except asyncio.CancelledError:
                pass
        
        await self.publisher.close()
        await self.state_tracker.close()
        await self.consumer.stop()
        
        log_info("[WORKFLOW] Workflow orchestrator shutdown complete", component="workflow")