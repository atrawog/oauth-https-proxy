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
from typing import Dict, Optional, Any
from datetime import datetime, timezone

from ..storage.redis_stream_publisher import RedisStreamPublisher
from ..storage.instance_state import InstanceStateTracker, InstanceState
from ..dispatcher.redis_stream_consumer import RedisStreamConsumer

logger = logging.getLogger(__name__)


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
    
    async def _get_proxy_target(self, hostname: str):
        """Get proxy target using async storage if available."""
        if self.async_storage:
            return await self.async_storage.get_proxy_target(hostname)
        return self.storage.get_proxy_target(hostname)
    
    async def _get_certificate(self, cert_name: str):
        """Get certificate using async storage if available."""
        if self.async_storage:
            return await self.async_storage.get_certificate(cert_name)
        return self.storage.get_certificate(cert_name)
    
    async def _store_proxy_target(self, hostname: str, proxy):
        """Store proxy target using async storage if available."""
        if self.async_storage:
            return await self.async_storage.store_proxy_target(hostname, proxy)
        return self.storage.store_proxy_target(hostname, proxy)
    
    async def _store_certificate(self, cert_name: str, cert):
        """Store certificate using async storage if available."""
        if self.async_storage:
            return await self.async_storage.store_certificate(cert_name, cert)
        return self.storage.store_certificate(cert_name, cert)
    
    async def start(self):
        """Start the workflow orchestrator."""
        # Force immediate flush to ensure logs appear
        import sys
        logger.info("[WORKFLOW] Starting workflow orchestrator initialization")
        sys.stderr.flush()
        sys.stdout.flush()
        
        await self.consumer.initialize()
        logger.info("[WORKFLOW] Consumer initialized")
        # Publisher and state tracker don't need initialization - they connect on first use
        
        # Start consuming workflow events
        self.consumer_task = asyncio.create_task(
            self.consumer.consume_events(self.handle_workflow_event)
        )
        logger.info("[WORKFLOW] Consumer task created")
        
        # Start handling pending messages
        self.pending_task = asyncio.create_task(
            self.consumer.claim_pending_messages(idle_time_ms=30000)  # 30 seconds
        )
        logger.info("[WORKFLOW] Pending task created")
        
        logger.info("[WORKFLOW] Instance workflow orchestrator started with event processing")
        sys.stderr.flush()
        sys.stdout.flush()
    
    async def handle_workflow_event(self, event: Dict[str, Any]):
        """
        Handle workflow events and trigger appropriate actions.
        
        Args:
            event: Event data from Redis Stream
        """
        import sys
        event_type = event.get('type')
        hostname = event.get('hostname')
        
        logger.info(f"[WORKFLOW] Processing {event_type} for {hostname}")
        print(f"[WORKFLOW] Processing {event_type} for {hostname}", file=sys.stderr)
        sys.stderr.flush()
        
        try:
            # Critical fix: Actually handle the events!
            if event_type == 'proxy_creation_requested':
                await self.handle_proxy_creation_requested(event)
                
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
                
            else:
                logger.debug(f"[WORKFLOW] Unhandled event type: {event_type}")
                
        except Exception as e:
            logger.error(f"[WORKFLOW] Error handling {event_type} for {hostname}: {e}", exc_info=True)
            
            # Publish failure event
            await self.publisher.publish_instance_failed(
                hostname=hostname,
                instance_type="workflow",
                error=str(e)
            )
    
    async def handle_proxy_creation_requested(self, event: Dict):
        """
        Handle proxy creation request.
        
        Flow:
        1. Analyze existing resources (proxy, cert, instances)
        2. Determine what needs to be created
        3. Orchestrate creation in correct order
        """
        hostname = event.get('hostname')
        target_url = event.get('target_url')
        enable_http = event.get('enable_http', True)
        enable_https = event.get('enable_https', True)
        cert_email = event.get('cert_email')
        cert_name = event.get('cert_name')
        owner_token_hash = event.get('owner_token_hash')
        created_by = event.get('created_by')
        
        logger.info(f"[WORKFLOW] Analyzing resources for proxy creation: {hostname}")
        
        # Set initial state
        await self.state_tracker.set_instance_state(
            hostname=hostname,
            state=InstanceState.PENDING,
            details={
                "target_url": target_url,
                "enable_http": enable_http,
                "enable_https": enable_https
            }
        )
        
        # CRITICAL: Check if proxy already exists in storage
        existing_proxy = await self._get_proxy_target(hostname)
        if existing_proxy:
            logger.info(f"[WORKFLOW] Proxy {hostname} already exists in storage")
            
            # Check if certificate exists and is ready
            cert_ready = False
            if existing_proxy.cert_name:
                cert = await self._get_certificate(existing_proxy.cert_name)
                if cert and cert.status == 'active':
                    cert_ready = True
                    logger.info(f"[WORKFLOW] Certificate {existing_proxy.cert_name} is ready for {hostname}")
                elif cert and cert.status == 'pending':
                    logger.info(f"[WORKFLOW] Certificate {existing_proxy.cert_name} is still pending for {hostname}")
                else:
                    logger.info(f"[WORKFLOW] Certificate {existing_proxy.cert_name} not found or failed for {hostname}")
            
            # Check what instances exist
            # For now, just proceed with port allocation
            await self.publisher.publish_event("allocate_ports_requested", {
                "hostname": hostname,
                "enable_http": existing_proxy.enable_http,
                "enable_https": existing_proxy.enable_https,
                "cert_ready": cert_ready,
                "cert_name": existing_proxy.cert_name
            })
            return
        
        # Proxy doesn't exist - this shouldn't happen as API creates it first
        # But handle it anyway for completeness
        logger.warning(f"[WORKFLOW] Proxy {hostname} not found in storage, creating it")
        
        # Store proxy configuration
        from ..proxy.models import ProxyTarget
        proxy = ProxyTarget(
            hostname=hostname,
            target_url=target_url,
            enable_http=enable_http,
            enable_https=enable_https,
            cert_name=cert_name,
            owner_token_hash=owner_token_hash,
            created_by=created_by,
            created_at=datetime.now(timezone.utc)
        )
        
        if await self._store_proxy_target(hostname, proxy):
            logger.info(f"[WORKFLOW] Proxy {hostname} stored successfully")
            
            # Publish proxy_stored event
            await self.publisher.publish_event("proxy_stored", {
                "hostname": hostname,
                "target_url": target_url,
                "enable_http": enable_http,
                "enable_https": enable_https,
                "cert_email": cert_email,
                "cert_name": cert_name
            })
        else:
            logger.error(f"[WORKFLOW] Failed to store proxy {hostname}")
            await self.state_tracker.set_instance_state(
                hostname=hostname,
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
        hostname = event.get('hostname')
        enable_https = event.get('enable_https')
        cert_email = event.get('cert_email')
        cert_name = event.get('cert_name')
        
        logger.info(f"[WORKFLOW] Proxy {hostname} stored, proceeding with setup")
        
        # Request certificate if HTTPS is enabled
        if enable_https and cert_name:
            logger.info(f"[WORKFLOW] Requesting certificate for {hostname}")
            
            await self.state_tracker.set_pending_operation(
                hostname=hostname,
                operation="waiting_for_certificate",
                details={"cert_name": cert_name}
            )
            
            await self.publisher.publish_event("certificate_requested", {
                "hostname": hostname,
                "cert_name": cert_name,
                "cert_email": cert_email,
                "domains": [hostname]
            })
        
        # Always request port allocation (for HTTP at minimum)
        await self.publisher.publish_event("allocate_ports_requested", {
            "hostname": hostname,
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
        hostname = event.get('hostname')
        cert_name = event.get('cert_name')
        cert_email = event.get('cert_email')
        domains = event.get('domains', [hostname])
        
        logger.info(f"[WORKFLOW] Starting certificate generation for {hostname}")
        
        if self.cert_manager:
            # Trigger certificate generation
            from ..certmanager.models import CertificateRequest
            cert_request = CertificateRequest(
                domain=hostname,
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
            logger.warning(f"[WORKFLOW] No certificate manager available")
    
    async def handle_allocate_ports(self, event: Dict):
        """
        Handle port allocation request.
        
        Flow:
        1. Allocate HTTP port if enabled
        2. Allocate HTTPS port if enabled
        3. Publish ports_allocated event with cert status
        """
        hostname = event.get('hostname')
        enable_http = event.get('enable_http', True)
        enable_https = event.get('enable_https', True)
        cert_ready = event.get('cert_ready', False)
        cert_name = event.get('cert_name')
        
        logger.info(f"[WORKFLOW] Allocating ports for {hostname} (cert_ready={cert_ready})")
        
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
            self.next_http_port += 1
            
            logger.info(f"[WORKFLOW] Allocated HTTP port {allocated['http_port']} for {hostname}")
        
        # Allocate HTTPS port
        if enable_https:
            # Find next available HTTPS port
            while self.next_https_port in self.allocated_ports:
                self.next_https_port += 1
            
            allocated['https_port'] = self.next_https_port
            allocated['https_internal_port'] = self.next_https_port + 2000
            self.allocated_ports.add(self.next_https_port)
            self.allocated_ports.add(allocated['https_internal_port'])
            self.next_https_port += 1
            
            logger.info(f"[WORKFLOW] Allocated HTTPS port {allocated['https_port']} for {hostname}")
        
        # Publish ports allocated event with cert status
        await self.publisher.publish_event("ports_allocated", {
            "hostname": hostname,
            **allocated
        })
        
        # Also publish port_changed events for tracking
        for port_type, port in allocated.items():
            if 'internal' not in port_type and port_type not in ['cert_ready', 'cert_name', 'hostname']:
                await self.publisher.publish_port_changed(
                    port=port,
                    action="allocated",
                    service=hostname
                )
    
    async def handle_ports_allocated(self, event: Dict):
        """
        Handle ports allocated event.
        
        Flow:
        1. Create instance with allocated ports
        2. Start HTTP instance if port allocated
        3. Start HTTPS instance if cert ready, otherwise wait
        """
        hostname = event.get('hostname')
        http_port = event.get('http_port')
        https_port = event.get('https_port')
        cert_ready = event.get('cert_ready', False)
        cert_name = event.get('cert_name')
        
        logger.info(f"[WORKFLOW] Ports allocated for {hostname}, creating instances")
        
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
                hostname=hostname,
                state=InstanceState.HTTP_ONLY,
                details=state_details
            )
        elif https_port and not http_port:
            # This would be unusual, but handle it
            await self.state_tracker.set_instance_state(
                hostname=hostname,
                state=InstanceState.PENDING,
                details=state_details
            )
        else:
            # Both HTTP and HTTPS planned
            await self.state_tracker.set_instance_state(
                hostname=hostname,
                state=InstanceState.PENDING,
                details=state_details
            )
        
        # Trigger HTTP instance creation if port allocated
        if http_port:
            await self.publisher.publish_event("create_http_instance", {
                "hostname": hostname,
                "http_port": http_port,
                "http_internal_port": event.get('http_internal_port')
            })
        
        # Handle HTTPS based on certificate readiness
        if https_port:
            if cert_ready:
                # Certificate is already ready, start HTTPS immediately!
                logger.info(f"[WORKFLOW] Certificate ready for {hostname}, creating HTTPS instance immediately")
                await self.publisher.publish_event("create_https_instance", {
                    "hostname": hostname,
                    "https_port": https_port,
                    "https_internal_port": event.get('https_internal_port'),
                    "cert_name": cert_name
                })
            else:
                # Need to wait for certificate
                pending_op = await self.state_tracker.get_pending_operation(hostname)
                if pending_op and pending_op.get('operation') == 'waiting_for_certificate':
                    logger.info(f"[WORKFLOW] HTTPS port allocated for {hostname}, waiting for certificate")
                else:
                    # Check if certificate exists now (race condition handling)
                    proxy = await self._get_proxy_target(hostname)
                    if proxy and proxy.cert_name:
                        cert = await self._get_certificate(proxy.cert_name)
                        if cert and cert.status == 'active':
                            # Certificate became ready, start HTTPS
                            logger.info(f"[WORKFLOW] Certificate now ready for {hostname}, creating HTTPS instance")
                            await self.publisher.publish_event("create_https_instance", {
                                "hostname": hostname,
                                "https_port": https_port,
                                "https_internal_port": event.get('https_internal_port'),
                                "cert_name": proxy.cert_name
                            })
                        else:
                            logger.info(f"[WORKFLOW] Certificate {proxy.cert_name} not ready for {hostname}, will wait")
    
    async def handle_http_instance_started(self, event: Dict):
        """
        Handle HTTP instance started event.
        
        Flow:
        1. Register HTTP routes
        2. Update instance state
        3. Check if waiting for HTTPS
        """
        hostname = event.get('hostname')
        http_port = event.get('port')
        
        logger.info(f"[WORKFLOW] HTTP instance started for {hostname} on port {http_port}")
        
        # Register HTTP route if dispatcher available
        # Note: self.dispatcher is actually the UnifiedMultiInstanceServer
        # The actual dispatcher is self.dispatcher.dispatcher
        if self.dispatcher and hasattr(self.dispatcher, 'dispatcher'):
            self.dispatcher.dispatcher.register_domain(
                [hostname],
                http_port,
                0,  # No HTTPS port yet
                enable_http=True,
                enable_https=False
            )
            
            logger.info(f"[WORKFLOW] HTTP route registered for {hostname}")
        
        # Update state based on what's pending
        pending_op = await self.state_tracker.get_pending_operation(hostname)
        if pending_op and pending_op.get('operation') == 'waiting_for_certificate':
            # Still waiting for certificate
            await self.state_tracker.set_instance_state(
                hostname=hostname,
                state=InstanceState.HTTP_ONLY,
                details={"http_port": http_port, "waiting_for": "certificate"}
            )
        else:
            # Check if HTTPS is expected
            proxy = await self._get_proxy_target(hostname)
            if proxy and proxy.enable_https:
                await self.state_tracker.set_instance_state(
                    hostname=hostname,
                    state=InstanceState.HTTP_ONLY,
                    details={"http_port": http_port}
                )
            else:
                # Only HTTP was requested, we're done
                await self.state_tracker.set_instance_state(
                    hostname=hostname,
                    state=InstanceState.FULLY_RUNNING,
                    details={"http_port": http_port}
                )
                
                await self.publisher.publish_event("instance_fully_operational", {
                    "hostname": hostname,
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
        
        logger.info(f"[WORKFLOW] Certificate {cert_name} ready for domains {domains}")
        
        for hostname in domains:
            # Clear pending operation
            await self.state_tracker.clear_pending_operation(hostname)
            
            # Get current state
            state_data = await self.state_tracker.get_instance_state(hostname)
            if not state_data:
                logger.warning(f"[WORKFLOW] No state found for {hostname}")
                continue
            
            # Check if HTTPS port was allocated
            https_port = state_data.get('details', {}).get('https_port')
            if https_port:
                logger.info(f"[WORKFLOW] Starting HTTPS for {hostname} on port {https_port}")
                
                await self.publisher.publish_event("create_https_instance", {
                    "hostname": hostname,
                    "https_port": https_port,
                    "https_internal_port": https_port + 2000,
                    "cert_name": cert_name
                })
            else:
                logger.warning(f"[WORKFLOW] No HTTPS port allocated for {hostname}")
    
    async def handle_https_instance_started(self, event: Dict):
        """
        Handle HTTPS instance started event.
        
        Flow:
        1. Register HTTPS routes
        2. Update instance state to fully running
        3. Publish completion event
        """
        hostname = event.get('hostname')
        https_port = event.get('port')
        
        logger.info(f"[WORKFLOW] HTTPS instance started for {hostname} on port {https_port}")
        
        # Register HTTPS route if dispatcher available
        # Note: self.dispatcher is actually the UnifiedMultiInstanceServer
        # The actual dispatcher is self.dispatcher.dispatcher
        if self.dispatcher and hasattr(self.dispatcher, 'dispatcher'):
            # Get HTTP port from state
            state_data = await self.state_tracker.get_instance_state(hostname)
            http_port = state_data.get('details', {}).get('http_port', 0)
            
            # Update registration to include HTTPS
            self.dispatcher.dispatcher.register_domain(
                [hostname],
                http_port,
                https_port,
                enable_http=bool(http_port),
                enable_https=True
            )
            
            logger.info(f"[WORKFLOW] HTTPS route registered for {hostname}")
        
        # Update state to fully running
        state_data = await self.state_tracker.get_instance_state(hostname)
        details = state_data.get('details', {})
        details['https_port'] = https_port
        
        await self.state_tracker.set_instance_state(
            hostname=hostname,
            state=InstanceState.FULLY_RUNNING,
            details=details
        )
        
        # Publish completion event
        await self.publisher.publish_event("instance_fully_operational", {
            "hostname": hostname,
            "http_port": details.get('http_port'),
            "https_port": https_port
        })
        
        logger.info(f"[WORKFLOW] Instance {hostname} is fully operational")
    
    async def handle_instance_failed(self, event: Dict):
        """
        Handle instance failure event.
        
        Flow:
        1. Update state to failed
        2. Release allocated ports
        3. Clean up partial resources
        """
        hostname = event.get('hostname')
        error = event.get('error')
        instance_type = event.get('instance_type')
        
        logger.error(f"[WORKFLOW] Instance {instance_type} failed for {hostname}: {error}")
        
        # Update state
        await self.state_tracker.set_instance_state(
            hostname=hostname,
            state=InstanceState.FAILED,
            details={"error": error, "failed_component": instance_type}
        )
        
        # Get allocated ports from state
        state_data = await self.state_tracker.get_instance_state(hostname)
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
                        service=hostname
                    )
                    
                    logger.info(f"[WORKFLOW] Released port {port} for failed instance {hostname}")
        
        # TODO: Clean up any partial resources (routes, instances, etc.)
    
    async def handle_create_http_instance(self, event: Dict):
        """
        Handle HTTP instance creation request.
        
        This event is triggered when ports are allocated and we need to create the HTTP instance.
        """
        hostname = event.get('hostname')
        http_port = event.get('http_port')
        http_internal_port = event.get('http_internal_port', http_port)
        
        logger.info(f"[WORKFLOW] Creating HTTP instance for {hostname} on port {http_port}")
        
        if self.dispatcher:
            try:
                # The dispatcher's create_instance_for_proxy only takes hostname
                # It will handle port allocation and instance creation internally
                await self.dispatcher.create_instance_for_proxy(hostname)
                
                # Publish success event
                await self.publisher.publish_event("http_instance_started", {
                    "hostname": hostname,
                    "port": http_port,
                    "internal_port": http_internal_port
                })
                
                logger.info(f"[WORKFLOW] HTTP instance created for {hostname}")
                
            except Exception as e:
                logger.error(f"[WORKFLOW] Failed to create HTTP instance for {hostname}: {e}")
                await self.publisher.publish_instance_failed(
                    hostname=hostname,
                    instance_type="http",
                    error=str(e)
                )
        else:
            logger.error(f"[WORKFLOW] No dispatcher available to create HTTP instance for {hostname}")
    
    async def handle_create_https_instance(self, event: Dict):
        """
        Handle HTTPS instance creation request.
        
        This event is triggered when a certificate is ready and we need to create the HTTPS instance.
        """
        hostname = event.get('hostname')
        https_port = event.get('https_port')
        https_internal_port = event.get('https_internal_port', https_port)
        cert_name = event.get('cert_name')
        
        logger.info(f"[WORKFLOW] Creating HTTPS instance for {hostname} on port {https_port} with cert {cert_name}")
        
        # Verify certificate exists and is active
        cert = await self._get_certificate(cert_name)
        if not cert or cert.status != 'active':
            logger.error(f"[WORKFLOW] Certificate {cert_name} not ready for {hostname}")
            await self.publisher.publish_instance_failed(
                hostname=hostname,
                instance_type="https",
                error=f"Certificate {cert_name} not active"
            )
            return
        
        if self.dispatcher:
            try:
                # The dispatcher's create_instance_for_proxy only takes hostname
                # If an HTTP instance already exists, it will upgrade it to HTTPS
                # If not, it will create a new HTTPS-only instance
                await self.dispatcher.create_instance_for_proxy(hostname)
                
                # Publish success event
                await self.publisher.publish_event("https_instance_started", {
                    "hostname": hostname,
                    "port": https_port,
                    "internal_port": https_internal_port,
                    "cert_name": cert_name
                })
                
                logger.info(f"[WORKFLOW] HTTPS instance created for {hostname}")
                
            except Exception as e:
                logger.error(f"[WORKFLOW] Failed to create HTTPS instance for {hostname}: {e}")
                await self.publisher.publish_instance_failed(
                    hostname=hostname,
                    instance_type="https",
                    error=str(e)
                )
        else:
            logger.error(f"[WORKFLOW] No dispatcher available to create HTTPS instance for {hostname}")
    
    async def handle_certificate_renewal(self, event: Dict):
        """
        Handle certificate renewal request.
        
        This starts the renewal process for a certificate.
        """
        cert_name = event.get('cert_name')
        force = event.get('force', False)
        
        logger.info(f"[WORKFLOW] Processing certificate renewal for {cert_name}")
        
        if self.cert_manager:
            try:
                # Start renewal process
                await self.cert_manager.renew_certificate(cert_name, force)
                
                # The cert_manager will publish certificate_renewed when done
                logger.info(f"[WORKFLOW] Certificate renewal initiated for {cert_name}")
                
            except Exception as e:
                logger.error(f"[WORKFLOW] Failed to start renewal for {cert_name}: {e}")
                await self.publisher.publish_event("certificate_renewal_failed", {
                    "cert_name": cert_name,
                    "error": str(e)
                })
        else:
            logger.error(f"[WORKFLOW] No certificate manager available for renewal")
    
    async def handle_certificate_renewed(self, event: Dict):
        """
        Handle certificate renewed event.
        
        Updates SSL contexts for all affected instances.
        """
        cert_name = event.get('cert_name')
        domains = event.get('domains', [])
        
        logger.info(f"[WORKFLOW] Certificate {cert_name} renewed, updating instances")
        
        # Find all proxies using this certificate
        for hostname in domains:
            proxy = await self._get_proxy_target(hostname)
            if proxy and proxy.cert_name == cert_name:
                # Trigger SSL context reload
                if self.dispatcher:
                    await self.dispatcher.reload_ssl_context(hostname)
                    logger.info(f"[WORKFLOW] Reloaded SSL context for {hostname}")
        
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
        
        logger.info(f"[WORKFLOW] Converting {cert_name} from staging to production")
        
        # Get current certificate
        cert = await self._get_certificate(cert_name)
        if not cert:
            logger.error(f"[WORKFLOW] Certificate {cert_name} not found")
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
    
    async def handle_production_cert_ready(self, event: Dict):
        """
        Handle production certificate ready after staging conversion.
        """
        cert_name = event.get('cert_name')
        domains = event.get('domains', [])
        
        logger.info(f"[WORKFLOW] Production certificate {cert_name} ready, updating instances")
        
        # Update all affected instances
        for hostname in domains:
            proxy = await self._get_proxy_target(hostname)
            if proxy and proxy.cert_name == cert_name:
                # Reload SSL context with new production cert
                if self.dispatcher:
                    await self.dispatcher.reload_ssl_context(hostname)
                    logger.info(f"[WORKFLOW] Updated {hostname} to production certificate")
        
        # Publish completion event
        await self.publisher.publish_event("staging_to_production_complete", {
            "cert_name": cert_name,
            "domains": domains
        })
    
    async def close(self):
        """Clean up resources."""
        logger.info("[WORKFLOW] Shutting down workflow orchestrator")
        
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
        
        logger.info("[WORKFLOW] Workflow orchestrator shutdown complete")