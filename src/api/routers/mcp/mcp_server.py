"""FastMCP server implementation with integrated tools and Redis backing.

This module provides the core MCP server with tools for managing proxies,
certificates, and system operations, all integrated with the existing
async logging and Redis Streams architecture.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP

from ....shared.unified_logger import UnifiedAsyncLogger
from ....storage.async_redis_storage import AsyncRedisStorage
from .event_publisher import MCPEventPublisher
from .session_manager import MCPSessionManager

# Import all tool modules
from .tools import (
    TokenTools,
    CertificateTools,
    ProxyTools,
    ServiceTools,
    RouteTools,
    LogTools,
    OAuthTools,
    WorkflowTools,
    SystemTools
)


class IntegratedMCPServer:
    """MCP server with full integration into the OAuth HTTPS Proxy system."""

    def __init__(
        self,
        async_storage: AsyncRedisStorage,
        unified_logger: UnifiedAsyncLogger,
        cert_manager=None,
        docker_manager=None
    ):
        """Initialize the integrated MCP server.

        Args:
            async_storage: Async Redis storage instance
            unified_logger: Unified async logger for events and logs
            cert_manager: Optional certificate manager for cert operations
            docker_manager: Optional Docker manager for service operations
        """
        # Create FastMCP instance with root path since we mount at /mcp
        # Keep stateful mode for proper session management
        self.mcp = FastMCP(
            "OAuth-HTTPS-Proxy-MCP", 
            streamable_http_path="/",
            stateless_http=False  # MUST be stateful for sessions
        )

        # Store dependencies
        self.storage = async_storage
        self.logger = unified_logger
        self.cert_manager = cert_manager
        self.docker_manager = docker_manager

        # Set component name for logging
        self.logger.set_component("mcp_server")

        # Initialize managers
        self.session_manager = MCPSessionManager(async_storage, unified_logger)
        self.event_publisher = MCPEventPublisher(async_storage, unified_logger)

        # Register all tools
        self._register_core_tools()  # Register built-in tools
        self._register_modular_tools()  # Register modular tool categories
        
        # Log how many tools were registered
        import logging
        logger = logging.getLogger(__name__)
        # Check the tool manager directly since list_tools() is async
        tool_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
        logger.info(f"[MCP SERVER] Registered {tool_count} tools")

    def _register_modular_tools(self):
        """Register all modular tool categories."""
        import logging
        logger = logging.getLogger(__name__)
        logger.info("[MCP SERVER] Registering modular tools")
        
        # Initialize and register each tool category
        tool_categories = [
            (TokenTools, "Token Management"),
            (CertificateTools, "Certificate Management"),
            (ProxyTools, "Proxy Management"),
            (ServiceTools, "Service Management"),
            (RouteTools, "Route Management"),
            (LogTools, "Log Management"),
            (OAuthTools, "OAuth Management"),
            (WorkflowTools, "Workflow Automation"),
            (SystemTools, "System Configuration")
        ]
        
        for ToolClass, category_name in tool_categories:
            try:
                logger.info(f"[MCP SERVER] Registering {category_name} tools")
                tool_instance = ToolClass(
                    mcp_server=self,
                    storage=self.storage,
                    logger=self.logger,
                    event_publisher=self.event_publisher,
                    session_manager=self.session_manager
                )
                tool_instance.register_tools()
                logger.info(f"[MCP SERVER] {category_name} tools registered successfully")
            except Exception as e:
                logger.error(f"[MCP SERVER] Failed to register {category_name} tools: {e}")
    
    def _register_core_tools(self):
        """Register core built-in MCP tools."""
        import logging
        logger = logging.getLogger(__name__)
        logger.info("[MCP SERVER] Starting core tool registration")

        # ========== System Tools ==========
        logger.info("[MCP SERVER] Registering echo tool")

        @self.mcp.tool(
            annotations={
                "title": "Echo Message",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def echo(message: str) -> str:
            """Echo back a message for testing.

            Args:
                message: The message to echo back

            Returns:
                The echoed message with a prefix
            """
            # Get session context
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except:
                session_id = 'unknown'
            
            # Use unified logger with trace context
            async with self.logger.trace_context(
                "mcp_tool_echo",
                session_id=session_id,
                input_message=message
            ):
                await self.logger.log(
                    "info",
                    "Echo tool called",
                    tool="echo",
                    input_message=message,
                    session_id=session_id
                )
                
                result = f"Echo: {message}"
                
                await self.logger.log(
                    "info",
                    "Echo tool result",
                    tool="echo",
                    result=result,
                    session_id=session_id
                )
                
                return result
        
        tool_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
        logger.info(f"[MCP SERVER] After echo registration: {tool_count} tools")

        logger.info("[MCP SERVER] Registering health_check tool")
        
        @self.mcp.tool(
            annotations={
                "title": "System Health Check",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def health_check() -> Dict[str, Any]:
            """Check system health status.

            Returns:
                Dictionary with health status of all components
            """
            async with self.logger.trace_context("mcp_tool_health_check"):
                health = {
                    "status": "healthy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "components": {}
                }

                # Check Redis
                try:
                    await self.storage.redis_client.ping()
                    health["components"]["redis"] = "healthy"
                except Exception:
                    health["components"]["redis"] = "unhealthy"
                    health["status"] = "degraded"

                # Check certificate manager if available
                if self.cert_manager:
                    health["components"]["cert_manager"] = "healthy"

                # Check Docker manager if available
                if self.docker_manager:
                    health["components"]["docker_manager"] = "healthy"

                return health

        # ========== Proxy Management Tools ==========

        @self.mcp.tool(
            annotations={
                "title": "List Proxy Configurations",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_list(
            token: Optional[str] = None,
            include_details: bool = False
        ) -> Dict[str, Any]:
            """List configured proxy targets.

            Args:
                token: Optional API token for authentication
                include_details: Include full proxy details

            Returns:
                Dictionary with list of proxy configurations
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_list_proxies",
                session_id=session_id,
                has_token=bool(token)
            ):
                # Validate token if provided
                user = "anonymous"
                if token:
                    token_info = await self.storage.get_token_by_hash(token)
                    if not token_info:
                        raise PermissionError("Invalid token")
                    user = token_info.get("name", "unknown")

                # Get proxy targets
                proxies = await self.storage.list_proxy_targets()

                # Format response
                if include_details:
                    proxy_list = [
                        {
                            "hostname": p.hostname,
                            "target_url": p.target_url,
                            "auth_enabled": p.auth_enabled,
                            "cert_name": p.cert_name,
                            "enable_http": p.enable_http,
                            "enable_https": p.enable_https
                        }
                        for p in proxies
                    ]
                else:
                    proxy_list = [
                        {"hostname": p.hostname, "target_url": p.target_url}
                        for p in proxies
                    ]

                # Log audit event
                await self.event_publisher.publish_audit_event(
                    action="list_proxies",
                    session_id=session_id,
                    user=user,
                    details={"count": len(proxy_list)}
                )

                return {
                    "proxies": proxy_list,
                    "count": len(proxy_list)
                }

        @self.mcp.tool(
            annotations={
                "title": "Create Proxy Configuration",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def proxy_create(
            hostname: str,
            target_url: str,
            token: str,
            enable_http: bool = True,
            enable_https: bool = True,
            auth_enabled: bool = False
        ) -> Dict[str, Any]:
            """Create a new proxy configuration.

            Args:
                hostname: The hostname for the proxy
                target_url: The target URL to proxy to
                token: API token for authentication (required)
                enable_http: Enable HTTP (port 80)
                enable_https: Enable HTTPS (port 443)
                auth_enabled: Enable OAuth authentication

            Returns:
                Dictionary with creation status
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_create_proxy",
                session_id=session_id,
                hostname=hostname
            ) as trace_id:
                # Validate token (required for creation)
                token_info = await self.storage.get_token_by_hash(token)
                if not token_info:
                    raise PermissionError("Valid token required for proxy creation")

                user = token_info.get("name", "unknown")

                # Create proxy configuration
                proxy_data = {
                    "hostname": hostname,
                    "target_url": target_url,
                    "enable_http": enable_http,
                    "enable_https": enable_https,
                    "auth_enabled": auth_enabled,
                    "owner_token": token_info["name"]
                }

                # Store proxy
                await self.storage.create_proxy_target(proxy_data)

                # Publish workflow event for instance creation
                await self.event_publisher.publish_workflow_event(
                    event_type="proxy_created",
                    hostname=hostname,
                    data={
                        "target_url": target_url,
                        "created_by": "mcp",
                        "session_id": session_id,
                        "user": user,
                        "enable_http": enable_http,
                        "enable_https": enable_https
                    },
                    trace_id=trace_id
                )

                # Log audit event
                await self.event_publisher.publish_audit_event(
                    action="create_proxy",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname, "target_url": target_url}
                )

                return {
                    "status": "created",
                    "hostname": hostname,
                    "message": f"Proxy {hostname} created successfully"
                }

        @self.mcp.tool(
            annotations={
                "title": "Delete Proxy Configuration",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_delete(
            hostname: str,
            token: str
        ) -> Dict[str, Any]:
            """Delete a proxy configuration.

            Args:
                hostname: The hostname of the proxy to delete
                token: API token for authentication (required)

            Returns:
                Dictionary with deletion status
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_delete_proxy",
                session_id=session_id,
                hostname=hostname
            ) as trace_id:
                # Validate token
                token_info = await self.storage.get_token_by_hash(token)
                if not token_info:
                    raise PermissionError("Valid token required for proxy deletion")

                user = token_info.get("name", "unknown")

                # Get proxy to check ownership
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy {hostname} not found")

                # Check ownership (unless admin token)
                if proxy.owner_token != token_info["name"] and token_info["name"] != "admin":
                    raise PermissionError("You can only delete proxies you own")

                # Delete proxy
                await self.storage.delete_proxy_target(hostname)

                # Publish workflow event for instance deletion
                await self.event_publisher.publish_workflow_event(
                    event_type="proxy_deleted",
                    hostname=hostname,
                    data={
                        "deleted_by": "mcp",
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )

                # Log audit event
                await self.event_publisher.publish_audit_event(
                    action="delete_proxy",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname}
                )

                return {
                    "status": "deleted",
                    "hostname": hostname,
                    "message": f"Proxy {hostname} deleted successfully"
                }

        # ========== Certificate Management Tools ==========

        @self.mcp.tool(
            annotations={
                "title": "List SSL Certificates",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def cert_list(
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """List available SSL certificates.

            Args:
                token: Optional API token for filtering owned certificates

            Returns:
                Dictionary with list of certificates
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_list_certificates",
                session_id=session_id
            ):
                # Get all certificates
                certs = await self.storage.list_certificates()

                # Filter by ownership if token provided
                if token:
                    token_info = await self.storage.get_token_by_hash(token)
                    if token_info:
                        # Filter to owned certificates
                        owned_certs = []
                        for cert in certs:
                            if cert.get("owner_token") == token_info["name"]:
                                owned_certs.append(cert)
                        certs = owned_certs

                # Format response
                cert_list = [
                    {
                        "name": c.cert_name,
                        "domains": c.domains,
                        "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                        "status": "active" if c.expires_at and c.expires_at > datetime.now(timezone.utc) else "expired"
                    }
                    for c in certs
                ]

                return {
                    "certificates": cert_list,
                    "count": len(cert_list)
                }

        @self.mcp.tool(
            annotations={
                "title": "Request SSL Certificate",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": True
            }
        )
        async def cert_create(
            domain: str,
            token: str,
            email: Optional[str] = None
        ) -> Dict[str, Any]:
            """Request a new SSL certificate for a domain.

            Args:
                domain: The domain to request a certificate for
                token: API token for authentication (required)
                email: Optional email for certificate notifications

            Returns:
                Dictionary with certificate request status
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_request_certificate",
                session_id=session_id,
                domain=domain
            ) as trace_id:
                # Validate token
                token_info = await self.storage.get_token_by_hash(token)
                if not token_info:
                    raise PermissionError("Valid token required for certificate requests")

                user = token_info.get("name", "unknown")
                cert_email = email or token_info.get("cert_email")

                if not cert_email:
                    raise ValueError("Email required for certificate request")

                if not self.cert_manager:
                    raise RuntimeError("Certificate manager not available")

                # Request certificate
                cert_name = f"mcp-{domain}"

                # Publish workflow event for certificate request
                await self.event_publisher.publish_workflow_event(
                    event_type="certificate_requested",
                    hostname=domain,
                    data={
                        "cert_name": cert_name,
                        "email": cert_email,
                        "requested_by": "mcp",
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )

                return {
                    "status": "requested",
                    "domain": domain,
                    "cert_name": cert_name,
                    "message": f"Certificate request initiated for {domain}"
                }

        # ========== Service Management Tools (if Docker manager available) ==========

        if self.docker_manager:
            @self.mcp.tool(
                annotations={
                    "title": "List Docker Services",
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False
                }
            )
            async def service_list() -> Dict[str, Any]:
                """List Docker services managed by the system.

                Returns:
                    Dictionary with list of services
                """
                # Get context using FastMCP's method
                try:
                    context = self.mcp.get_context()
                    session_id = getattr(context, 'session_id', None) if context else None
                except (LookupError, AttributeError):
                    session_id = None

                async with self.logger.trace_context(
                    "mcp_tool_list_services",
                    session_id=session_id
                ):
                    services = await self.docker_manager.list_services()

                    service_list = [
                        {
                            "name": s.name,
                            "image": s.image,
                            "status": s.status,
                            "ports": s.ports
                        }
                        for s in services
                    ]

                    return {
                        "services": service_list,
                        "count": len(service_list)
                    }

        # ========== Route Management Tools ==========

        @self.mcp.tool(
            annotations={
                "title": "List HTTP Routing Rules",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def route_list() -> Dict[str, Any]:
            """List HTTP routing rules.

            Returns:
                Dictionary with list of routes
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_list_routes",
                session_id=session_id
            ):
                routes = await self.storage.list_routes()

                route_list = [
                    {
                        "route_id": r.route_id,
                        "path_pattern": r.path_pattern,
                        "target_type": r.target_type,
                        "target_value": r.target_value,
                        "priority": r.priority,
                        "enabled": r.enabled
                    }
                    for r in routes
                ]

                return {
                    "routes": route_list,
                    "count": len(route_list)
                }

        # ========== Log Query Tools ==========

        @self.mcp.tool(
            annotations={
                "title": "Query System Logs",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def logs(
            hours: int = 24,
            hostname: Optional[str] = None,
            status_code: Optional[int] = None,
            limit: int = 100
        ) -> Dict[str, Any]:
            """Query system logs with filters.

            Args:
                hours: How many hours back to search
                hostname: Filter by proxy hostname
                status_code: Filter by HTTP status code
                limit: Maximum number of results

            Returns:
                Dictionary with matching log entries
            """
            # Get context using FastMCP's method
            try:
                context = self.mcp.get_context()
                session_id = getattr(context, 'session_id', None) if context else None
            except (LookupError, AttributeError):
                session_id = None

            async with self.logger.trace_context(
                "mcp_tool_query_logs",
                session_id=session_id,
                filters={
                    "hours": hours,
                    "hostname": hostname,
                    "status_code": status_code
                }
            ):
                # Query logs from Redis
                start_time = time.time() - (hours * 3600)

                # Build index key based on filters
                logs = []
                try:
                    if hostname:
                        # Query by hostname
                        index_key = f"idx:req:host:{hostname}"
                        log_keys = await self.async_storage.redis_client.zrevrange(index_key, 0, limit - 1)
                    elif status_code:
                        # Query by status code
                        index_key = f"idx:req:status:{status_code}"
                        log_keys = await self.async_storage.redis_client.zrevrange(index_key, 0, limit - 1)
                    else:
                        # Get all recent logs from stream
                        # Use the stream for recent logs
                        log_keys = []
                        stream_data = await self.async_storage.redis_client.xrevrange(
                            "stream:requests",
                            count=limit
                        )
                        for stream_id, fields in stream_data:
                            logs.append(fields)
                    
                    # Fetch log entries if we have keys
                    if log_keys and not logs:
                        for key in log_keys:
                            if isinstance(key, bytes):
                                key = key.decode('utf-8')
                            log_data = await self.async_storage.redis_client.hgetall(key)
                            if log_data:
                                # Convert bytes to strings if needed
                                log_entry = {}
                                for k, v in log_data.items():
                                    if isinstance(k, bytes):
                                        k = k.decode('utf-8')
                                    if isinstance(v, bytes):
                                        v = v.decode('utf-8')
                                    log_entry[k] = v
                                logs.append(log_entry)
                except Exception as e:
                    logger.warning(f"Error querying logs: {e}")
                    logs = []

                return {
                    "logs": logs,
                    "count": len(logs),
                    "filters": {
                        "hours": hours,
                        "hostname": hostname,
                        "status_code": status_code
                    }
                }

    def get_server(self) -> FastMCP:
        """Get the FastMCP server instance.

        Returns:
            The FastMCP server instance
        """
        return self.mcp
