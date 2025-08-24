"""FastMCP server implementation with integrated tools and Redis backing.

This module provides the core MCP server with tools for managing proxies,
certificates, and system operations, all integrated with the existing
async logging and Redis Streams architecture.
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP

from ....shared.unified_logger import UnifiedAsyncLogger
from ....storage.async_redis_storage import AsyncRedisStorage
from .event_publisher import MCPEventPublisher
from .session_manager import MCPSessionManager
from .session_interceptor import MCPSessionInterceptor

# Import all tool modules
from .tools import (
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
    
    def _log_info_async(self, message: str, **kwargs):
        """Fire-and-forget async info logging without creating orphaned tasks."""
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
        """Fire-and-forget async error logging without creating orphaned tasks."""
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
        """Fire-and-forget async warning logging without creating orphaned tasks."""
        if self.logger:
            try:
                # Create task with proper error handling
                task = asyncio.create_task(self.logger.warning(message, **kwargs))
                # Add callback to handle exceptions
                task.add_done_callback(lambda t: t.exception() if t.done() else None)
            except RuntimeError:
                # No event loop running, skip logging
                pass
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
        self.async_storage = async_storage  # Also store as async_storage for compatibility
        
        # Create component-specific logger to prevent contamination
        redis_clients = getattr(unified_logger, 'redis_clients', None)
        if redis_clients:
            self.logger = UnifiedAsyncLogger(redis_clients, component="mcp_server")
        else:
            # Fallback if redis_clients not available
            self.logger = unified_logger
        
        self.cert_manager = cert_manager
        self.docker_manager = docker_manager

        # Initialize managers with their own loggers
        if redis_clients:
            self.session_manager = MCPSessionManager(async_storage, redis_clients)
            self.event_publisher = MCPEventPublisher(async_storage, redis_clients)
        else:
            # Fallback - should not happen in production
            self.session_manager = MCPSessionManager(async_storage, unified_logger.redis_clients)
            self.event_publisher = MCPEventPublisher(async_storage, unified_logger.redis_clients)
        
        # Initialize session interceptor to bridge FastMCP with Redis
        self.session_interceptor = MCPSessionInterceptor(
            self.session_manager,
            self.event_publisher
        )

        # Register all tools
        self._register_core_tools()  # Register built-in tools
        self._register_modular_tools()  # Register modular tool categories
        
        # Log how many tools were registered
        # Check the tool manager directly since list_tools() is async
        tool_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
        # Fire-and-forget info log
        import asyncio
        self._log_info_async(f"[MCP SERVER] Registered {tool_count} tools")

    def _register_modular_tools(self):
        """Register all modular tool categories."""
        import asyncio
        self._log_info_async("[MCP SERVER] Registering modular tools")
        
        # Log initial tool count
        initial_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
        self._log_info_async(f"[MCP SERVER] Initial tool count before modular registration: {initial_count}")
        
        # Initialize and register each tool category
        # PERFORMANCE FIX: FastMCP generates 54KB response for 55 tools which takes >5s to process
        # Claude.ai has 5s timeout. Limiting to essential tools keeps response under 15KB for fast processing
        tool_categories = [
            # Re-enabling all tools - proxy speed is now fixed
            (ProxyTools, "Proxy Management"),  # 9 tools
            (LogTools, "Log Management"),  # 5 tools  
            (ServiceTools, "Service Management"),  # 7 tools
            (CertificateTools, "Certificate Management"),  # 5 tools
            (RouteTools, "Route Management"),  # 5 tools
            # (OAuthTools, "OAuth Management"),  # 5 tools
            # (WorkflowTools, "Workflow Automation"),  # 5 tools
            # (SystemTools, "System Configuration")  # 5 tools
        ]
        # With optimized proxy, we can handle more tools
        
        for ToolClass, category_name in tool_categories:
            try:
                before_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
                self._log_info_async(f"[MCP SERVER] Registering {category_name} tools (current count: {before_count})")
                
                tool_instance = ToolClass(
                    mcp_server=self,
                    storage=self.storage,
                    logger=self.logger,
                    event_publisher=self.event_publisher,
                    session_manager=self.session_manager
                )
                tool_instance.register_tools()
                
                after_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
                tools_added = after_count - before_count
                self._log_info_async(f"[MCP SERVER] {category_name} tools registered successfully - added {tools_added} tools (total: {after_count})")
            except Exception as e:
                self._log_error_async(f"[MCP SERVER] Failed to register {category_name} tools: {e}")
                import traceback
                self._log_error_async(f"[MCP SERVER] Traceback: {traceback.format_exc()}")
    
    def _register_core_tools(self):
        """Register core built-in MCP tools."""
        self._log_info_async("[MCP SERVER] Starting core tool registration")

        # ========== System Tools ==========
        self._log_info_async("[MCP SERVER] Registering echo tool")

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
        self._log_info_async(f"[MCP SERVER] After echo registration: {tool_count} tools")

        self._log_info_async("[MCP SERVER] Registering health_check tool")
        
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
                            "proxy_hostname": p.hostname,
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
                        {"proxy_hostname": p.hostname, "target_url": p.target_url}
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
            proxy_hostname: str,
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
                session_id=session_id, proxy_hostname=proxy_hostname
            ) as trace_id:
                # Validate token (required for creation)
                token_info = await self.storage.get_token_by_hash(token)
                if not token_info:
                    raise PermissionError("Valid token required for proxy creation")

                user = token_info.get("name", "unknown")

                # Create proxy configuration
                proxy_data = {
                    "proxy_hostname": proxy_hostname,
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
                    event_type="proxy_created", proxy_hostname=proxy_hostname,
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
                    details={"proxy_hostname": proxy_hostname, "target_url": target_url}
                )

                return {
                    "status": "created",
                    "proxy_hostname": proxy_hostname,
                    "message": f"Proxy {proxy_hostname} created successfully"
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
            proxy_hostname: str,
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
                session_id=session_id, proxy_hostname=proxy_hostname
            ) as trace_id:
                # Validate token
                token_info = await self.storage.get_token_by_hash(token)
                if not token_info:
                    raise PermissionError("Valid token required for proxy deletion")

                user = token_info.get("name", "unknown")

                # Get proxy to check ownership
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy {proxy_hostname} not found")

                # Check ownership (unless admin token)
                if proxy.owner_token != token_info["name"] and token_info["name"] != "admin":
                    raise PermissionError("You can only delete proxies you own")

                # Delete proxy
                await self.storage.delete_proxy_target(hostname)

                # Publish workflow event for instance deletion
                await self.event_publisher.publish_workflow_event(
                    event_type="proxy_deleted", proxy_hostname=proxy_hostname,
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
                    details={"proxy_hostname": proxy_hostname}
                )

                return {
                    "status": "deleted",
                    "proxy_hostname": proxy_hostname,
                    "message": f"Proxy {proxy_hostname} deleted successfully"
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

        # Note: cert_create is now registered via CertificateTools in modular tools
        
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
                    "proxy_hostname": proxy_hostname,
                    "status_code": status_code
                }
            ):
                # Query logs from Redis
                start_time = time.time() - (hours * 3600)

                # Use async_storage's search_logs method which properly handles all cases
                logs = []
                try:
                    # Build search parameters
                    search_params = {
                        'hours': hours,
                        'limit': limit
                    }
                    
                    if hostname:
                        search_params['hostname'] = hostname
                    if status_code:
                        search_params['status'] = status_code
                    
                    # Use async storage search which properly indexes all logs
                    result = await self.async_storage.search_logs(**search_params)
                    logs = result.get('logs', [])
                except Exception as e:
                    # Fire-and-forget warning log
                    import asyncio
                    if unified_logger:
                        try:
                            task = asyncio.create_task(unified_logger.warning(f"Error querying logs: {e}"))
                            task.add_done_callback(lambda t: t.exception() if t.done() else None)
                        except Exception:
                            pass
                    logs = []

                # Match proxy-client API format for search endpoint
                return {
                    "total": len(logs),
                    "logs": logs,
                    "query_params": {
                        "hours": hours,
                        "limit": limit,
                        "offset": 0
                    }
                }

    def get_server(self) -> FastMCP:
        """Get the FastMCP server instance.

        Returns:
            The FastMCP server instance
        """
        return self.mcp
