"""Service management MCP tools for Docker and external services."""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class ServiceTools(BaseMCPTools):
    """MCP tools for service management."""
    
    def register_tools(self):
        """Register all service management tools."""
        
        # Note: service_list is already defined in mcp_server.py
        # We'll add extended service tools here
        
        @self.mcp.tool(
            annotations={
                "title": "Create Docker Service",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def service_create(
            name: str,
            image: str,
            token: str,
            port: Optional[int] = None,
            memory: str = "512m",
            cpu: float = 1.0
        ) -> Dict[str, Any]:
            """Create a Docker service.
            
            Args:
                name: Service name
                image: Docker image
                token: API token for authentication
                port: Optional port to expose
                memory: Memory limit (e.g., 512m, 1g)
                cpu: CPU limit (e.g., 0.5, 1.0, 2.0)
                
            Returns:
                Dictionary with service creation status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_create",
                session_id=session_id,
                service_name=name
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                if not self.docker_manager:
                    raise RuntimeError("Docker manager not available")
                
                # Create service configuration
                service_config = {
                    "name": name,
                    "image": image,
                    "memory": memory,
                    "cpu": cpu,
                    "owner_token": token_info["name"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                if port:
                    service_config["ports"] = [{"internal": port, "external": port}]
                
                # Store service configuration
                await self.storage.store_service_config(name, service_config)
                
                # Publish workflow event
                await self.publish_workflow_event(
                    event_type="service_create_requested",
                    data={
                        "service_name": name,
                        "image": image,
                        "requested_by": "mcp",
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="service_create",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name, "image": image}
                )
                
                return {
                    "status": "creating",
                    "name": name,
                    "image": image,
                    "message": f"Service '{name}' creation initiated"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Delete Docker Service",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def service_delete(
            name: str,
            token: str,
            force: bool = False
        ) -> Dict[str, Any]:
            """Delete a Docker service.
            
            Args:
                name: Service name
                token: API token for authentication
                force: Force deletion even if in use
                
            Returns:
                Dictionary with deletion status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_delete",
                session_id=session_id,
                service_name=name
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                if not self.docker_manager:
                    raise RuntimeError("Docker manager not available")
                
                # Get service configuration
                service_config = await self.storage.get_service_config(name)
                if not service_config:
                    raise ValueError(f"Service '{name}' not found")
                
                # Check ownership
                await self.check_ownership(token_info, service_config.get("owner_token", ""), "service")
                
                # Delete service
                await self.storage.delete_service_config(name)
                
                # Publish workflow event
                await self.publish_workflow_event(
                    event_type="service_delete_requested",
                    data={
                        "service_name": name,
                        "deleted_by": "mcp",
                        "session_id": session_id,
                        "user": user,
                        "forced": force
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="service_delete",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name, "forced": force}
                )
                
                return {
                    "status": "deleted",
                    "name": name,
                    "message": f"Service '{name}' deleted successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Start Docker Service",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def service_start(
            name: str,
            token: str
        ) -> Dict[str, Any]:
            """Start a stopped Docker service.
            
            Args:
                name: Service name
                token: API token for authentication
                
            Returns:
                Dictionary with start status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_start",
                session_id=session_id,
                service_name=name
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                if not self.docker_manager:
                    raise RuntimeError("Docker manager not available")
                
                # Start service via Docker manager
                result = await self.docker_manager.start_service(name)
                
                # Log audit event
                await self.log_audit_event(
                    action="service_start",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name}
                )
                
                return {
                    "status": "started",
                    "name": name,
                    "message": f"Service '{name}' started successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Stop Docker Service",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def service_stop(
            name: str,
            token: str
        ) -> Dict[str, Any]:
            """Stop a running Docker service.
            
            Args:
                name: Service name
                token: API token for authentication
                
            Returns:
                Dictionary with stop status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_stop",
                session_id=session_id,
                service_name=name
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                if not self.docker_manager:
                    raise RuntimeError("Docker manager not available")
                
                # Stop service via Docker manager
                result = await self.docker_manager.stop_service(name)
                
                # Log audit event
                await self.log_audit_event(
                    action="service_stop",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name}
                )
                
                return {
                    "status": "stopped",
                    "name": name,
                    "message": f"Service '{name}' stopped successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Get Service Logs",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def service_logs(
            name: str,
            lines: int = 100,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Get logs from a Docker service.
            
            Args:
                name: Service name
                lines: Number of log lines to retrieve
                token: Optional API token for ownership check
                
            Returns:
                Dictionary with service logs
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_logs",
                session_id=session_id,
                service_name=name
            ):
                user = "anonymous"
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                
                if not self.docker_manager:
                    raise RuntimeError("Docker manager not available")
                
                # Get logs via Docker manager
                logs = await self.docker_manager.get_service_logs(name, lines=lines)
                
                # Log audit event
                await self.log_audit_event(
                    action="service_logs",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name, "lines": lines}
                )
                
                return {
                    "service": name,
                    "lines": lines,
                    "logs": logs
                }
        
        # ========== External Service Tools ==========
        
        @self.mcp.tool(
            annotations={
                "title": "Register External Service",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def service_register(
            name: str,
            target_url: str,
            token: str,
            description: Optional[str] = None
        ) -> Dict[str, Any]:
            """Register an external service.
            
            Args:
                name: Service name
                target_url: Service URL
                token: API token for authentication
                description: Optional service description
                
            Returns:
                Dictionary with registration status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_register",
                session_id=session_id,
                service_name=name
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Check if service already exists
                existing = await self.storage.get_external_service(name)
                if existing:
                    raise ValueError(f"External service '{name}' already exists")
                
                # Store external service
                service_data = {
                    "name": name,
                    "target_url": target_url,
                    "description": description or "",
                    "owner_token": token_info["name"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                await self.storage.store_external_service(name, service_data)
                
                # Log audit event
                await self.log_audit_event(
                    action="service_register",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name, "target_url": target_url}
                )
                
                return {
                    "status": "registered",
                    "name": name,
                    "target_url": target_url,
                    "message": f"External service '{name}' registered successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Unregister External Service",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def service_unregister(
            name: str,
            token: str
        ) -> Dict[str, Any]:
            """Unregister an external service.
            
            Args:
                name: Service name
                token: API token for authentication
                
            Returns:
                Dictionary with unregistration status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_service_unregister",
                session_id=session_id,
                service_name=name
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get service
                service = await self.storage.get_external_service(name)
                if not service:
                    raise ValueError(f"External service '{name}' not found")
                
                # Check ownership
                await self.check_ownership(token_info, service.get("owner_token", ""), "service")
                
                # Delete service
                await self.storage.delete_external_service(name)
                
                # Log audit event
                await self.log_audit_event(
                    action="service_unregister",
                    session_id=session_id,
                    user=user,
                    details={"service_name": name}
                )
                
                return {
                    "status": "unregistered",
                    "name": name,
                    "message": f"External service '{name}' unregistered successfully"
                }