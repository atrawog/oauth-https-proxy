"""Base class for MCP tool implementations."""

from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class BaseMCPTools:
    """Base class for MCP tool category implementations."""
    
    def __init__(
        self,
        mcp_server,
        storage,
        logger,
        event_publisher,
        session_manager
    ):
        """Initialize base tool class.
        
        Args:
            mcp_server: The MCP server instance with FastMCP
            storage: UnifiedStorage instance
            logger: UnifiedAsyncLogger instance
            event_publisher: MCPEventPublisher instance
            session_manager: MCPSessionManager instance
        """
        self.mcp = mcp_server.mcp  # FastMCP instance
        self.storage = storage
        self.logger = logger
        self.event_publisher = event_publisher
        self.session_manager = session_manager
        
        # Optional managers
        self.cert_manager = getattr(mcp_server, 'cert_manager', None)
        self.docker_manager = getattr(mcp_server, 'docker_manager', None)
    
    def get_session_context(self) -> Optional[str]:
        """Get current session ID from MCP context.
        
        Returns:
            Session ID or None if not available
        """
        try:
            context = self.mcp.get_context()
            return getattr(context, 'session_id', None) if context else None
        except (LookupError, AttributeError):
            return None
    
    async def validate_token(self, token: str, require_admin: bool = False) -> Dict[str, Any]:
        """Validate API token and return token info.
        
        Note: This method is deprecated with OAuth-only authentication.
        It's kept for backward compatibility but always returns a dummy response.
        
        Args:
            token: API token to validate (ignored)
            require_admin: Whether admin privileges are required (ignored)
            
        Returns:
            Dummy token information dictionary
        """
        # OAuth-only system - no API tokens to validate
        # Return dummy response for backward compatibility
        return {
            'name': 'oauth_user',
            'type': 'oauth',
            'valid': True
        }
    
    async def check_ownership(self, token_info: Dict[str, Any], resource_owner: str, resource_type: str = "resource") -> None:
        """Check if token owns a resource.
        
        Args:
            token_info: Token information dictionary
            resource_owner: Owner token name of the resource
            resource_type: Type of resource for error message
            
        Raises:
            PermissionError: If token doesn't own the resource
        """
        token_name = token_info.get('name', '')
        is_admin = token_name.upper() == 'ADMIN'
        
        if not is_admin and resource_owner != token_name:
            raise PermissionError(f"You can only manage {resource_type}s you own")
    
    async def log_audit_event(
        self,
        action: str,
        session_id: Optional[str] = None,
        user: str = "anonymous",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an audit event.
        
        Args:
            action: Action being performed
            session_id: Session ID if available
            user: User performing the action
            details: Additional event details
        """
        await self.event_publisher.publish_audit_event(
            action=action,
            session_id=session_id or self.get_session_context(),
            user=user,
            details=details or {}
        )
    
    async def publish_workflow_event(
        self,
        event_type: str,
        hostname: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None
    ) -> None:
        """Publish a workflow event.
        
        Args:
            event_type: Type of workflow event
            hostname: Hostname related to the event
            data: Event data
            trace_id: Trace ID for correlation
        """
        await self.event_publisher.publish_workflow_event(
            event_type=event_type, proxy_hostname=proxy_hostname,
            data=data or {},
            trace_id=trace_id
        )
    
    def register_tools(self):
        """Register all tools in this category. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement register_tools()")