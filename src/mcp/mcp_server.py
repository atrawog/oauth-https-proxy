"""MCP Server implementation using official SDK."""

import logging
from typing import Optional

# Try to import from MCP SDK, fall back to simple implementation
try:
    from mcp.server import FastMCP
except ImportError:
    from .simple_mcp import FastMCP

from src.storage.async_redis_storage import AsyncRedisStorage
from src.shared.unified_logger import UnifiedAsyncLogger
from .redis_state import RedisStateManager

logger = logging.getLogger(__name__)


class MCPServer:
    """MCP Server integrated with oauth-https-proxy infrastructure."""
    
    def __init__(
        self,
        storage: AsyncRedisStorage,
        unified_logger: UnifiedAsyncLogger,
        stateless_mode: bool = False,
        session_timeout: int = 3600,
        auth_manager: Optional[object] = None
    ):
        """Initialize MCP Server.
        
        Args:
            storage: AsyncRedisStorage instance
            unified_logger: UnifiedAsyncLogger instance
            stateless_mode: Whether to run in stateless mode
            session_timeout: Session timeout in seconds (for stateful mode)
            auth_manager: Optional auth manager for OAuth integration
        """
        self.storage = storage
        self.unified_logger = unified_logger
        self.stateless_mode = stateless_mode
        self.session_timeout = session_timeout
        self.auth_manager = auth_manager
        
        # Create FastMCP instance using official SDK
        self.mcp = FastMCP(name="OAuth-HTTPS-Proxy MCP Server")
        
        # Initialize state manager with Redis backend
        self.state_manager = RedisStateManager(
            storage=storage,
            stateless_mode=stateless_mode,
            session_timeout=session_timeout
        )
        
        # Store dependencies in MCP state for tool access
        self.mcp.state = {
            "storage": self.storage,
            "logger": self.unified_logger,
            "state_manager": self.state_manager,
            "auth_manager": self.auth_manager,
            "stateless_mode": self.stateless_mode
        }
        
        # Register all tools
        self._register_tools()
        
        logger.info(
            "MCP Server initialized in %s mode with %d second timeout",
            "stateless" if stateless_mode else "stateful",
            session_timeout
        )
    
    def _register_tools(self):
        """Register all 21 tools matching mcp-http-echo-server."""
        from .tools import (
            register_echo_tools,
            register_debug_tools,
            register_auth_tools,
            register_system_tools,
            register_state_tools
        )
        
        # Create context with all dependencies
        context = {
            "storage": self.storage,
            "logger": self.unified_logger,
            "state_manager": self.state_manager,
            "stateless_mode": self.stateless_mode,
            "auth_manager": self.auth_manager
        }
        
        # Register tool categories
        try:
            register_echo_tools(self.mcp, context)
            logger.debug("Registered echo tools")
        except Exception as e:
            logger.error(f"Failed to register echo tools: {e}")
        
        try:
            register_debug_tools(self.mcp, context)
            logger.debug("Registered debug tools")
        except Exception as e:
            logger.error(f"Failed to register debug tools: {e}")
        
        try:
            register_auth_tools(self.mcp, context)
            logger.debug("Registered auth tools")
        except Exception as e:
            logger.error(f"Failed to register auth tools: {e}")
        
        try:
            register_system_tools(self.mcp, context)
            logger.debug("Registered system tools")
        except Exception as e:
            logger.error(f"Failed to register system tools: {e}")
        
        try:
            register_state_tools(self.mcp, context)
            logger.debug("Registered state tools")
        except Exception as e:
            logger.error(f"Failed to register state tools: {e}")
        
        logger.info("Completed tool registration for MCP server")
    
    def get_server_info(self) -> dict:
        """Get server information for MCP protocol."""
        return {
            "name": "OAuth-HTTPS-Proxy MCP Server",
            "version": "1.0.0",
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": False},
                "prompts": {"listChanged": False}
            },
            "serverInfo": {
                "name": "OAuth-HTTPS-Proxy MCP Server",
                "version": "1.0.0",
                "mode": "stateless" if self.stateless_mode else "stateful",
                "sessionTimeout": self.session_timeout
            }
        }
    
    async def handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize request."""
        # Log initialization
        await self.unified_logger.event("mcp_initialize", {
            "client_info": params.get("clientInfo", {}),
            "protocol_version": params.get("protocolVersion"),
            "mode": "stateless" if self.stateless_mode else "stateful"
        })
        
        return self.get_server_info()