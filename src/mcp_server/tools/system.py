"""System tools for MCP server."""

import logging
import time
from typing import Dict, Any, Optional

# Try to import from MCP SDK, fall back to simple implementation
try:
    from mcp.server import FastMCP
except ImportError:
    from ..simple_mcp import FastMCP

logger = logging.getLogger(__name__)


def register_system_tools(mcp: FastMCP, context: dict):
    """Register system-related tools.
    
    Args:
        mcp: FastMCP instance
        context: Dictionary containing dependencies
    """
    
    storage = context["storage"]
    unified_logger = context["logger"]
    state_manager = context["state_manager"]
    stateless_mode = context["stateless_mode"]
    
    @mcp.tool()
    async def healthProbe() -> Dict[str, Any]:
        """Perform a comprehensive health check of the MCP server.
        
        Returns:
            Dictionary with health status information
        """
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "mode": "stateless" if stateless_mode else "stateful",
            "components": {  # Include components for test compatibility
                "redis": False,
                "sessions": False,
                "storage": False
            },
            "checks": {
                "redis": False,
                "sessions": False,
                "storage": False
            },
            "metrics": {}
        }
        
        # Check Redis connectivity
        try:
            redis_ok = await storage.health_check()
            health_status["checks"]["redis"] = redis_ok
            health_status["components"]["redis"] = redis_ok
            
            if redis_ok:
                # Get some metrics
                proxy_count = len(await storage.keys("proxy:*"))
                cert_count = len(await storage.keys("cert:*"))
                token_count = len(await storage.keys("token:*"))
                
                health_status["metrics"]["proxies"] = proxy_count
                health_status["metrics"]["certificates"] = cert_count
                health_status["metrics"]["tokens"] = token_count
        except Exception as e:
            health_status["checks"]["redis"] = False
            health_status["components"]["redis"] = False
            health_status["errors"] = {"redis": str(e)}
            health_status["status"] = "degraded"
        
        # Check session management (stateful mode only)
        if not stateless_mode:
            try:
                session_count = await state_manager.get_session_count()
                health_status["checks"]["sessions"] = True
                health_status["components"]["sessions"] = True
                health_status["metrics"]["active_sessions"] = session_count
                
                # Clean up expired sessions
                cleaned = await state_manager.cleanup_expired_sessions()
                if cleaned > 0:
                    health_status["metrics"]["cleaned_sessions"] = cleaned
            except Exception as e:
                health_status["checks"]["sessions"] = False
                health_status["components"]["sessions"] = False
                health_status["errors"] = health_status.get("errors", {})
                health_status["errors"]["sessions"] = str(e)
                health_status["status"] = "degraded"
        else:
            health_status["checks"]["sessions"] = "n/a"
            health_status["components"]["sessions"] = "n/a"
        
        # Check storage operations
        try:
            # Try a simple write/read/delete operation
            test_key = "mcp:health:test"
            test_value = str(time.time())
            
            write_ok = await storage.redis_client.set(test_key, test_value, ex=10)
            if write_ok:
                read_value = await storage.redis_client.get(test_key)
                if read_value == test_value:
                    await storage.delete(test_key)
                    health_status["checks"]["storage"] = True
                    health_status["components"]["storage"] = True
                else:
                    health_status["checks"]["storage"] = False
                    health_status["components"]["storage"] = False
                    health_status["status"] = "degraded"
            else:
                health_status["checks"]["storage"] = False
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["checks"]["storage"] = False
            health_status["errors"] = health_status.get("errors", {})
            health_status["errors"]["storage"] = str(e)
            health_status["status"] = "unhealthy"
        
        # Overall status determination
        if all(v for v in health_status["checks"].values() if v != "n/a"):
            health_status["status"] = "healthy"
        elif any(v for v in health_status["checks"].values() if v and v != "n/a"):
            health_status["status"] = "degraded"
        else:
            health_status["status"] = "unhealthy"
        
        # Log health check
        await unified_logger.event("mcp_health_check", {
            "status": health_status["status"],
            "checks": health_status["checks"],
            "metrics": health_status["metrics"]
        })
        
        return health_status
    
    @mcp.tool()
    async def sessionInfo(session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get information about the current session or all sessions.
        
        Args:
            session_id: Optional specific session ID to query
            
        Returns:
            Session information dictionary
        """
        session_info = {
            "session_id": session_id or "none",  # Always include session_id
            "mode": "stateless" if stateless_mode else "stateful",
            "timestamp": time.time()
        }
        
        if stateless_mode:
            session_info["message"] = "Session management is disabled in stateless mode"
            session_info["hint"] = "Each request is independent with no session persistence"
            
            # Still provide request-scoped state info if available
            if session_id:
                request_keys = await storage.keys(f"mcp:request:{session_id}:*")
                session_info["request_state_keys"] = len(request_keys)
                session_info["request_id"] = session_id
        else:
            # Stateful mode - full session management
            if session_id:
                # Get specific session info
                session_data = await state_manager.get_session(session_id)
                if session_data:
                    session_info["session"] = {
                        "id": session_data["id"],
                        "created_at": session_data["created_at"],
                        "last_accessed": session_data["last_accessed"],
                        "age_seconds": time.time() - session_data["created_at"],
                        "idle_seconds": time.time() - session_data["last_accessed"]
                    }
                    
                    # Get state keys for this session
                    state_keys = await state_manager.list_state_keys(session_id)
                    session_info["session"]["state_keys"] = state_keys
                    session_info["session"]["state_count"] = len(state_keys)
                else:
                    session_info["error"] = f"Session not found: {session_id}"
            else:
                # Get all sessions info
                active_sessions = await state_manager.list_active_sessions()
                session_info["total_sessions"] = len(active_sessions)
                session_info["active_session_ids"] = active_sessions[:10]  # Limit to 10
                
                if len(active_sessions) > 10:
                    session_info["note"] = f"Showing first 10 of {len(active_sessions)} sessions"
                
                # Get aggregate stats
                total_state_keys = 0
                oldest_session = time.time()
                
                for sid in active_sessions[:10]:  # Sample first 10
                    session_data = await state_manager.get_session(sid)
                    if session_data:
                        if session_data["created_at"] < oldest_session:
                            oldest_session = session_data["created_at"]
                        state_keys = await state_manager.list_state_keys(sid)
                        total_state_keys += len(state_keys)
                
                if active_sessions:
                    session_info["stats"] = {
                        "average_state_keys": total_state_keys / min(10, len(active_sessions)),
                        "oldest_session_age": time.time() - oldest_session if oldest_session < time.time() else 0
                    }
                
                # Session timeout configuration
                session_info["configuration"] = {
                    "timeout_seconds": state_manager.session_timeout,
                    "timeout_minutes": state_manager.session_timeout / 60
                }
        
        # Log session info request
        await unified_logger.event("mcp_session_info", {
            "session_id": session_id,
            "mode": session_info["mode"],
            "session_count": session_info.get("total_sessions", 0)
        })
        
        return session_info
    
    logger.info("Registered system tools: healthProbe, sessionInfo")