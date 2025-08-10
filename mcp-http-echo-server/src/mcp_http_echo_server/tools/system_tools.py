"""System monitoring tools for MCP Echo Server."""

import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, UTC
from fastmcp import FastMCP, Context
from ..utils.state_adapter import StateAdapter
from ..session_manager import SessionManager

logger = logging.getLogger(__name__)

MAX_DISPLAY_SESSIONS = 10


def register_system_tools(mcp: FastMCP, stateless_mode: bool, session_manager: Optional[SessionManager]):
    """Register system monitoring tools.
    
    Args:
        mcp: FastMCP instance
        stateless_mode: Whether server is in stateless mode
        session_manager: Session manager instance (None in stateless mode)
    """
    
    @mcp.tool
    async def healthProbe(ctx: Context) -> Dict[str, Any]:
        """Perform deep health check of service and dependencies.
        
        Checks the health status of:
        - Server status and version
        - Protocol compliance
        - Session management (stateful mode)
        - Resource usage estimates
        
        Returns:
            Comprehensive health status report
        """
        result = {
            "status": "healthy",
            "timestamp": time.time(),
            "server": {
                "name": ctx.get_state("server_name", "mcp-http-echo-server"),
                "version": ctx.get_state("server_version", "1.0.0"),
                "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful",
                "debug": ctx.get_state("server_debug", False)
            },
            "protocol": {
                "supported_versions": ctx.get_state("supported_versions", ["2025-06-18"]),
                "transport": "HTTP with optional SSE"
            }
        }
        
        # Add session health if stateful
        if not ctx.get_state("stateless_mode") and session_manager:
            session_stats = session_manager.get_session_stats()
            result["sessions"] = {
                "total_active": session_stats["total_sessions"],
                "initialized": session_stats["initialized_sessions"],
                "average_age_seconds": session_stats["average_age_seconds"],
                "average_requests": session_stats["average_request_count"],
                "queued_messages": session_stats["total_queued_messages"],
                "timeout_seconds": session_stats["session_timeout"]
            }
            
            # Check session health
            if session_stats["total_sessions"] > 1000:
                result["status"] = "degraded"
                result["warnings"] = result.get("warnings", [])
                result["warnings"].append("High number of active sessions")
            
            # Current session health
            session_id = ctx.get_state("session_id")
            if session_id:
                session = session_manager.get_session(session_id)
                if session:
                    session_age = time.time() - session["created_at"]
                    result["current_session"] = {
                        "id": session_id[:8] + "...",
                        "age_seconds": session_age,
                        "requests": session.get("request_count", 0),
                        "initialized": session.get("initialized", False)
                    }
        else:
            result["sessions"] = {
                "message": "Session tracking disabled in stateless mode"
            }
        
        # Tool availability
        result["tools"] = {
            "total": 21,
            "categories": {
                "echo": 2,
                "debug": 4,
                "auth": 3,
                "system": 2,
                "state": 10
            },
            "stateful_only": ["replayLastEcho", "sessionHistory", "sessionTransfer"] if ctx.get_state("stateless_mode") else []
        }
        
        # Performance metrics
        request_start = ctx.get_state("request_start_time")
        if request_start:
            elapsed = (time.time() - request_start) * 1000
            result["performance"] = {
                "current_request_ms": elapsed,
                "status": "excellent" if elapsed < 10 else "good" if elapsed < 50 else "acceptable" if elapsed < 100 else "slow"
            }
        
        return result
    
    @mcp.tool
    async def sessionInfo(ctx: Context) -> Dict[str, Any]:
        """Display current session information and statistics.
        
        Shows:
        - Current session details (stateful mode)
        - Server statistics
        - Active sessions list (stateful mode)
        - Mode capabilities
        
        Returns:
            Session information and statistics
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        result = {
            "mode": "stateless" if is_stateless else "stateful",
            "server": {
                "name": ctx.get_state("server_name", "mcp-http-echo-server"),
                "version": ctx.get_state("server_version", "1.0.0")
            }
        }
        
        if is_stateless:
            # Stateless mode information
            result["session_management"] = {
                "enabled": False,
                "message": "Running in stateless mode - no session tracking",
                "request_id": ctx.get_state("request_id", "unknown")
            }
            
            result["capabilities"] = {
                "session_persistence": False,
                "message_queuing": False,
                "replay_support": False,
                "horizontal_scaling": True,
                "serverless_ready": True,
                "available_tools": [
                    "echo", "printHeader", "bearerDecode", "authContext",
                    "requestTiming", "corsAnalysis", "environmentDump",
                    "healthProbe", "sessionInfo", "whoIStheGOAT",
                    "stateInspector", "stateManipulator", "stateBenchmark",
                    "stateValidator", "requestTracer", "modeDetector"
                ]
            }
        else:
            # Stateful mode information
            session_id = ctx.get_state("session_id")
            
            if session_id and session_manager:
                session = session_manager.get_session(session_id)
                
                if session:
                    result["current_session"] = {
                        "session_id": session_id,
                        "created_at": datetime.fromtimestamp(session["created_at"], tz=UTC).isoformat(),
                        "last_activity": datetime.fromtimestamp(session["last_activity"], tz=UTC).isoformat(),
                        "age_seconds": time.time() - session["created_at"],
                        "initialized": session.get("initialized", False),
                        "protocol_version": session.get("protocol_version"),
                        "request_count": session.get("request_count", 0)
                    }
                    
                    # Client info
                    client_info = session.get("client_info", {})
                    if client_info:
                        result["current_session"]["client"] = {
                            "name": client_info.get("name", "unknown"),
                            "version": client_info.get("version", "unknown")
                        }
                    
                    # Check for queued messages
                    has_messages = session_manager.has_queued_messages(session_id)
                    result["current_session"]["has_queued_messages"] = has_messages
                else:
                    result["current_session"] = {
                        "error": f"Session {session_id} not found"
                    }
            else:
                result["current_session"] = {
                    "error": "No session ID available"
                }
            
            # Global session statistics
            if session_manager:
                stats = session_manager.get_session_stats()
                result["server_statistics"] = {
                    "total_active_sessions": stats["total_sessions"],
                    "initialized_sessions": stats["initialized_sessions"],
                    "average_session_age": f"{stats['average_age_seconds']:.1f}s",
                    "average_request_count": f"{stats['average_request_count']:.1f}",
                    "total_queued_messages": stats["total_queued_messages"],
                    "session_timeout": f"{stats['session_timeout']}s"
                }
                
                # List active sessions (limited)
                all_sessions = session_manager.get_all_sessions(limit=MAX_DISPLAY_SESSIONS)
                if all_sessions:
                    result["active_sessions"] = []
                    for sess in all_sessions:
                        age = time.time() - sess["created_at"] if sess["created_at"] else 0
                        result["active_sessions"].append({
                            "id": sess["session_id"][:8] + "...",
                            "age": f"{int(age)}s",
                            "requests": sess["request_count"],
                            "is_current": sess["session_id"] == session_id
                        })
                    
                    total_count = session_manager.get_session_count()
                    if total_count > MAX_DISPLAY_SESSIONS:
                        result["active_sessions_note"] = f"Showing {MAX_DISPLAY_SESSIONS} of {total_count} total sessions"
            
            result["capabilities"] = {
                "session_persistence": True,
                "message_queuing": True,
                "replay_support": True,
                "horizontal_scaling": False,
                "serverless_ready": False,
                "available_tools": "All 21 tools including stateful-only tools"
            }
        
        return result
    
    logger.debug(f"Registered system tools (stateless_mode={stateless_mode})")