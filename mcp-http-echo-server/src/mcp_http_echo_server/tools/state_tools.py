"""Advanced state tracking tools for MCP Echo Server."""

import os
import sys
import time
import json
import base64
import uuid
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, UTC
from fastmcp import FastMCP, Context
from ..utils.state_adapter import StateAdapter

logger = logging.getLogger(__name__)


def register_state_tools(mcp: FastMCP, stateless_mode: bool):
    """Register advanced state tracking tools.
    
    Args:
        mcp: FastMCP instance
        stateless_mode: Whether server is in stateless mode
    """
    
    @mcp.tool
    async def stateInspector(
        ctx: Context,
        key_pattern: str = "*",
        include_sizes: bool = True,
        max_depth: int = 3
    ) -> Dict[str, Any]:
        """Inspect all state keys and values in current context/session.
        
        Provides deep inspection of state storage with filtering and size analysis.
        
        Args:
            key_pattern: Pattern to filter keys (supports * wildcard)
            include_sizes: Include size information for values
            max_depth: Maximum depth for nested structure display
            
        Returns:
            Detailed state inspection report
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        result = {
            "mode": "stateless" if is_stateless else "stateful",
            "scope": "request" if is_stateless else "session",
            "pattern": key_pattern,
            "states": {},
            "summary": {}
        }
        
        # Get scope prefix
        prefix = StateAdapter.get_scope_prefix(ctx)
        
        # Note: In real implementation, we would need access to all state keys
        # For now, we'll check known state keys
        known_keys = [
            "last_echo", "echo_history", "session_history", "state_manipulations",
            "decoded_token", "goat_identified", "request_headers", "request_start_time",
            "request_id", "session_id", "request_errors", "request_breadcrumbs"
        ]
        
        total_size = 0
        state_count = 0
        
        for key in known_keys:
            # Check if key matches pattern
            if not match_pattern(key, key_pattern):
                continue
            
            value = await StateAdapter.get_state(ctx, key)
            if value is not None:
                state_count += 1
                
                # Prepare state info
                state_info = {
                    "type": type(value).__name__,
                    "value": truncate_value(value, max_depth)
                }
                
                if include_sizes:
                    try:
                        size = sys.getsizeof(value)
                        state_info["size_bytes"] = size
                        total_size += size
                    except:
                        state_info["size_bytes"] = 0
                
                result["states"][key] = state_info
        
        # Add summary
        result["summary"] = {
            "total_keys": state_count,
            "total_size_bytes": total_size,
            "total_size_kb": round(total_size / 1024, 2) if total_size > 0 else 0,
            "average_size_bytes": int(total_size / state_count) if state_count > 0 else 0
        }
        
        if not is_stateless:
            session_id = ctx.get_state("session_id")
            if session_id:
                result["session_id"] = session_id
        
        return result
    
    @mcp.tool
    async def sessionHistory(
        ctx: Context,
        limit: int = 50,
        include_states: bool = False
    ) -> Dict[str, Any]:
        """Show session event history and state changes.
        
        Provides an audit trail of all events and state changes in the session.
        Only available in stateful mode.
        
        Args:
            limit: Maximum number of events to return
            include_states: Include state snapshots with events
            
        Returns:
            Session history and audit trail
        """
        if ctx.get_state("stateless_mode"):
            return {
                "error": "Session history not available in stateless mode",
                "hint": "Use requestTracer for current request events",
                "mode": "stateless"
            }
        
        session_id = ctx.get_state("session_id")
        if not session_id:
            return {"error": "No session ID available"}
        
        # Get session history
        history = await StateAdapter.get_state(ctx, "session_history", [])
        
        # Add current tool call to history
        current_event = {
            "timestamp": time.time(),
            "event": "tool_called",
            "tool": "sessionHistory",
            "request_id": ctx.get_state("request_id")
        }
        history.append(current_event)
        await StateAdapter.set_state(ctx, "session_history", history)
        
        # Format history for display
        formatted_history = []
        for event in history[-limit:]:
            entry = {
                "timestamp": event["timestamp"],
                "iso_time": datetime.fromtimestamp(event["timestamp"], tz=UTC).isoformat(),
                "event_type": event.get("event"),
                "details": {}
            }
            
            # Add relevant details
            if "tool" in event:
                entry["details"]["tool"] = event["tool"]
            if "request_id" in event:
                entry["details"]["request_id"] = event["request_id"]
            if "message" in event:
                entry["details"]["message"] = event["message"]
            
            if include_states and "state_snapshot" in event:
                entry["state_snapshot"] = event["state_snapshot"]
            
            formatted_history.append(entry)
        
        result = {
            "session_id": session_id,
            "total_events": len(history),
            "events_shown": len(formatted_history),
            "history": formatted_history
        }
        
        if history:
            result["session_age_seconds"] = time.time() - history[0]["timestamp"]
            result["events_per_minute"] = len(history) / (result["session_age_seconds"] / 60) if result["session_age_seconds"] > 0 else 0
        
        return result
    
    @mcp.tool
    async def stateManipulator(
        ctx: Context,
        action: str,
        key: str = None,
        value: Any = None,
        source_key: str = None
    ) -> Dict[str, Any]:
        """Manipulate state for debugging purposes.
        
        Allows direct manipulation of state storage for testing and debugging.
        
        Args:
            action: Action to perform (set, delete, clear, copy)
            key: State key to manipulate
            value: Value to set (for set action)
            source_key: Source key (for copy action)
            
        Returns:
            Result of the manipulation operation
        """
        valid_actions = ["set", "delete", "clear", "copy"]
        if action not in valid_actions:
            return {
                "error": f"Invalid action. Must be one of: {', '.join(valid_actions)}",
                "action": action
            }
        
        result = {
            "action": action,
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful",
            "success": False
        }
        
        if action == "set":
            if not key:
                return {**result, "error": "Key required for set action"}
            
            await StateAdapter.set_state(ctx, key, value)
            result.update({
                "success": True,
                "key": key,
                "value_type": type(value).__name__,
                "message": f"State '{key}' set successfully"
            })
            
        elif action == "delete":
            if not key:
                return {**result, "error": "Key required for delete action"}
            
            deleted = await StateAdapter.delete_state(ctx, key)
            result.update({
                "success": deleted,
                "key": key,
                "message": f"State '{key}' {'deleted' if deleted else 'not found'}"
            })
            
        elif action == "clear":
            # Clear all states in current scope
            # Note: This is a simplified implementation
            cleared_count = 0
            known_keys = ["last_echo", "echo_history", "session_history", "decoded_token"]
            
            for key in known_keys:
                if await StateAdapter.delete_state(ctx, key):
                    cleared_count += 1
            
            result.update({
                "success": True,
                "cleared_count": cleared_count,
                "message": f"Cleared {cleared_count} state entries"
            })
            
        elif action == "copy":
            if not key or not source_key:
                return {**result, "error": "Both key and source_key required for copy action"}
            
            source_value = await StateAdapter.get_state(ctx, source_key)
            if source_value is None:
                return {**result, "error": f"Source key '{source_key}' not found"}
            
            await StateAdapter.set_state(ctx, key, source_value)
            result.update({
                "success": True,
                "source_key": source_key,
                "target_key": key,
                "message": f"Copied state from '{source_key}' to '{key}'"
            })
        
        # Log the manipulation
        manipulations = await StateAdapter.get_state(ctx, "state_manipulations", [])
        manipulations.append({
            "timestamp": time.time(),
            "action": action,
            "result": result
        })
        await StateAdapter.set_state(ctx, "state_manipulations", manipulations)
        
        return result
    
    @mcp.tool
    async def sessionCompare(
        ctx: Context,
        other_session_id: str = None
    ) -> Dict[str, Any]:
        """Compare current session with another or show all sessions.
        
        Only available in stateful mode. Compares session metadata and state.
        
        Args:
            other_session_id: Session ID to compare with (optional)
            
        Returns:
            Session comparison or list of all sessions
        """
        if ctx.get_state("stateless_mode"):
            return {
                "error": "Session comparison not available in stateless mode",
                "mode": "stateless"
            }
        
        current_session_id = ctx.get_state("session_id")
        if not current_session_id:
            return {"error": "No current session ID"}
        
        result = {
            "current_session": current_session_id,
            "mode": "stateful"
        }
        
        # Note: In a real implementation, we would access the session manager
        # For now, we'll provide a simplified response
        result["message"] = "Session comparison requires access to session manager"
        result["current_session_info"] = {
            "id": current_session_id,
            "has_echo_history": await StateAdapter.get_state(ctx, "echo_history") is not None,
            "has_session_history": await StateAdapter.get_state(ctx, "session_history") is not None
        }
        
        return result
    
    @mcp.tool
    async def sessionTransfer(
        ctx: Context,
        action: str,
        session_data: Any = None,
        target_session_id: str = None
    ) -> Dict[str, Any]:
        """Export, import, or clone session state.
        
        Allows session state to be exported for backup or transferred between sessions.
        Only available in stateful mode.
        
        Args:
            action: Action to perform (export, import, clone)
            session_data: Data to import (for import action)
            target_session_id: Target session ID (for import/clone)
            
        Returns:
            Result of the transfer operation
        """
        if ctx.get_state("stateless_mode"):
            return {
                "error": "Session transfer not available in stateless mode",
                "mode": "stateless"
            }
        
        valid_actions = ["export", "import", "clone"]
        if action not in valid_actions:
            return {
                "error": f"Invalid action. Must be one of: {', '.join(valid_actions)}",
                "action": action
            }
        
        session_id = ctx.get_state("session_id")
        if not session_id and action != "import":
            return {"error": "No session ID available"}
        
        if action == "export":
            # Export current session state
            export_data = {
                "session_id": session_id,
                "exported_at": time.time(),
                "states": {}
            }
            
            # Collect key state values
            state_keys = ["last_echo", "echo_history", "session_history", "decoded_token"]
            for key in state_keys:
                value = await StateAdapter.get_state(ctx, key)
                if value is not None:
                    export_data["states"][key] = value
            
            # Encode as base64 for easy transfer
            json_data = json.dumps(export_data, default=str)
            encoded = base64.b64encode(json_data.encode()).decode()
            
            return {
                "action": "export",
                "session_id": session_id,
                "state_count": len(export_data["states"]),
                "export_token": encoded[:100] + "..." if len(encoded) > 100 else encoded,
                "size_bytes": len(encoded)
            }
        
        elif action == "import":
            return {
                "action": "import",
                "message": "Import functionality would restore state from export token",
                "note": "Full implementation requires state management access"
            }
        
        elif action == "clone":
            return {
                "action": "clone",
                "source_session": session_id,
                "message": "Clone functionality would duplicate session state",
                "note": "Full implementation requires session manager access"
            }
        
        return {"error": "Unexpected error in session transfer"}
    
    @mcp.tool
    async def stateBenchmark(
        ctx: Context,
        operations: int = 100,
        data_size: str = "small"
    ) -> Dict[str, Any]:
        """Benchmark state operations performance.
        
        Tests the performance of state read/write/delete operations.
        
        Args:
            operations: Number of operations to perform
            data_size: Size of test data (small, medium, large)
            
        Returns:
            Performance benchmark results
        """
        # Validate inputs
        if operations < 1 or operations > 10000:
            return {"error": "Operations must be between 1 and 10000"}
        
        if data_size not in ["small", "medium", "large"]:
            return {"error": "Data size must be small, medium, or large"}
        
        # Generate test data
        if data_size == "small":
            test_data = "x" * 100
        elif data_size == "medium":
            test_data = "x" * 10000
        else:
            test_data = "x" * 100000
        
        result = {
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful",
            "operations": operations,
            "data_size": data_size,
            "data_bytes": len(test_data)
        }
        
        # Benchmark writes
        write_start = time.perf_counter()
        for i in range(operations):
            await StateAdapter.set_state(ctx, f"benchmark_test_{i}", test_data)
        write_time = time.perf_counter() - write_start
        
        # Benchmark reads
        read_start = time.perf_counter()
        for i in range(operations):
            _ = await StateAdapter.get_state(ctx, f"benchmark_test_{i}")
        read_time = time.perf_counter() - read_start
        
        # Benchmark deletes
        delete_start = time.perf_counter()
        for i in range(operations):
            await StateAdapter.delete_state(ctx, f"benchmark_test_{i}")
        delete_time = time.perf_counter() - delete_start
        
        # Calculate metrics
        result["write"] = {
            "total_ms": round(write_time * 1000, 2),
            "per_op_ms": round((write_time * 1000) / operations, 4),
            "ops_per_sec": int(operations / write_time) if write_time > 0 else 0
        }
        
        result["read"] = {
            "total_ms": round(read_time * 1000, 2),
            "per_op_ms": round((read_time * 1000) / operations, 4),
            "ops_per_sec": int(operations / read_time) if read_time > 0 else 0
        }
        
        result["delete"] = {
            "total_ms": round(delete_time * 1000, 2),
            "per_op_ms": round((delete_time * 1000) / operations, 4),
            "ops_per_sec": int(operations / delete_time) if delete_time > 0 else 0
        }
        
        result["summary"] = {
            "total_time_ms": round((write_time + read_time + delete_time) * 1000, 2),
            "fastest_operation": min(["write", "read", "delete"], key=lambda x: result[x]["per_op_ms"])
        }
        
        return result
    
    @mcp.tool
    async def sessionLifecycle(
        ctx: Context,
        show_events: bool = True,
        show_stats: bool = True
    ) -> Dict[str, Any]:
        """Display session lifecycle information and events.
        
        Shows session phase, age, expiry information, and lifecycle events.
        Only meaningful in stateful mode.
        
        Args:
            show_events: Include lifecycle events
            show_stats: Include session statistics
            
        Returns:
            Session lifecycle information
        """
        if ctx.get_state("stateless_mode"):
            return {
                "mode": "stateless",
                "lifecycle": "request-scoped",
                "message": "No session lifecycle in stateless mode",
                "request_info": {
                    "request_id": ctx.get_state("request_id"),
                    "start_time": ctx.get_state("request_start_time")
                }
            }
        
        session_id = ctx.get_state("session_id")
        if not session_id:
            return {"error": "No session ID available"}
        
        session_data = ctx.get_state(f"session_{session_id}_data", {})
        
        result = {
            "session_id": session_id,
            "phase": "active",
            "mode": "stateful"
        }
        
        # Calculate lifecycle metrics
        current_time = time.time()
        if session_data and "created_at" in session_data:
            created_at = session_data["created_at"]
            last_activity = session_data.get("last_activity", created_at)
            
            age = current_time - created_at
            idle_time = current_time - last_activity
            
            result["timing"] = {
                "created_at": datetime.fromtimestamp(created_at, tz=UTC).isoformat(),
                "last_activity": datetime.fromtimestamp(last_activity, tz=UTC).isoformat(),
                "age_seconds": round(age, 1),
                "age_human": format_duration(age),
                "idle_seconds": round(idle_time, 1),
                "request_count": session_data.get("request_count", 0)
            }
            
            # Estimate expiry (assuming 3600 second timeout)
            timeout = 3600
            time_until_expiry = timeout - idle_time
            
            result["expiry"] = {
                "timeout_seconds": timeout,
                "expires_in_seconds": max(0, round(time_until_expiry, 1)),
                "expiry_risk": "high" if time_until_expiry < 60 else "medium" if time_until_expiry < 300 else "low"
            }
        
        if show_events:
            # Get lifecycle events
            events = await StateAdapter.get_state(ctx, "lifecycle_events", [])
            if not events:
                # Create sample events
                events = [
                    {"type": "session_created", "timestamp": session_data.get("created_at", current_time)},
                    {"type": "session_initialized", "timestamp": session_data.get("created_at", current_time) + 0.1}
                ]
            result["events"] = events[-10:]  # Last 10 events
        
        if show_stats:
            # Calculate statistics
            history = await StateAdapter.get_state(ctx, "session_history", [])
            echo_history = await StateAdapter.get_state(ctx, "echo_history", [])
            
            result["statistics"] = {
                "total_events": len(history),
                "echo_count": len(echo_history) if echo_history else 0,
                "state_keys_used": 5  # Simplified count
            }
        
        return result
    
    @mcp.tool
    async def stateValidator(
        ctx: Context,
        validate_types: bool = True,
        validate_size: bool = True,
        max_size_mb: float = 1.0
    ) -> Dict[str, Any]:
        """Validate state consistency and identify issues.
        
        Checks for state consistency issues, size violations, and orphaned states.
        
        Args:
            validate_types: Check for unusual type usage
            validate_size: Check for size limit violations
            max_size_mb: Maximum size per state in MB
            
        Returns:
            Validation report with issues and warnings
        """
        issues = []
        warnings = []
        stats = {
            "total_states": 0,
            "total_size_bytes": 0,
            "largest_state": None,
            "largest_size": 0
        }
        
        # Check known state keys
        state_keys = ["last_echo", "echo_history", "session_history", "decoded_token", "state_manipulations"]
        
        for key in state_keys:
            value = await StateAdapter.get_state(ctx, key)
            if value is None:
                continue
            
            stats["total_states"] += 1
            
            # Check size
            try:
                size = sys.getsizeof(value)
                stats["total_size_bytes"] += size
                
                if size > stats["largest_size"]:
                    stats["largest_size"] = size
                    stats["largest_state"] = key
                
                if validate_size and size > max_size_mb * 1024 * 1024:
                    issues.append({
                        "type": "size_exceeded",
                        "key": key,
                        "size_mb": round(size / (1024 * 1024), 2),
                        "limit_mb": max_size_mb
                    })
            except:
                warnings.append({
                    "type": "size_check_failed",
                    "key": key
                })
            
            # Check types
            if validate_types:
                if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                    warnings.append({
                        "type": "unusual_type",
                        "key": key,
                        "actual_type": type(value).__name__
                    })
        
        result = {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "statistics": {
                **stats,
                "total_size_mb": round(stats["total_size_bytes"] / (1024 * 1024), 2),
                "average_size_bytes": int(stats["total_size_bytes"] / max(1, stats["total_states"]))
            },
            "health": "healthy" if len(issues) == 0 else "unhealthy" if len(issues) > 5 else "degraded"
        }
        
        return result
    
    @mcp.tool
    async def requestTracer(
        ctx: Context,
        include_headers: bool = True,
        include_timing: bool = True
    ) -> Dict[str, Any]:
        """Trace the current request flow and context.
        
        Provides detailed tracing of the current request including headers,
        timing, and breadcrumbs.
        
        Args:
            include_headers: Include request headers in trace
            include_timing: Include timing information
            
        Returns:
            Request trace information
        """
        trace = {
            "request_id": ctx.get_state("request_id", "unknown"),
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful",
            "timestamp": time.time()
        }
        
        # Add session info if stateful
        if not ctx.get_state("stateless_mode"):
            session_id = ctx.get_state("session_id")
            if session_id:
                trace["session_id"] = session_id
                session_data = ctx.get_state(f"session_{session_id}_data", {})
                trace["session_request_number"] = session_data.get("request_count", 0)
        
        # Include headers if requested
        if include_headers:
            headers = ctx.get_state("request_headers", {})
            trace["headers"] = {
                "mcp_session_id": headers.get("mcp-session-id"),
                "accept": headers.get("accept"),
                "content_type": headers.get("content-type"),
                "user_agent": headers.get("user-agent"),
                "x_forwarded_for": headers.get("x-forwarded-for"),
                "origin": headers.get("origin")
            }
        
        # Include timing if requested
        if include_timing:
            start_time = ctx.get_state("request_start_time")
            if start_time:
                elapsed = time.time() - start_time
                trace["timing"] = {
                    "start_time": start_time,
                    "elapsed_seconds": round(elapsed, 3),
                    "elapsed_ms": round(elapsed * 1000, 1),
                    "phase": "processing"
                }
        
        # Add breadcrumbs
        breadcrumbs = ctx.get_state("request_breadcrumbs", [])
        breadcrumbs.append({
            "tool": "requestTracer",
            "timestamp": time.time()
        })
        ctx.set_state("request_breadcrumbs", breadcrumbs)
        
        trace["breadcrumbs"] = breadcrumbs
        trace["breadcrumb_count"] = len(breadcrumbs)
        
        return trace
    
    @mcp.tool
    async def modeDetector(ctx: Context) -> Dict[str, Any]:
        """Detect and explain the current operational mode.
        
        Analyzes various indicators to determine the current mode and capabilities.
        
        Returns:
            Mode detection analysis with capabilities and recommendations
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        result = {
            "detected_mode": "stateless" if is_stateless else "stateful",
            "confidence": "high",
            "timestamp": time.time()
        }
        
        # Check various indicators
        indicators = {
            "stateless_flag": ctx.get_state("stateless_mode", False),
            "has_session_id": ctx.get_state("session_id") is not None,
            "has_session_data": ctx.get_state(f"session_{ctx.get_state('session_id')}_data") is not None if ctx.get_state("session_id") else False,
            "has_request_id": ctx.get_state("request_id") is not None
        }
        
        result["indicators"] = indicators
        
        # Determine capabilities based on mode
        if is_stateless:
            result["capabilities"] = {
                "session_persistence": False,
                "message_queuing": False,
                "replay_support": False,
                "state_transfer": False,
                "session_history": False,
                "horizontal_scaling": True,
                "serverless_ready": True,
                "memory_efficient": True,
                "request_isolation": True
            }
            
            result["recommendations"] = [
                "Use for high-traffic API endpoints",
                "Deploy in serverless environments (Lambda, Cloud Functions)",
                "Suitable for stateless microservices",
                "Ideal for horizontal auto-scaling"
            ]
            
            result["limitations"] = [
                "No session state persistence",
                "No replay functionality",
                "No message queuing",
                "No session history tracking"
            ]
        else:
            result["capabilities"] = {
                "session_persistence": True,
                "message_queuing": True,
                "replay_support": True,
                "state_transfer": True,
                "session_history": True,
                "horizontal_scaling": False,
                "serverless_ready": False,
                "memory_efficient": False,
                "request_isolation": False
            }
            
            result["recommendations"] = [
                "Use for interactive debugging sessions",
                "Deploy with sticky session load balancing",
                "Suitable for development and testing",
                "Ideal for complex stateful workflows"
            ]
            
            result["limitations"] = [
                "Requires session affinity for scaling",
                "Higher memory usage per session",
                "Not suitable for serverless",
                "Session cleanup overhead"
            ]
        
        # Environment detection
        result["environment"] = {
            "kubernetes": os.getenv("KUBERNETES_SERVICE_HOST") is not None,
            "docker": os.path.exists("/.dockerenv"),
            "lambda": os.getenv("LAMBDA_RUNTIME_DIR") is not None,
            "ci": os.getenv("CI") is not None,
            "github_actions": os.getenv("GITHUB_ACTIONS") is not None,
            "recommended_mode": "stateless" if (
                os.getenv("KUBERNETES_SERVICE_HOST") is not None or
                os.getenv("LAMBDA_RUNTIME_DIR") is not None
            ) else "stateful"
        }
        
        return result
    
    logger.debug(f"Registered state tools (stateless_mode={stateless_mode})")


def match_pattern(text: str, pattern: str) -> bool:
    """Match text against a simple wildcard pattern.
    
    Args:
        text: Text to match
        pattern: Pattern with * wildcards
        
    Returns:
        True if matches
    """
    if pattern == "*":
        return True
    
    # Simple wildcard matching
    import re
    regex = pattern.replace("*", ".*")
    return bool(re.match(f"^{regex}$", text))


def truncate_value(value: Any, max_depth: int) -> Any:
    """Truncate value for display.
    
    Args:
        value: Value to truncate
        max_depth: Maximum depth for nested structures
        
    Returns:
        Truncated value
    """
    if max_depth <= 0:
        return "..."
    
    if isinstance(value, str):
        return value[:100] + "..." if len(value) > 100 else value
    elif isinstance(value, (list, tuple)):
        return [truncate_value(v, max_depth - 1) for v in value[:5]]
    elif isinstance(value, dict):
        return {k: truncate_value(v, max_depth - 1) for k, v in list(value.items())[:5]}
    else:
        return value


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human-readable duration
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"