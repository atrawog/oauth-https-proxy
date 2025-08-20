"""State management tools for MCP server."""

import json
import logging
import random
import time
from typing import Dict, Any, List, Optional, Union

# Try to import from MCP SDK, fall back to simple implementation
try:
    from mcp.server import FastMCP
except ImportError:
    from ..simple_mcp import FastMCP

logger = logging.getLogger(__name__)


def register_state_tools(mcp: FastMCP, context: dict):
    """Register state management tools.
    
    Args:
        mcp: FastMCP instance
        context: Dictionary containing dependencies
    """
    
    storage = context["storage"]
    unified_logger = context["logger"]
    state_manager = context["state_manager"]
    stateless_mode = context["stateless_mode"]
    
    @mcp.tool()
    async def stateInspector(session_id: Optional[str] = None) -> Dict[str, Any]:
        """Inspect all state data for a session.
        
        Args:
            session_id: Session ID to inspect (default: 'default')
            
        Returns:
            Complete state information
        """
        if not session_id:
            session_id = "default"
        
        state_info = {
            "session_id": session_id,
            "mode": "stateless" if stateless_mode else "stateful",
            "timestamp": time.time(),
            "state": {}
        }
        
        # Get all state keys for this session
        state_keys = await state_manager.list_state_keys(session_id)
        
        # Retrieve all state values
        for key in state_keys:
            value = await state_manager.get_state(session_id, key)
            state_info["state"][key] = value
        
        state_info["state_count"] = len(state_keys)
        
        # In stateful mode, add session metadata
        if not stateless_mode:
            session_data = await state_manager.get_session(session_id)
            if session_data:
                state_info["session_metadata"] = {
                    "created_at": session_data["created_at"],
                    "last_accessed": session_data["last_accessed"],
                    "age_seconds": time.time() - session_data["created_at"]
                }
        
        await unified_logger.event("mcp_state_inspect", {
            "session_id": session_id,
            "state_count": len(state_keys)
        })
        
        return state_info
    
    @mcp.tool()
    async def sessionHistory(session_id: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Get session activity history.
        
        Args:
            session_id: Session ID (default: 'default')
            limit: Maximum number of history entries to return
            
        Returns:
            List of historical events
        """
        if stateless_mode:
            return [{
                "message": "Session history is not available in stateless mode",
                "mode": "stateless"
            }]
        
        if not session_id:
            session_id = "default"
        
        # Get echo history as an example of session history
        echo_history = await state_manager.get_state(session_id, "echo_history", [])
        
        # Get other activity markers
        activities = []
        
        # Add echo history
        for echo in echo_history[-limit:]:
            activities.append({
                "type": "echo",
                "timestamp": echo.get("timestamp", 0),
                "data": {"message": echo.get("message")}
            })
        
        # Check for other state changes (simplified)
        state_keys = await state_manager.list_state_keys(session_id)
        for key in state_keys:
            if key not in ["echo_history", "last_echo"]:
                value = await state_manager.get_state(session_id, key)
                activities.append({
                    "type": "state_change",
                    "timestamp": time.time(),  # We don't track individual timestamps
                    "data": {"key": key, "value_type": type(value).__name__}
                })
        
        # Sort by timestamp
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        
        await unified_logger.event("mcp_session_history", {
            "session_id": session_id,
            "history_count": len(activities)
        })
        
        return activities[:limit]
    
    @mcp.tool()
    async def stateManipulator(
        session_id: str,
        operation: str,
        key: str,
        value: Optional[Union[str, int, float, bool, dict, list]] = None
    ) -> Dict[str, Any]:
        """Manipulate session state directly.
        
        Args:
            session_id: Session ID
            operation: Operation to perform (get, set, delete, clear)
            key: State key
            value: Value for set operation
            
        Returns:
            Operation result
        """
        result = {
            "session_id": session_id,
            "operation": operation,
            "key": key,
            "success": False
        }
        
        try:
            if operation == "get":
                value = await state_manager.get_state(session_id, key)
                result["value"] = value
                result["success"] = True
                
            elif operation == "set":
                if value is None:
                    result["error"] = "Value required for set operation"
                else:
                    success = await state_manager.set_state(session_id, key, value)
                    result["success"] = success
                    result["value"] = value
                    
            elif operation == "delete":
                success = await state_manager.delete_state(session_id, key)
                result["success"] = success
                result["deleted"] = success
                
            elif operation == "clear":
                count = await state_manager.clear_state(session_id)
                result["success"] = True
                result["cleared_keys"] = count
                
            else:
                result["error"] = f"Unknown operation: {operation}"
        
        except Exception as e:
            result["error"] = str(e)
        
        await unified_logger.event("mcp_state_manipulate", {
            "session_id": session_id,
            "operation": operation,
            "key": key,
            "success": result["success"]
        })
        
        return result
    
    @mcp.tool()
    async def sessionCompare(session_id1: str, session_id2: str) -> Dict[str, Any]:
        """Compare state between two sessions.
        
        Args:
            session_id1: First session ID
            session_id2: Second session ID
            
        Returns:
            Comparison results
        """
        # Get state for both sessions
        keys1 = set(await state_manager.list_state_keys(session_id1))
        keys2 = set(await state_manager.list_state_keys(session_id2))
        
        comparison = {
            "session1": session_id1,
            "session2": session_id2,
            "keys_only_in_session1": list(keys1 - keys2),
            "keys_only_in_session2": list(keys2 - keys1),
            "common_keys": list(keys1 & keys2),
            "differences": {}
        }
        
        # Compare values for common keys
        for key in comparison["common_keys"]:
            value1 = await state_manager.get_state(session_id1, key)
            value2 = await state_manager.get_state(session_id2, key)
            
            if value1 != value2:
                comparison["differences"][key] = {
                    "session1_value": value1,
                    "session2_value": value2
                }
        
        comparison["summary"] = {
            "total_keys_session1": len(keys1),
            "total_keys_session2": len(keys2),
            "unique_to_session1": len(comparison["keys_only_in_session1"]),
            "unique_to_session2": len(comparison["keys_only_in_session2"]),
            "common_keys": len(comparison["common_keys"]),
            "different_values": len(comparison["differences"])
        }
        
        await unified_logger.event("mcp_session_compare", {
            "session1": session_id1,
            "session2": session_id2,
            "differences": len(comparison["differences"])
        })
        
        return comparison
    
    @mcp.tool()
    async def sessionTransfer(
        source_session: str,
        target_session: str,
        keys: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Transfer state from one session to another.
        
        Args:
            source_session: Source session ID
            target_session: Target session ID
            keys: Specific keys to transfer (None = all)
            
        Returns:
            Transfer results
        """
        if stateless_mode:
            return {
                "error": "Session transfer is not available in stateless mode",
                "mode": "stateless"
            }
        
        result = {
            "source": source_session,
            "target": target_session,
            "transferred": [],
            "failed": [],
            "success": False
        }
        
        try:
            # Get keys to transfer
            if keys is None:
                keys = await state_manager.list_state_keys(source_session)
            
            # Transfer each key
            for key in keys:
                try:
                    value = await state_manager.get_state(source_session, key)
                    if value is not None:
                        success = await state_manager.set_state(target_session, key, value)
                        if success:
                            result["transferred"].append(key)
                        else:
                            result["failed"].append(key)
                except Exception as e:
                    result["failed"].append(f"{key}: {str(e)}")
            
            result["success"] = len(result["failed"]) == 0
            result["summary"] = {
                "total_keys": len(keys),
                "transferred": len(result["transferred"]),
                "failed": len(result["failed"])
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        await unified_logger.event("mcp_session_transfer", {
            "source": source_session,
            "target": target_session,
            "transferred": len(result["transferred"]),
            "failed": len(result["failed"])
        })
        
        return result
    
    @mcp.tool()
    async def stateBenchmark(
        operations: int = 100,
        data_size: str = "small"
    ) -> Dict[str, Any]:
        """Benchmark state operations performance.
        
        Args:
            operations: Number of operations to perform
            data_size: Size of test data (small, medium, large)
            
        Returns:
            Benchmark results
        """
        # Generate test data based on size
        if data_size == "small":
            test_data = "x" * 100
        elif data_size == "medium":
            test_data = "x" * 1000
        elif data_size == "large":
            test_data = "x" * 10000
        else:
            test_data = "x" * 100
        
        session_id = f"benchmark_{int(time.time())}"
        results = {
            "operations": operations,
            "data_size": data_size,
            "data_bytes": len(test_data),
            "timings": {}
        }
        
        # Benchmark writes
        start_time = time.time()
        for i in range(operations):
            await state_manager.set_state(session_id, f"benchmark_key_{i}", test_data)
        write_time = time.time() - start_time
        results["timings"]["write"] = {
            "total_seconds": write_time,
            "ops_per_second": operations / write_time if write_time > 0 else 0,
            "avg_ms": (write_time * 1000) / operations
        }
        
        # Benchmark reads
        start_time = time.time()
        for i in range(operations):
            await state_manager.get_state(session_id, f"benchmark_key_{i}")
        read_time = time.time() - start_time
        results["timings"]["read"] = {
            "total_seconds": read_time,
            "ops_per_second": operations / read_time if read_time > 0 else 0,
            "avg_ms": (read_time * 1000) / operations
        }
        
        # Benchmark deletes
        start_time = time.time()
        for i in range(operations):
            await state_manager.delete_state(session_id, f"benchmark_key_{i}")
        delete_time = time.time() - start_time
        results["timings"]["delete"] = {
            "total_seconds": delete_time,
            "ops_per_second": operations / delete_time if delete_time > 0 else 0,
            "avg_ms": (delete_time * 1000) / operations
        }
        
        # Clean up
        await state_manager.delete_session(session_id)
        
        results["summary"] = {
            "total_time": write_time + read_time + delete_time,
            "fastest_operation": min(results["timings"], key=lambda k: results["timings"][k]["avg_ms"]),
            "slowest_operation": max(results["timings"], key=lambda k: results["timings"][k]["avg_ms"])
        }
        
        await unified_logger.event("mcp_state_benchmark", results)
        
        return results
    
    @mcp.tool()
    async def sessionLifecycle(session_id: str, action: str) -> Dict[str, Any]:
        """Manage session lifecycle (create, refresh, expire, delete).
        
        Args:
            session_id: Session ID
            action: Action to perform (create, refresh, expire, delete)
            
        Returns:
            Action result
        """
        if stateless_mode and action != "create":
            return {
                "error": "Session lifecycle management is limited in stateless mode",
                "mode": "stateless"
            }
        
        result = {
            "session_id": session_id,
            "action": action,
            "success": False
        }
        
        try:
            if action == "create":
                session_data = await state_manager.create_session(session_id)
                result["session"] = session_data
                result["success"] = True
                
            elif action == "refresh":
                session_data = await state_manager.get_session(session_id)
                if session_data:
                    result["session"] = session_data
                    result["success"] = True
                else:
                    result["error"] = "Session not found"
                    
            elif action == "expire":
                # Set session to expire immediately
                session_key = f"{state_manager.session_prefix}:{session_id}"
                success = await storage.expire(session_key, 1)  # Expire in 1 second
                result["success"] = success
                result["expires_in"] = 1 if success else None
                
            elif action == "delete":
                success = await state_manager.delete_session(session_id)
                result["success"] = success
                result["deleted"] = success
                
            else:
                result["error"] = f"Unknown action: {action}"
        
        except Exception as e:
            result["error"] = str(e)
        
        await unified_logger.event("mcp_session_lifecycle", {
            "session_id": session_id,
            "action": action,
            "success": result["success"]
        })
        
        return result
    
    @mcp.tool()
    async def stateValidator(
        session_id: str,
        schema: Dict[str, str]
    ) -> Dict[str, Any]:
        """Validate session state against a schema.
        
        Args:
            session_id: Session ID
            schema: Expected schema (key -> type mapping)
            
        Returns:
            Validation results
        """
        validation = {
            "session_id": session_id,
            "valid": True,
            "errors": [],
            "warnings": [],
            "state": {}
        }
        
        # Get current state
        state_keys = await state_manager.list_state_keys(session_id)
        
        # Check required keys
        for key, expected_type in schema.items():
            if key not in state_keys:
                validation["errors"].append(f"Missing required key: {key}")
                validation["valid"] = False
            else:
                value = await state_manager.get_state(session_id, key)
                validation["state"][key] = value
                
                # Type validation
                if expected_type == "string" and not isinstance(value, str):
                    validation["errors"].append(f"Key '{key}' should be string, got {type(value).__name__}")
                    validation["valid"] = False
                elif expected_type == "number" and not isinstance(value, (int, float)):
                    validation["errors"].append(f"Key '{key}' should be number, got {type(value).__name__}")
                    validation["valid"] = False
                elif expected_type == "boolean" and not isinstance(value, bool):
                    validation["errors"].append(f"Key '{key}' should be boolean, got {type(value).__name__}")
                    validation["valid"] = False
                elif expected_type == "object" and not isinstance(value, dict):
                    validation["errors"].append(f"Key '{key}' should be object, got {type(value).__name__}")
                    validation["valid"] = False
                elif expected_type == "array" and not isinstance(value, list):
                    validation["errors"].append(f"Key '{key}' should be array, got {type(value).__name__}")
                    validation["valid"] = False
        
        # Check for extra keys
        extra_keys = set(state_keys) - set(schema.keys())
        if extra_keys:
            validation["warnings"].append(f"Extra keys found: {list(extra_keys)}")
        
        validation["summary"] = {
            "expected_keys": len(schema),
            "found_keys": len(state_keys),
            "missing_keys": len([e for e in validation["errors"] if "Missing" in e]),
            "type_errors": len([e for e in validation["errors"] if "should be" in e])
        }
        
        await unified_logger.event("mcp_state_validate", {
            "session_id": session_id,
            "valid": validation["valid"],
            "errors": len(validation["errors"])
        })
        
        return validation
    
    @mcp.tool()
    async def requestTracer(trace_id: Optional[str] = None) -> Dict[str, Any]:
        """Trace request flow and state changes.
        
        Args:
            trace_id: Specific trace ID to look up
            
        Returns:
            Trace information
        """
        if trace_id:
            # Look up specific trace
            trace_key = f"mcp:trace:{trace_id}"
            trace_data = await storage.redis_client.hgetall(trace_key)
            
            if trace_data:
                return {
                    "trace_id": trace_id,
                    "found": True,
                    "data": trace_data
                }
            else:
                return {
                    "trace_id": trace_id,
                    "found": False,
                    "message": "Trace not found"
                }
        else:
            # Generate new trace ID and start tracing
            trace_id = f"trace_{int(time.time())}_{random.randint(1000, 9999)}"
            trace_data = {
                "trace_id": trace_id,
                "started_at": time.time(),
                "events": []
            }
            
            # Store trace
            # Store trace data
            trace_key = f"mcp:trace:{trace_id}"
            await storage.redis_client.hset(trace_key, "trace_id", trace_id)
            await storage.redis_client.hset(trace_key, "started_at", str(time.time()))
            
            await unified_logger.event("mcp_request_trace", {
                "trace_id": trace_id,
                "action": "started"
            })
            
            return trace_data
    
    @mcp.tool()
    async def modeDetector() -> Dict[str, Any]:
        """Detect and report the current server mode and capabilities.
        
        Returns:
            Mode information and capabilities
        """
        mode_info = {
            "current_mode": "stateless" if stateless_mode else "stateful",
            "capabilities": {
                "session_persistence": not stateless_mode,
                "state_management": True,
                "cross_request_state": not stateless_mode,
                "session_transfer": not stateless_mode,
                "session_history": not stateless_mode
            },
            "configuration": {
                "session_timeout": state_manager.session_timeout if not stateless_mode else None,
                "redis_connected": await storage.health_check()
            },
            "recommendations": []
        }
        
        # Add mode-specific recommendations
        if stateless_mode:
            mode_info["recommendations"] = [
                "Use for high-traffic, scalable deployments",
                "Each request is independent",
                "No session overhead",
                "Suitable for serverless environments"
            ]
        else:
            mode_info["recommendations"] = [
                "Use for development and debugging",
                "Full session persistence across requests",
                "Session history and replay capabilities",
                "State inspection and manipulation"
            ]
        
        # Check environment hints
        import os
        if os.getenv("KUBERNETES_SERVICE_HOST"):
            mode_info["environment"] = "kubernetes"
        elif os.getenv("LAMBDA_RUNTIME_DIR"):
            mode_info["environment"] = "aws_lambda"
        elif os.getenv("FUNCTIONS_WORKER_RUNTIME"):
            mode_info["environment"] = "azure_functions"
        else:
            mode_info["environment"] = "standalone"
        
        await unified_logger.event("mcp_mode_detect", mode_info)
        
        return mode_info
    
    logger.info("Registered state tools: stateInspector, sessionHistory, stateManipulator, "
                "sessionCompare, sessionTransfer, stateBenchmark, sessionLifecycle, "
                "stateValidator, requestTracer, modeDetector")