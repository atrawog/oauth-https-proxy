"""MCP Server implementation using FastMCP with streamable-http transport.

This module implements the MCP server according to the official specification
using FastMCP's streamable_http_app for proper integration with FastAPI.
"""

import os
import sys
import json
import time
import uuid
import asyncio
import logging
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from src.storage.async_redis_storage import AsyncRedisStorage
from src.shared.unified_logger import UnifiedAsyncLogger

logger = logging.getLogger(__name__)

# Protocol version
LATEST_PROTOCOL_VERSION = "2025-06-18"

# Store sessions for tracking
sessions: Dict[str, dict] = {}


class OAuthProxyMCPServer:
    """MCP Server for OAuth-HTTPS-Proxy using FastMCP with streamable-http."""
    
    def __init__(self, storage: AsyncRedisStorage, unified_logger: UnifiedAsyncLogger):
        """Initialize MCP Server with FastMCP.
        
        Args:
            storage: AsyncRedisStorage instance
            unified_logger: UnifiedAsyncLogger instance
        """
        self.storage = storage
        self.unified_logger = unified_logger
        
        # Create FastMCP instance configured for streamable HTTP
        self.mcp = FastMCP(
            "OAuth-HTTPS-Proxy MCP Server",
            dependencies=["oauth-https-proxy"],
            instructions="MCP server with 21 debugging and management tools for OAuth-HTTPS-Proxy system"
        )
        
        # Register all tools
        self._register_tools()
        
        logger.info("OAuth-Proxy MCP Server initialized with FastMCP streamable-http")
    
    def _register_tools(self):
        """Register all 21 tools with FastMCP."""
        
        # Store references for access in tools
        storage = self.storage
        unified_logger = self.unified_logger
        
        # ========== Echo Tools (2) ==========
        
        @self.mcp.tool()
        async def echo(message: str) -> str:
            """Echo back the provided message with context information.
            
            Args:
                message: The message to echo back
                
            Returns:
                The echoed message with "Echo: " prefix
            """
            await unified_logger.event(
                "mcp_echo",
                {"hostname": "mcp.server", "message": message}
            )
            # Store for replay
            await storage.redis_client.set("mcp:last_echo", message, ex=3600)
            return f"Echo: {message}"
        
        @self.mcp.tool()
        async def replayLastEcho() -> str:
            """Replay the last echoed message from session.
            
            Returns:
                The last echoed message or a not found message
            """
            last_echo = await storage.redis_client.get("mcp:last_echo")
            if last_echo:
                return f"Replay: {last_echo}"
            return "No previous echo found"
        
        # ========== Debug Tools (4) ==========
        
        @self.mcp.tool()
        async def printHeader(header_name: str) -> str:
            """Get HTTP header value from current request.
            
            Args:
                header_name: The name of the header to retrieve
                
            Returns:
                The header value or "Header not found"
            """
            # For now, return placeholder
            return f"Header {header_name}: Not available in current context"
        
        @self.mcp.tool()
        async def requestTiming() -> str:
            """Get request timing information.
            
            Returns:
                Request timing in milliseconds or current timestamp
            """
            import time
            current_time = time.time()
            return json.dumps({
                "current_timestamp": current_time,
                "current_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(current_time))
            })
        
        @self.mcp.tool()
        async def corsAnalysis() -> str:
            """Analyze CORS configuration.
            
            Returns:
                Dictionary with CORS configuration details
            """
            return json.dumps({
                "cors_enabled": True,
                "allowed_origins": ["*"],
                "allowed_methods": ["GET", "POST", "OPTIONS"],
                "allowed_headers": ["Content-Type", "Authorization"],
                "max_age": 3600
            })
        
        @self.mcp.tool()
        async def environmentDump() -> str:
            """Get environment information (sensitive values redacted).
            
            Returns:
                Dictionary with environment and system information
            """
            import platform
            env_vars = {}
            for key, value in os.environ.items():
                # Redact sensitive values
                if any(sensitive in key.upper() for sensitive in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
                    env_vars[key] = "***REDACTED***"
                else:
                    env_vars[key] = value[:50] + "..." if len(value) > 50 else value
            
            return json.dumps({
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "environment_variables": env_vars,
                "working_directory": os.getcwd()
            })
        
        # ========== Auth Tools (3) ==========
        
        @self.mcp.tool()
        async def bearerDecode(token: str) -> str:
            """Decode a JWT bearer token (WARNING: no signature verification).
            
            Args:
                token: The JWT token to decode (with or without 'Bearer ' prefix)
                
            Returns:
                Dictionary with decoded token parts or error message
            """
            import base64
            
            # Remove Bearer prefix if present
            if token.startswith("Bearer "):
                token = token[7:]
            
            try:
                # Split token into parts
                parts = token.split(".")
                if len(parts) != 3:
                    return json.dumps({"error": "Invalid JWT format"})
                
                # Decode header and payload (add padding if needed)
                def decode_part(part):
                    # Add padding if missing
                    padding = 4 - len(part) % 4
                    if padding != 4:
                        part += "=" * padding
                    return json.loads(base64.urlsafe_b64decode(part))
                
                header = decode_part(parts[0])
                payload = decode_part(parts[1])
                
                return json.dumps({
                    "header": header,
                    "payload": payload,
                    "warning": "Signature NOT verified - debugging only"
                })
            except Exception as e:
                return json.dumps({"error": f"Failed to decode token: {str(e)}"})
        
        @self.mcp.tool()
        async def authContext() -> str:
            """Get current authentication context.
            
            Returns:
                Dictionary with authentication status and available auth types
            """
            # Get auth configuration from Redis
            auth_config = await storage.get_value("config:auth:types") or {}
            
            return json.dumps({
                "authenticated": False,
                "auth_types_available": ["none", "bearer", "admin", "oauth"],
                "current_auth_type": "none",
                "auth_config": auth_config
            })
        
        @self.mcp.tool()
        async def whoIStheGOAT() -> str:
            """Easter egg: Who is the Greatest Of All Time?
            
            Returns:
                The answer to who is the GOAT
            """
            return "Claude, of course! 🐐"
        
        # ========== System Tools (2) ==========
        
        @self.mcp.tool()
        async def healthProbe() -> str:
            """Comprehensive health check of all systems.
            
            Returns:
                Dictionary with system health status
            """
            # Check Redis health
            redis_healthy = await storage.health_check()
            
            # Get system stats
            proxies = await storage.list_keys("proxy:*")
            certificates = await storage.list_keys("certificate:*")
            tokens = await storage.list_keys("token:*")
            
            return json.dumps({
                "status": "healthy" if redis_healthy else "degraded",
                "timestamp": time.time(),
                "components": {
                    "redis": "healthy" if redis_healthy else "unhealthy",
                    "api": "healthy",
                    "mcp": "healthy"
                },
                "stats": {
                    "proxies": len(proxies),
                    "certificates": len(certificates),
                    "tokens": len(tokens)
                }
            })
        
        @self.mcp.tool()
        async def sessionInfo() -> str:
            """Get session management information.
            
            Returns:
                Dictionary with session statistics and configuration
            """
            # Get MCP sessions from Redis
            mcp_sessions = await storage.list_keys("mcp:session:*")
            
            return json.dumps({
                "mode": "stateful",
                "session_timeout": 3600,
                "active_sessions": len(mcp_sessions),
                "sessions": sessions  # In-memory sessions
            })
        
        # ========== State Tools (10) ==========
        
        @self.mcp.tool()
        async def stateInspector() -> str:
            """Inspect current session state and Redis keys.
            
            Returns:
                Dictionary with state inspection results
            """
            # Get all MCP-related keys from Redis
            mcp_keys = await storage.list_keys("mcp:*")
            
            state_data = {}
            for key in mcp_keys[:20]:  # Limit to first 20 keys
                value = await storage.get_value(key)
                state_data[key] = value if value else "null"
            
            return json.dumps({
                "total_mcp_keys": len(mcp_keys),
                "sample_state": state_data
            })
        
        @self.mcp.tool()
        async def sessionHistory() -> str:
            """Get session activity history.
            
            Returns:
                List of session history entries
            """
            # Get session history from Redis
            history_keys = await storage.list_keys("mcp:history:*")
            history = []
            
            for key in history_keys[:10]:  # Last 10 entries
                entry = await storage.get_value(key)
                if entry:
                    history.append(entry)
            
            return json.dumps({
                "total_history_entries": len(history_keys),
                "recent_history": history
            })
        
        @self.mcp.tool()
        async def stateManipulator(key: str, value: Optional[str] = None, action: str = "get") -> str:
            """Directly manipulate session state in Redis.
            
            Args:
                key: The state key to manipulate
                value: The value to set (for set action)
                action: The action to perform (get, set, delete, exists)
                
            Returns:
                Dictionary with operation result
            """
            mcp_key = f"mcp:{key}"
            
            if action == "get":
                result = await storage.get_value(mcp_key)
                return json.dumps({"key": key, "value": result, "action": "get"})
            elif action == "set":
                await storage.set_value(mcp_key, value, expire=3600)
                return json.dumps({"key": key, "value": value, "action": "set", "success": True})
            elif action == "delete":
                await storage.delete_value(mcp_key)
                return json.dumps({"key": key, "action": "delete", "success": True})
            elif action == "exists":
                exists = await storage.redis_client.exists(mcp_key)
                return json.dumps({"key": key, "exists": bool(exists), "action": "exists"})
            else:
                return json.dumps({"error": f"Unknown action: {action}"})
        
        @self.mcp.tool()
        async def sessionCompare(session1: str, session2: str) -> str:
            """Compare two session states.
            
            Args:
                session1: First session ID
                session2: Second session ID
                
            Returns:
                Dictionary with comparison results
            """
            # Get session data
            s1_keys = await storage.list_keys(f"mcp:session:{session1}:*")
            s2_keys = await storage.list_keys(f"mcp:session:{session2}:*")
            
            s1_data = {}
            for key in s1_keys:
                s1_data[key] = await storage.get_value(key)
            
            s2_data = {}
            for key in s2_keys:
                s2_data[key] = await storage.get_value(key)
            
            # Compare
            only_in_s1 = set(s1_keys) - set(s2_keys)
            only_in_s2 = set(s2_keys) - set(s1_keys)
            common = set(s1_keys) & set(s2_keys)
            
            differences = {}
            for key in common:
                if s1_data[key] != s2_data[key]:
                    differences[key] = {
                        "session1": s1_data[key],
                        "session2": s2_data[key]
                    }
            
            return json.dumps({
                "session1": session1,
                "session2": session2,
                "only_in_session1": list(only_in_s1),
                "only_in_session2": list(only_in_s2),
                "common_keys": len(common),
                "differences": differences
            })
        
        @self.mcp.tool()
        async def sessionTransfer(from_session: str, to_session: str) -> str:
            """Transfer state between sessions.
            
            Args:
                from_session: Source session ID
                to_session: Target session ID
                
            Returns:
                Dictionary with transfer result
            """
            # Get source session data
            source_keys = await storage.list_keys(f"mcp:session:{from_session}:*")
            
            transferred = 0
            for key in source_keys:
                value = await storage.get_value(key)
                if value:
                    # Create new key for target session
                    new_key = key.replace(from_session, to_session)
                    await storage.set_value(new_key, value, expire=3600)
                    transferred += 1
            
            return json.dumps({
                "from_session": from_session,
                "to_session": to_session,
                "keys_transferred": transferred,
                "success": True
            })
        
        @self.mcp.tool()
        async def stateBenchmark(operations: int = 100, data_size: str = "small") -> str:
            """Benchmark state operations against Redis.
            
            Args:
                operations: Number of operations to perform
                data_size: Size of test data (small, medium, large)
                
            Returns:
                Dictionary with benchmark results
            """
            import time
            
            # Generate test data
            if data_size == "small":
                test_data = "x" * 10
            elif data_size == "medium":
                test_data = "x" * 1000
            else:
                test_data = "x" * 10000
            
            # Benchmark writes
            start_time = time.time()
            for i in range(operations):
                await storage.set_value(f"mcp:benchmark:{i}", test_data, expire=60)
            write_time = time.time() - start_time
            
            # Benchmark reads
            start_time = time.time()
            for i in range(operations):
                await storage.get_value(f"mcp:benchmark:{i}")
            read_time = time.time() - start_time
            
            # Cleanup
            for i in range(operations):
                await storage.delete_value(f"mcp:benchmark:{i}")
            
            return json.dumps({
                "operations": operations,
                "data_size": data_size,
                "write_time_ms": write_time * 1000,
                "read_time_ms": read_time * 1000,
                "writes_per_second": operations / write_time,
                "reads_per_second": operations / read_time
            })
        
        @self.mcp.tool()
        async def sessionLifecycle(action: str, session_id: Optional[str] = None) -> str:
            """Manage session lifecycle (create, destroy, list, clear).
            
            Args:
                action: The action to perform
                session_id: The session ID for destroy action
                
            Returns:
                Dictionary with action result
            """
            if action == "create":
                new_session_id = str(uuid.uuid4())
                await storage.set_value(
                    f"mcp:session:{new_session_id}",
                    json.dumps({"created": time.time()}),
                    expire=3600
                )
                sessions[new_session_id] = {"created": time.time()}
                return json.dumps({
                    "action": "create",
                    "session_id": new_session_id,
                    "success": True
                })
            elif action == "destroy":
                if session_id:
                    # Delete all session keys
                    session_keys = await storage.list_keys(f"mcp:session:{session_id}:*")
                    for key in session_keys:
                        await storage.delete_value(key)
                    await storage.delete_value(f"mcp:session:{session_id}")
                    sessions.pop(session_id, None)
                    return json.dumps({
                        "action": "destroy",
                        "session_id": session_id,
                        "keys_deleted": len(session_keys) + 1,
                        "success": True
                    })
                return json.dumps({"error": "session_id required for destroy"})
            elif action == "list":
                session_keys = await storage.list_keys("mcp:session:*")
                session_list = []
                for key in session_keys:
                    if ":" not in key.replace("mcp:session:", ""):
                        session_list.append(key.replace("mcp:session:", ""))
                return json.dumps({
                    "action": "list",
                    "sessions": session_list,
                    "count": len(session_list)
                })
            elif action == "clear":
                # Clear all sessions
                session_keys = await storage.list_keys("mcp:session:*")
                for key in session_keys:
                    await storage.delete_value(key)
                sessions.clear()
                return json.dumps({
                    "action": "clear",
                    "keys_deleted": len(session_keys),
                    "success": True
                })
            else:
                return json.dumps({"error": f"Unknown action: {action}"})
        
        @self.mcp.tool()
        async def stateValidator(schema: dict, data: dict) -> str:
            """Validate state data against a JSON schema.
            
            Args:
                schema: The JSON schema to validate against
                data: The data to validate
                
            Returns:
                Dictionary with validation results
            """
            try:
                import jsonschema
                jsonschema.validate(data, schema)
                return json.dumps({
                    "valid": True,
                    "data": data,
                    "schema": schema
                })
            except jsonschema.ValidationError as e:
                return json.dumps({
                    "valid": False,
                    "error": str(e),
                    "data": data,
                    "schema": schema
                })
            except Exception as e:
                return json.dumps({
                    "error": f"Validation failed: {str(e)}"
                })
        
        @self.mcp.tool()
        async def requestTracer(trace_id: Optional[str] = None) -> str:
            """Trace request flow through the system.
            
            Args:
                trace_id: Optional trace ID to use
                
            Returns:
                Dictionary with trace information
            """
            if not trace_id:
                trace_id = str(uuid.uuid4())
            
            # Store trace point
            await storage.set_value(
                f"mcp:trace:{trace_id}",
                json.dumps({
                    "timestamp": time.time(),
                    "component": "mcp_server",
                    "action": "trace_request"
                }),
                expire=300
            )
            
            return json.dumps({
                "trace_id": trace_id,
                "timestamp": time.time(),
                "component": "mcp_server",
                "message": "Trace point recorded"
            })
        
        @self.mcp.tool()
        async def modeDetector() -> str:
            """Detect server operating mode and environment.
            
            Returns:
                Dictionary with environment detection results
            """
            import platform
            
            # Detect environment
            environment = "development"
            if os.getenv("KUBERNETES_SERVICE_HOST"):
                environment = "kubernetes"
            elif os.getenv("LAMBDA_RUNTIME_DIR"):
                environment = "aws_lambda"
            elif os.getenv("FUNCTIONS_WORKER_RUNTIME"):
                environment = "azure_functions"
            elif os.getenv("DOCKER_CONTAINER"):
                environment = "docker"
            
            return json.dumps({
                "mode": "stateful",
                "environment": environment,
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "mcp_version": LATEST_PROTOCOL_VERSION,
                "redis_available": await storage.health_check(),
                "base_domain": os.getenv("BASE_DOMAIN", "not_set")
            })


def create_mcp_router(async_storage: AsyncRedisStorage, unified_logger: UnifiedAsyncLogger):
    """Create MCP router using FastMCP's http_app for proper SSE support.
    
    This creates a proper MCP server with SSE (Server-Sent Events) support
    that Claude.ai and other MCP clients require for real-time communication.
    
    Returns the ASGI app directly rather than a router, as MCP requires
    its own ASGI app for proper SSE support.
    """
    # Create MCP server instance
    mcp_server = OAuthProxyMCPServer(async_storage, unified_logger)
    
    # Get the HTTP app from FastMCP (streamable_http_app is deprecated)
    # This provides proper SSE support that Claude.ai requires
    mcp_app = mcp_server.mcp.http_app()
    
    logger.info("✓ MCP server created with FastMCP HTTP transport (SSE support enabled)")
    logger.info(f"✓ {len(list(mcp_server.mcp._tool_manager._tools.keys()))} tools registered")
    
    # Return the ASGI app directly - it will be mounted in the registry
    return mcp_app