"""Debug tools for MCP server."""

import json
import logging
import os
import time
from typing import Dict, Any, Optional

# Try to import from MCP SDK, fall back to simple implementation
try:
    from mcp.server import FastMCP
except ImportError:
    from ..simple_mcp import FastMCP

logger = logging.getLogger(__name__)


def register_debug_tools(mcp: FastMCP, context: dict):
    """Register debug-related tools.
    
    Args:
        mcp: FastMCP instance
        context: Dictionary containing dependencies
    """
    
    storage = context["storage"]
    unified_logger = context["logger"]
    state_manager = context["state_manager"]
    
    @mcp.tool()
    async def printHeader(header_name: str, session_id: Optional[str] = None) -> str:
        """Get HTTP header value from current request.
        
        Args:
            header_name: Name of the header to retrieve
            session_id: Optional session ID for context
            
        Returns:
            Header value or not found message
        """
        # Get current request headers from Redis (set by router)
        headers_key = f"mcp:current_request:{session_id or 'default'}:headers"
        headers = await storage.redis_client.hgetall(headers_key)
        
        if headers:
            # Convert header name to lowercase for case-insensitive lookup
            header_lower = header_name.lower()
            for key, value in headers.items():
                if key.lower() == header_lower:
                    await unified_logger.event("mcp_debug_header", {
                        "session_id": session_id,
                        "header_name": header_name,
                        "header_value": value
                    })
                    return f"{key}: {value}"
        
        return f"Header '{header_name}' not found in current request"
    
    @mcp.tool()
    async def requestTiming(session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get request timing information.
        
        Args:
            session_id: Optional session ID for context
            
        Returns:
            Dictionary with timing information
        """
        timing_key = f"mcp:current_request:{session_id or 'default'}:timing"
        timing_data = await storage.redis_client.hgetall(timing_key)
        
        if timing_data:
            # Calculate duration if start time is available
            if "start_time" in timing_data:
                start_time = float(timing_data["start_time"])
                current_time = time.time()
                timing_data["duration_ms"] = (current_time - start_time) * 1000
            
            await unified_logger.event("mcp_debug_timing", {
                "session_id": session_id,
                "timing": timing_data
            })
            
            return timing_data
        
        return {
            "message": "No timing data available for current request",
            "hint": "Timing data is set by the MCP router when handling requests"
        }
    
    @mcp.tool()
    async def corsAnalysis(session_id: Optional[str] = None) -> Dict[str, Any]:
        """Analyze CORS configuration for current request.
        
        Args:
            session_id: Optional session ID for context
            
        Returns:
            Dictionary with CORS analysis
        """
        headers_key = f"mcp:current_request:{session_id or 'default'}:headers"
        headers = await storage.redis_client.hgetall(headers_key)
        
        # Extract CORS-related headers
        cors_info = {
            "request": {
                "origin": None,
                "method": None,
                "requested_headers": None,
                "requested_method": None
            },
            "response": {
                "allow_origin": None,
                "allow_methods": None,
                "allow_headers": None,
                "allow_credentials": None,
                "max_age": None
            },
            "analysis": {
                "cors_enabled": False,
                "preflight_request": False,
                "credentials_allowed": False
            }
        }
        
        if headers:
            # Request headers (case-insensitive)
            for key, value in headers.items():
                key_lower = key.lower()
                if key_lower == "origin":
                    cors_info["request"]["origin"] = value
                elif key_lower == "access-control-request-method":
                    cors_info["request"]["requested_method"] = value
                    cors_info["analysis"]["preflight_request"] = True
                elif key_lower == "access-control-request-headers":
                    cors_info["request"]["requested_headers"] = value
                
                # Response headers (typically set by server)
                elif key_lower == "access-control-allow-origin":
                    cors_info["response"]["allow_origin"] = value
                    cors_info["analysis"]["cors_enabled"] = True
                elif key_lower == "access-control-allow-methods":
                    cors_info["response"]["allow_methods"] = value
                elif key_lower == "access-control-allow-headers":
                    cors_info["response"]["allow_headers"] = value
                elif key_lower == "access-control-allow-credentials":
                    cors_info["response"]["allow_credentials"] = value
                    cors_info["analysis"]["credentials_allowed"] = value.lower() == "true"
                elif key_lower == "access-control-max-age":
                    cors_info["response"]["max_age"] = value
        
        # Add analysis summary
        if cors_info["analysis"]["cors_enabled"]:
            if cors_info["response"]["allow_origin"] == "*":
                cors_info["analysis"]["security_note"] = "Wide open CORS (*) - accepts all origins"
            elif cors_info["response"]["allow_origin"] == cors_info["request"]["origin"]:
                cors_info["analysis"]["security_note"] = "Origin is explicitly allowed"
            else:
                cors_info["analysis"]["security_note"] = "CORS configured with specific rules"
        else:
            cors_info["analysis"]["security_note"] = "CORS not configured or not applicable"
        
        await unified_logger.event("mcp_debug_cors", {
            "session_id": session_id,
            "cors_analysis": cors_info
        })
        
        return cors_info
    
    @mcp.tool()
    async def environmentDump(include_all: bool = False) -> Dict[str, Any]:
        """Get environment information.
        
        Args:
            include_all: If True, include all environment variables (DANGEROUS!)
            
        Returns:
            Dictionary with environment information
        """
        env_info = {
            "safe_variables": {},
            "system_info": {
                "platform": os.name,
                "python_version": os.sys.version.split()[0],
                "cwd": os.getcwd()
            }
        }
        
        # Safe environment variables to include
        safe_vars = [
            "MCP_MODE",
            "MCP_ENABLED",
            "MCP_SESSION_TIMEOUT",
            "LOG_LEVEL",
            "BASE_DOMAIN",
            "HTTP_PORT",
            "HTTPS_PORT",
            "API_URL",
            "NODE_ENV",
            "ENVIRONMENT",
            "DEBUG"
        ]
        
        if include_all:
            # WARNING: This includes ALL environment variables
            # Should only be used in development
            env_info["all_variables"] = {}
            for key, value in os.environ.items():
                # Redact sensitive values
                if any(sensitive in key.upper() for sensitive in 
                       ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL"]):
                    env_info["all_variables"][key] = "***REDACTED***"
                else:
                    env_info["all_variables"][key] = value
            env_info["warning"] = "All environment variables included (sensitive values redacted)"
        else:
            # Only include safe variables
            for var in safe_vars:
                value = os.getenv(var)
                if value:
                    env_info["safe_variables"][var] = value
            
            # Check for Redis connection (redacted)
            if os.getenv("REDIS_URL"):
                env_info["safe_variables"]["REDIS_URL"] = "***CONFIGURED***"
            if os.getenv("REDIS_PASSWORD"):
                env_info["safe_variables"]["REDIS_PASSWORD"] = "***CONFIGURED***"
        
        # Add container/deployment detection
        deployment_hints = {
            "docker": os.path.exists("/.dockerenv"),
            "kubernetes": bool(os.getenv("KUBERNETES_SERVICE_HOST")),
            "aws_lambda": bool(os.getenv("LAMBDA_RUNTIME_DIR")),
            "azure_functions": bool(os.getenv("FUNCTIONS_WORKER_RUNTIME")),
            "google_cloud_run": bool(os.getenv("K_SERVICE"))
        }
        
        env_info["deployment"] = {
            key: value for key, value in deployment_hints.items() if value
        } or {"type": "standalone"}
        
        await unified_logger.event("mcp_debug_environment", {
            "include_all": include_all,
            "var_count": len(env_info.get("all_variables", env_info["safe_variables"]))
        })
        
        return env_info
    
    logger.info("Registered debug tools: printHeader, requestTiming, corsAnalysis, environmentDump")