"""Debug tools for MCP Echo Server."""

import os
import time
import logging
from typing import Dict, Any
from fastmcp import FastMCP, Context
from ..utils.state_adapter import StateAdapter

logger = logging.getLogger(__name__)

# Performance thresholds
PERFORMANCE_EXCELLENT_THRESHOLD = 0.010  # 10ms
PERFORMANCE_GOOD_THRESHOLD = 0.050  # 50ms
PERFORMANCE_ACCEPTABLE_THRESHOLD = 0.100  # 100ms


def register_debug_tools(mcp: FastMCP, stateless_mode: bool):
    """Register debug-related tools.
    
    Args:
        mcp: FastMCP instance
        stateless_mode: Whether server is in stateless mode
    """
    
    @mcp.tool
    async def printHeader(ctx: Context) -> str:
        """Display all HTTP headers from the current request.
        
        Headers are categorized into:
        - Traefik/proxy headers (X-Forwarded-*, X-Real-IP)
        - Authentication headers (Authorization, X-User-*, X-Auth-*)
        - Regular request headers
        - Alphabetical listing of all headers
        
        Returns:
            Formatted header information
        """
        headers = ctx.get_state("request_headers", {})
        
        result = "HTTP Headers\n" + "=" * 50 + "\n\n"
        
        if not headers:
            result += "No headers available (headers may not be captured in this transport mode)\n"
            return result
        
        # Categorize headers
        traefik_headers = {}
        auth_headers = {}
        mcp_headers = {}
        regular_headers = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower.startswith(("x-forwarded-", "x-real-ip")):
                traefik_headers[key] = value
            elif key_lower in ("authorization", "x-user-id", "x-user-name", "x-auth-token", "x-client-id", "x-oauth-client"):
                # Redact sensitive parts of auth tokens
                if key_lower in ("authorization", "x-auth-token") and value and len(value) > 40:
                    redacted_value = value[:20] + "...[redacted]..." + value[-20:]
                    auth_headers[key] = redacted_value
                else:
                    auth_headers[key] = value
            elif key_lower.startswith("mcp-"):
                mcp_headers[key] = value
            else:
                regular_headers[key] = value
        
        # Display headers by category
        if traefik_headers:
            result += "PROXY/TRAEFIK HEADERS:\n" + "-" * 30 + "\n"
            for key, value in sorted(traefik_headers.items()):
                result += f"  {key}: {value}\n"
            result += "\n"
        
        if auth_headers:
            result += "AUTHENTICATION HEADERS:\n" + "-" * 30 + "\n"
            for key, value in sorted(auth_headers.items()):
                result += f"  {key}: {value}\n"
            result += "\n"
        
        if mcp_headers:
            result += "MCP PROTOCOL HEADERS:\n" + "-" * 30 + "\n"
            for key, value in sorted(mcp_headers.items()):
                result += f"  {key}: {value}\n"
            result += "\n"
        
        if regular_headers:
            result += "REQUEST HEADERS:\n" + "-" * 30 + "\n"
            for key, value in sorted(regular_headers.items()):
                result += f"  {key}: {value}\n"
            result += "\n"
        
        # Add complete alphabetical list
        result += "ALL HEADERS (Alphabetical):\n" + "-" * 30 + "\n"
        all_headers = {**traefik_headers, **auth_headers, **mcp_headers, **regular_headers}
        for key, value in sorted(all_headers.items()):
            result += f"  {key}: {value}\n"
        
        # Add context info
        result += "\n" + "=" * 50 + "\n"
        result += f"Total headers: {len(all_headers)}\n"
        result += f"Mode: {'stateless' if ctx.get_state('stateless_mode') else 'stateful'}\n"
        
        if not ctx.get_state("stateless_mode"):
            session_id = ctx.get_state("session_id")
            if session_id:
                result += f"Session ID: {session_id}\n"
        
        return result
    
    @mcp.tool
    async def requestTiming(ctx: Context) -> Dict[str, Any]:
        """Show request timing and performance metrics.
        
        Provides timing information including:
        - Request processing time
        - Performance indicators (excellent/good/acceptable/slow)
        - Session age (stateful mode only)
        
        Returns:
            Timing metrics dictionary
        """
        start_time = ctx.get_state("request_start_time", time.time())
        current_time = time.time()
        elapsed = current_time - start_time
        
        result = {
            "timing": {
                "request_start": start_time,
                "current_time": current_time,
                "elapsed_seconds": elapsed,
                "elapsed_ms": elapsed * 1000
            },
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful"
        }
        
        # Performance classification
        if elapsed < PERFORMANCE_EXCELLENT_THRESHOLD:
            performance = "⚡ Excellent (<10ms)"
        elif elapsed < PERFORMANCE_GOOD_THRESHOLD:
            performance = "✅ Good (<50ms)"
        elif elapsed < PERFORMANCE_ACCEPTABLE_THRESHOLD:
            performance = "⚠️ Acceptable (<100ms)"
        else:
            performance = "❌ Slow (>100ms)"
        
        result["performance"] = performance
        
        # Add session timing if stateful
        if not ctx.get_state("stateless_mode"):
            session_id = ctx.get_state("session_id")
            if session_id:
                session_data = ctx.get_state(f"session_{session_id}_data", {})
                if session_data and "created_at" in session_data:
                    session_age = current_time - session_data["created_at"]
                    result["session"] = {
                        "session_id": session_id[:8] + "...",
                        "age_seconds": session_age,
                        "age_human": format_duration(session_age),
                        "request_count": session_data.get("request_count", 0)
                    }
        
        return result
    
    @mcp.tool
    async def corsAnalysis(ctx: Context) -> str:
        """Analyze CORS configuration and requirements.
        
        Examines CORS-related headers and configuration.
        Note: In production, CORS is typically handled by the proxy/gateway layer.
        
        Returns:
            CORS analysis report
        """
        headers = ctx.get_state("request_headers", {})
        
        result = "CORS Configuration Analysis\n" + "=" * 40 + "\n\n"
        
        # Note about external CORS handling
        result += "⚡ CORS HANDLING NOTE ⚡\n"
        result += "In production deployments, CORS is typically handled by:\n"
        result += "- Reverse proxy (Traefik, nginx, etc.)\n"
        result += "- API gateway\n"
        result += "- FastMCP transport layer\n\n"
        
        # Check request headers
        result += "Request CORS Headers:\n"
        origin = headers.get("origin", "")
        if origin:
            result += f"  Origin: {origin}\n"
            
            # Analyze origin
            if origin.startswith("http://localhost"):
                result += "  Type: Local development\n"
            elif origin.startswith("https://"):
                result += "  Type: Secure origin\n"
            elif origin.startswith("http://"):
                result += "  Type: ⚠️ Insecure origin\n"
        else:
            result += "  Origin: Not present (same-origin request or non-browser client)\n"
        
        # Check for preflight indicators
        request_method = headers.get("access-control-request-method")
        request_headers = headers.get("access-control-request-headers")
        
        if request_method or request_headers:
            result += "\nPreflight Request Detected:\n"
            if request_method:
                result += f"  Requested Method: {request_method}\n"
            if request_headers:
                result += f"  Requested Headers: {request_headers}\n"
        
        # FastMCP transport info
        result += "\nFastMCP Transport:\n"
        result += f"  Mode: {'stateless' if ctx.get_state('stateless_mode') else 'stateful'}\n"
        result += "  Transport: HTTP (with optional SSE)\n"
        result += "  CORS headers should be configured at transport level\n"
        
        return result
    
    @mcp.tool
    async def environmentDump(ctx: Context, show_secrets: bool = False) -> Dict[str, Any]:
        """Display environment configuration.
        
        Shows environment variables related to MCP Echo Server configuration.
        Sensitive values are redacted unless show_secrets is True.
        
        Args:
            show_secrets: Show first/last 4 chars of secrets (default: False)
            
        Returns:
            Environment configuration dictionary
        """
        result = {
            "mode": "stateless" if ctx.get_state("stateless_mode") else "stateful",
            "mcp_config": {},
            "server_config": {},
            "system_info": {}
        }
        
        # MCP-specific environment variables
        mcp_vars = {
            "MCP_ECHO_HOST": os.getenv("MCP_ECHO_HOST", "not set"),
            "MCP_ECHO_PORT": os.getenv("MCP_ECHO_PORT", "not set"),
            "MCP_ECHO_DEBUG": os.getenv("MCP_ECHO_DEBUG", "not set"),
            "MCP_MODE": os.getenv("MCP_MODE", "not set"),
            "MCP_SESSION_TIMEOUT": os.getenv("MCP_SESSION_TIMEOUT", "not set"),
            "MCP_PROTOCOL_VERSION": os.getenv("MCP_PROTOCOL_VERSION", "not set"),
            "MCP_PROTOCOL_VERSIONS_SUPPORTED": os.getenv("MCP_PROTOCOL_VERSIONS_SUPPORTED", "not set"),
            "MCP_STATELESS": os.getenv("MCP_STATELESS", "not set"),
        }
        
        for var, value in mcp_vars.items():
            display_value = value
            
            # Redact sensitive values
            if not show_secrets and any(secret_word in var.lower() for secret_word in ["secret", "key", "token", "password", "auth"]):
                if value != "not set" and len(value) > 8:
                    display_value = value[:4] + "***" + value[-4:]
                elif value != "not set":
                    display_value = "***"
            
            result["mcp_config"][var] = display_value
        
        # Server configuration from context
        result["server_config"] = {
            "server_name": ctx.get_state("server_name", "unknown"),
            "server_version": ctx.get_state("server_version", "unknown"),
            "debug_mode": ctx.get_state("server_debug", False),
            "stateless_mode": ctx.get_state("stateless_mode", False),
            "supported_versions": ctx.get_state("supported_versions", [])
        }
        
        # System information
        result["system_info"] = {
            "platform": os.name,
            "python_path": os.getenv("PYTHONPATH", "not set"),
            "working_directory": os.getcwd(),
            "process_id": os.getpid()
        }
        
        # Environment detection
        result["environment_detection"] = {
            "kubernetes": os.getenv("KUBERNETES_SERVICE_HOST") is not None,
            "docker": os.path.exists("/.dockerenv"),
            "lambda": os.getenv("LAMBDA_RUNTIME_DIR") is not None,
            "ci": os.getenv("CI") is not None,
            "github_actions": os.getenv("GITHUB_ACTIONS") is not None
        }
        
        return result
    
    logger.debug(f"Registered debug tools (stateless_mode={stateless_mode})")


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human-readable duration string
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