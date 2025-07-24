"""MCP Transport Detection and Testing."""

from enum import Enum
from typing import Optional, Dict, Any, Tuple
import httpx
from dataclasses import dataclass


class TransportType(str, Enum):
    """MCP Transport Types."""
    HTTP_SSE = "http_sse"  # HTTP with SSE (GET only)
    STREAMABLE_HTTP = "streamable_http"  # POST with JSON or SSE response
    JSON_RPC = "json_rpc"  # POST with JSON response only
    UNKNOWN = "unknown"


@dataclass
class TransportCapabilities:
    """Detected transport capabilities of an MCP server."""
    primary_transport: TransportType
    supports_get_sse: bool = False
    supports_post_json: bool = False
    supports_post_sse: bool = False
    get_response_type: Optional[str] = None
    post_response_type: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    
    def describe(self) -> str:
        """Human-readable description of capabilities."""
        if self.primary_transport == TransportType.HTTP_SSE:
            return "HTTP with SSE transport (GET requests only, SSE responses)"
        elif self.primary_transport == TransportType.STREAMABLE_HTTP:
            modes = []
            if self.supports_post_json:
                modes.append("JSON")
            if self.supports_post_sse:
                modes.append("SSE")
            return f"Streamable HTTP transport (POST requests, {' or '.join(modes)} responses)"
        elif self.primary_transport == TransportType.JSON_RPC:
            return "JSON-RPC transport (POST requests, JSON responses only)"
        else:
            return "Unknown transport type"


class TransportDetector:
    """Detects MCP server transport capabilities."""
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    async def detect(self, url: str, headers: Dict[str, str]) -> TransportCapabilities:
        """Detect transport capabilities of an MCP server.
        
        Tests both GET and POST methods with appropriate Accept headers
        to determine what transport methods the server supports.
        """
        caps = TransportCapabilities(primary_transport=TransportType.UNKNOWN)
        
        # Test GET with SSE accept header
        get_sse_result = await self._test_get_sse(url, headers)
        if get_sse_result[0]:
            caps.supports_get_sse = True
            caps.get_response_type = get_sse_result[1]
        
        # Test POST with JSON
        post_json_result = await self._test_post_json(url, headers)
        if post_json_result[0]:
            caps.supports_post_json = True
            caps.post_response_type = post_json_result[1]
        
        # Test POST with SSE accept
        post_sse_result = await self._test_post_sse(url, headers)
        if post_sse_result[0]:
            caps.supports_post_sse = True
            if not caps.post_response_type:
                caps.post_response_type = post_sse_result[1]
        
        # Determine primary transport type
        if caps.supports_get_sse and not caps.supports_post_json and not caps.supports_post_sse:
            caps.primary_transport = TransportType.HTTP_SSE
        elif caps.supports_post_json or caps.supports_post_sse:
            if caps.supports_post_sse:
                caps.primary_transport = TransportType.STREAMABLE_HTTP
            else:
                caps.primary_transport = TransportType.JSON_RPC
        
        return caps
    
    async def _test_get_sse(self, url: str, base_headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """Test GET request with SSE accept header."""
        headers = base_headers.copy()
        headers["Accept"] = "text/event-stream"
        
        try:
            # Use stream=True to handle SSE connections properly
            # Set a very short timeout for just the initial connection
            async with self.client.stream("GET", url, headers=headers, timeout=3.0) as response:
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")
                    if "text/event-stream" in content_type:
                        # Try to read a small amount to verify it's actually SSE
                        # SSE servers will send data or keep connection open
                        # For SSE, just having the right content-type is enough
                        # We don't need to read data - SSE streams stay open
                        return True, content_type
                elif response.status_code == 405:
                    # Method not allowed - server doesn't support GET
                    return False, None
                return False, None
        except (httpx.TimeoutException, httpx.ConnectTimeout, httpx.ReadTimeout):
            # These are expected for SSE connections
            return False, None
        except Exception:
            return False, None
    
    async def _test_post_json(self, url: str, base_headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """Test POST request with JSON accept header."""
        headers = base_headers.copy()
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        
        # Minimal JSON-RPC request
        test_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            # Use a shorter timeout for transport detection
            response = await self.client.post(url, headers=headers, json=test_request, timeout=httpx.Timeout(5.0))
            if response.status_code in [200, 202]:
                content_type = response.headers.get("content-type", "")
                if "application/json" in content_type:
                    return True, content_type
            # Don't treat 405 Method Not Allowed as an error - it's expected for GET-only servers
            return False, None
        except Exception:
            return False, None
    
    async def _test_post_sse(self, url: str, base_headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """Test POST request with SSE accept header."""
        headers = base_headers.copy()
        headers["Accept"] = "text/event-stream"
        headers["Content-Type"] = "application/json"
        
        test_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            # Use a shorter timeout for transport detection
            response = await self.client.post(url, headers=headers, json=test_request, timeout=httpx.Timeout(5.0))
            if response.status_code in [200, 202]:
                content_type = response.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    return True, content_type
            # Don't treat 405 Method Not Allowed as an error - it's expected for GET-only servers
            return False, None
        except Exception:
            return False, None