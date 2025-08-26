"""Starlette app for MCP with proper SSE streaming.

This module provides the Starlette application that handles MCP requests
and properly streams SSE responses without race conditions.
"""

import asyncio
import json
import logging
import secrets
from typing import Optional

from starlette.applications import Starlette
from starlette.responses import StreamingResponse, Response, JSONResponse
from starlette.routing import Route
from starlette.requests import Request

from .pure_mcp_server import PureMCPServer

logger = logging.getLogger(__name__)


class MCPStarletteApp:
    """Starlette app for MCP with working SSE streaming."""
    
    def __init__(self, mcp_server: PureMCPServer):
        """Initialize the Starlette app for MCP.
        
        Args:
            mcp_server: PureMCPServer instance to handle requests
        """
        self.mcp = mcp_server
        
        # Create Starlette app with route at root
        # When mounted at /mcp, this will handle /mcp requests
        self.app = Starlette(
            routes=[
                Route("/", self.handle_mcp, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
            ]
        )
        
        logger.info(f"[MCP APP] Starlette app created with {len(self.mcp.tools)} tools")
    
    async def handle_mcp(self, request: Request):
        """Handle MCP requests with proper SSE streaming.
        
        Args:
            request: Starlette request object
            
        Returns:
            Response with SSE stream or appropriate headers
        """
        # Generate or extract request ID
        request_id = request.headers.get("x-request-id", f"mcp_{secrets.token_hex(4)}")
        
        # Extract all relevant headers for comprehensive logging
        session_id = request.headers.get("mcp-session-id")
        accept_header = request.headers.get("accept", "")
        content_type = request.headers.get("content-type", "")
        protocol_version = request.headers.get("mcp-protocol-version", "")
        origin = request.headers.get("origin", "")
        
        # Generate trace ID
        trace_id = f"mcp_req_{request_id}"
        
        # Extract request info
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        method = request.method
        
        # Comprehensive request logging
        logger.info(f"[MCP APP] {method} request (ID: {request_id}, Session: {session_id})")
        logger.debug(f"[MCP APP] Headers - Accept: {accept_header}, Content-Type: {content_type}")
        logger.debug(f"[MCP APP] Client - IP: {client_ip}, User-Agent: {user_agent}")
        if protocol_version:
            logger.debug(f"[MCP APP] Protocol Version: {protocol_version}")
        if origin:
            logger.debug(f"[MCP APP] Origin: {origin}")
        
        # Unified logger with all context
        if self.mcp.logger:
            self.mcp.logger.info(
                f"MCP {method} request received",
                trace_id=trace_id,
                request_id=request_id,
                method=method,
                session_id=session_id,
                client_ip=client_ip,
                user_agent=user_agent,
                accept=accept_header,
                content_type=content_type,
                protocol_version=protocol_version,
                origin=origin
            )
        
        # Handle HEAD requests for Claude.ai discovery
        if method == "HEAD":
            # Create or get session
            session_id = await self.mcp.get_or_create_session(session_id)
            
            logger.info(f"[MCP APP] HEAD request - session {session_id}")
            
            # Log with unified logger
            if self.mcp.logger:
                self.mcp.logger.info(
                    "MCP HEAD request processed",
                    trace_id=trace_id,
                    session_id=session_id,
                    client_ip=client_ip,
                    user_agent=user_agent
                )
            
            return Response(
                content="",
                status_code=200,
                headers={
                    "Content-Type": "text/event-stream",
                    "Allow": "GET, POST, DELETE, HEAD, OPTIONS",
                    "Mcp-Session-Id": session_id,
                    "MCP-Protocol-Version": "2025-06-18",
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive",
                    "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version"
                }
            )
        
        # Handle OPTIONS for CORS
        if method == "OPTIONS":
            return Response(
                content="",
                headers={
                    "Allow": "GET, POST, PUT, DELETE, HEAD, OPTIONS",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, HEAD, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version"
                }
            )
        
        # Handle DELETE for session termination (MCP spec)
        if method == "DELETE":
            if not session_id:
                logger.warning(f"[MCP APP] DELETE request without session ID")
                return Response(
                    content=json.dumps({"error": "Session ID required"}),
                    status_code=400,
                    media_type="application/json"
                )
            
            logger.info(f"[MCP APP] Session termination requested for {session_id}")
            
            # Terminate the session
            if hasattr(self.mcp, 'terminate_session'):
                await self.mcp.terminate_session(session_id)
            
            # Log session termination
            if self.mcp.logger:
                self.mcp.logger.info(
                    "MCP session terminated",
                    trace_id=trace_id,
                    session_id=session_id,
                    client_ip=client_ip
                )
            
            return Response(
                content="",
                status_code=204,  # No Content
                headers={
                    "Mcp-Session-Id": session_id
                }
            )
        
        # Handle JSON-RPC requests (POST, PUT, DELETE)
        try:
            # Check content type
            content_type = request.headers.get("content-type", "")
            accept_header = request.headers.get("accept", "")
            
            # Check if client accepts SSE - be explicit in logging
            accepts_sse = "text/event-stream" in accept_header
            logger.info(f"[MCP APP] Client accepts SSE: {accepts_sse} (Accept: {accept_header})")
            
            # For GET requests, open an SSE stream per MCP spec
            if method == "GET":
                logger.info(f"[MCP APP] GET request - opening SSE stream for session {session_id}")
                
                # Get or create session
                session_id = await self.mcp.get_or_create_session(session_id)
                
                # Create SSE stream that stays open for multiple requests
                async def persistent_sse_stream():
                    """Generate persistent SSE stream for GET requests per MCP spec."""
                    stream_id = f"get_stream_{secrets.token_hex(4)}"
                    logger.info(f"[MCP APP SSE] Opening persistent GET stream (id: {stream_id}, session: {session_id})")
                    
                    try:
                        # Send initial ping to establish connection
                        yield b": ping\n\n"
                        
                        # Send server hello message
                        hello_msg = {
                            "jsonrpc": "2.0",
                            "method": "notifications/hello",
                            "params": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": self.mcp.capabilities,
                                "serverInfo": self.mcp.server_info
                            }
                        }
                        hello_data = f"data: {json.dumps(hello_msg)}\n\n"
                        yield hello_data.encode('utf-8')
                        logger.info(f"[MCP APP SSE] Sent hello notification on GET stream")
                        
                        # Keep connection alive with periodic pings
                        ping_count = 0
                        max_pings = 600  # 5 minutes with 0.5s interval
                        
                        while ping_count < max_pings:
                            await asyncio.sleep(0.5)
                            yield b": keepalive\n\n"
                            ping_count += 1
                            
                            if ping_count % 20 == 0:  # Log every 10 seconds
                                logger.debug(f"[MCP APP SSE] GET stream alive ({ping_count}/{max_pings})")
                        
                        logger.info(f"[MCP APP SSE] GET stream timeout, closing (id: {stream_id})")
                    except Exception as e:
                        logger.error(f"[MCP APP SSE] GET stream error: {e}")
                        error_msg = {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32603,
                                "message": f"Stream error: {str(e)}"
                            }
                        }
                        error_data = f"data: {json.dumps(error_msg)}\n\n"
                        yield error_data.encode('utf-8')
                
                return StreamingResponse(
                    persistent_sse_stream(),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                        "Mcp-Session-Id": session_id,
                        "Connection": "keep-alive",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Expose-Headers": "Mcp-Session-Id"
                    }
                )
            
            # Parse JSON-RPC request body
            body_bytes = await request.body()
            if not body_bytes:
                return JSONResponse(
                    {"error": "No request body"},
                    status_code=400
                )
            
            try:
                body = json.loads(body_bytes)
            except json.JSONDecodeError as e:
                logger.error(f"[MCP APP] Invalid JSON: {e}")
                return JSONResponse(
                    {"error": f"Invalid JSON: {str(e)}"},
                    status_code=400
                )
            
            # Log the request details
            rpc_method = body.get("method", "unknown")
            rpc_id = body.get("id")
            has_params = "params" in body
            
            logger.info(f"[MCP APP] JSON-RPC: method={rpc_method}, id={rpc_id}, has_params={has_params}")
            
            # Log params structure for tools/list
            if rpc_method == "tools/list" and has_params:
                logger.debug(f"[MCP APP] tools/list params: {body.get('params')}")
            
            # Get or create session
            session_id = await self.mcp.get_or_create_session(session_id)
            
            # Create SSE generator that properly streams data
            async def generate_sse():
                """Generate SSE stream with proper formatting per MCP spec."""
                request_id = f"sse_{secrets.token_hex(4)}"
                
                try:
                    logger.info(f"[MCP APP SSE] Starting stream for {rpc_method} (req: {request_id}, session: {session_id})")
                    
                    # Send initial comment to establish connection
                    # This helps with connection keep-alive and debugging
                    yield b": ping\n\n"
                    
                    # Process the request
                    response = await self.mcp.process_request(body, session_id)
                    
                    # Log response details
                    response_json = json.dumps(response)
                    logger.info(f"[MCP APP SSE] Generated response for {rpc_method}: {len(response_json)} bytes")
                    
                    # Log first 200 chars of response for debugging
                    logger.debug(f"[MCP APP SSE] Response preview: {response_json[:200]}...")
                    
                    # Format as SSE per spec - single event with JSON data
                    # Include retry field for connection resilience
                    sse_data = f"retry: 5000\ndata: {response_json}\n\n"
                    
                    logger.info(f"[MCP APP SSE] Sending {len(sse_data)} bytes of SSE data")
                    
                    # Log SSE transmission with unified logger
                    if self.mcp.logger:
                        self.mcp.logger.info(
                            "SSE stream sending",
                            trace_id=trace_id,
                            session_id=session_id,
                            method=rpc_method,
                            response_size=len(sse_data),
                            request_id=request_id,
                            has_result="result" in response,
                            has_error="error" in response
                        )
                    
                    # Yield the SSE data
                    yield sse_data.encode('utf-8')
                    
                    logger.info(f"[MCP APP SSE] Stream complete for {rpc_method} (req: {request_id})")
                    
                except Exception as e:
                    logger.error(f"[MCP APP SSE] Error in stream generation: {e}", exc_info=True)
                    
                    # Send error as SSE data per JSON-RPC spec
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": body.get("id"),
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(e)}",
                            "data": {"request_id": request_id}
                        }
                    }
                    error_sse = f"data: {json.dumps(error_response)}\n\n"
                    yield error_sse.encode('utf-8')
                    
                    # Log error with full context
                    if self.mcp.event_publisher:
                        await self.mcp.event_publisher.publish_error(
                            error=e,
                            component="mcp_app_sse",
                            context={
                                "session_id": session_id,
                                "request": body,
                                "request_id": request_id,
                                "method": rpc_method
                            },
                            trace_id=trace_id
                        )
            
            # Check if client wants SSE or JSON response
            if accepts_sse:
                logger.info(f"[MCP APP] Client requested SSE, returning stream for {rpc_method}")
                
                # Return streaming SSE response with MCP-compliant headers
                logger.info(f"[MCP APP] Returning SSE StreamingResponse for {rpc_method}")
                return StreamingResponse(
                    generate_sse(),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",  # Disable nginx buffering
                        "Mcp-Session-Id": session_id,
                        "Connection": "keep-alive",
                        # CORS headers for browser clients
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id",
                        "Access-Control-Expose-Headers": "Mcp-Session-Id",
                    }
                )
            else:
                # Return JSON response for non-SSE clients
                logger.info(f"[MCP APP] Returning JSON response for {rpc_method}")
                response = await self.mcp.process_request(body, session_id)
                return JSONResponse(
                    response,
                    headers={
                        "Mcp-Session-Id": session_id
                    }
                )
                
        except Exception as e:
            logger.error(f"[MCP APP] Request handling error: {e}", exc_info=True)
            
            # Log critical error
            if self.mcp.logger:
                self.mcp.logger.error(
                    f"MCP request failed: {str(e)}",
                    trace_id=trace_id,
                    session_id=session_id,
                    error_type=type(e).__name__,
                    client_ip=client_ip
                )
            
            # Return error response
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": f"Server error: {str(e)}"
                    }
                },
                status_code=500,
                headers={
                    "Mcp-Session-Id": session_id or ""
                }
            )