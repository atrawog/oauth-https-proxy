"""MCP Starlette app mounting with proper task group initialization.

This module handles mounting the MCP SDK's Starlette app directly on FastAPI,
ensuring the task group is properly initialized for stateful operation.
"""

import asyncio
import logging
from typing import Optional

import anyio
from fastapi import FastAPI, Request, Response
from starlette.middleware.cors import CORSMiddleware

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global references for MCP components
_mcp_app = None
_mcp_session_manager = None
_mcp_task_group = None
_mcp_task = None
_unified_logger = None


def mount_mcp_app(
    app: FastAPI,
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> None:
    """Mount MCP Starlette app directly with proper initialization.
    
    This mounts the SDK's Starlette app at /mcp and ensures the task group
    is properly initialized for stateful operation.
    """
    global _mcp_app, _mcp_session_manager, _mcp_task_group, _mcp_task, _unified_logger
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    # Store unified logger for use in handlers
    _unified_logger = unified_logger
    
    logger.info("[MCP MOUNT] Creating MCP server and Starlette app")
    
    # Create integrated MCP server
    mcp_server = IntegratedMCPServer(
        async_storage,
        unified_logger,
        cert_manager,
        docker_manager
    )
    
    # Get FastMCP instance
    mcp = mcp_server.get_server()
    tool_count = len(mcp._tool_manager._tools) if hasattr(mcp, '_tool_manager') else 0
    logger.info(f"[MCP MOUNT] Registered {tool_count} tools")
    
    # Get the streamable HTTP app from the SDK
    _mcp_app = mcp.streamable_http_app()
    
    # Store the session manager for task group initialization
    _mcp_session_manager = mcp._session_manager
    
    # Add CORS middleware
    _mcp_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        allow_credentials=False,
        expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"]
    )
    
    # Mount the MCP app at /mcp/ (with trailing slash)
    app.mount("/mcp/", _mcp_app)
    logger.info("[MCP MOUNT] Mounted MCP Starlette app at /mcp/")
    
    # Add specific handler for /mcp (without trailing slash) to avoid redirects
    @app.api_route("/mcp", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
    async def mcp_no_slash(request: Request) -> Response:
        """Handle /mcp requests without redirecting to /mcp/."""
        import json
        
        # Log request details using unified logger
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get('user-agent', 'unknown')
        session_id = request.headers.get('mcp-session-id', 'no-session')
        
        # Use unified logger for async logging to Redis Streams
        await _unified_logger.log(
            "info",
            f"MCP {request.method} request",
            method=request.method,
            path="/mcp",
            client_ip=client_ip,
            session_id=session_id,
            user_agent=user_agent
        )
        
        # Simply forward to the mounted app with adjusted path
        # The mounted app at /mcp/ expects the request at the root path /
        from starlette.responses import StreamingResponse, JSONResponse
        import asyncio
        
        # Check if Accept header includes required formats
        accept_header = request.headers.get('accept', '')
        
        # If Accept header doesn't include the required formats, add them
        # This is to support Claude.ai which might send browser GET requests
        headers_list = []
        has_event_stream = 'text/event-stream' in accept_header
        has_json = 'application/json' in accept_header
        
        for k, v in request.headers.items():
            if k.lower() == 'accept':
                # Ensure both required formats are in Accept header
                if not has_event_stream or not has_json:
                    v = 'application/json, text/event-stream'
                    logger.info(f"[MCP HANDLER] Modified Accept header to: {v}")
            headers_list.append((k.encode(), v.encode()))
        
        # Build complete ASGI scope for the MCP app
        # The MCP app expects to receive requests at the root "/"
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': request.method,
            'path': '/',  # MCP app expects root path
            'root_path': '',
            'scheme': request.url.scheme,
            'query_string': request.url.query.encode() if request.url.query else b'',
            'headers': headers_list,
            'server': (request.client.host if request.client else '127.0.0.1',
                      request.client.port if request.client else 80),
            'client': (request.client.host if request.client else '127.0.0.1',
                      request.client.port if request.client else 0),
            'state': {}
        }
        
        # Get the request body
        body = await request.body()
        body_sent = False
        
        # Track if we need to inject initialization
        needs_init_injection = False
        
        # Log request body for MCP protocol messages
        if body:
            try:
                body_json = json.loads(body)
                method = body_json.get('method', 'unknown')
                request_id = body_json.get('id', 'no-id')
                
                # Check if this is a tools/list request that might come before initialization
                if method == 'tools/list':
                    # Check if session is initialized by looking at session_id
                    if session_id == 'no-session' or not session_id:
                        logger.info(f"[MCP FIX] Detected tools/list before initialization, will auto-initialize")
                        needs_init_injection = True
                
                # Fix incomplete initialize requests from Claude.ai
                if method == 'initialize':
                    params = body_json.get('params', {})
                    
                    # Ensure capabilities exist with proper structure
                    if 'capabilities' not in params or not params['capabilities']:
                        params['capabilities'] = {
                            "experimental": {},
                            "prompts": {"listChanged": False},
                            "resources": {"subscribe": False, "listChanged": False},
                            "tools": {"listChanged": False}
                        }
                        logger.info(f"[MCP FIX] Added missing capabilities to initialize request")
                    elif isinstance(params['capabilities'], dict):
                        # Fill in missing capability fields
                        caps = params['capabilities']
                        if 'experimental' not in caps:
                            caps['experimental'] = {}
                        if 'prompts' not in caps:
                            caps['prompts'] = {"listChanged": False}
                        if 'resources' not in caps:
                            caps['resources'] = {"subscribe": False, "listChanged": False}
                        if 'tools' not in caps:
                            caps['tools'] = {"listChanged": False}
                    
                    # Ensure clientInfo exists
                    if 'clientInfo' not in params:
                        params['clientInfo'] = {
                            "name": "Claude.ai",
                            "version": "1.0.0"
                        }
                    
                    # Update the body_json with fixed params
                    body_json['params'] = params
                    # Re-encode the fixed body
                    body = json.dumps(body_json).encode('utf-8')
                    logger.info(f"[MCP FIX] Fixed initialize request for session {session_id}")
                
                # Log MCP method details
                if method == 'initialize':
                    protocol_version = body_json.get('params', {}).get('protocolVersion', 'unknown')
                    client_info = body_json.get('params', {}).get('clientInfo', {})
                    await _unified_logger.log(
                        "info",
                        "MCP Initialize",
                        mcp_method=method,
                        mcp_id=request_id,
                        session_id=session_id,
                        client_ip=client_ip,
                        protocol_version=protocol_version,
                        client_name=client_info.get('name', 'unknown'),
                        client_version=client_info.get('version', 'unknown')
                    )
                elif method == 'tools/call':
                    tool_name = body_json.get('params', {}).get('name', 'unknown')
                    tool_args = body_json.get('params', {}).get('arguments', {})
                    await _unified_logger.log(
                        "info",
                        f"MCP Tool call: {tool_name}",
                        mcp_method=method,
                        mcp_id=request_id,
                        session_id=session_id,
                        client_ip=client_ip,
                        tool_name=tool_name,
                        tool_args=json.dumps(tool_args)[:200]
                    )
                elif method == 'tools/list':
                    await _unified_logger.log(
                        "info",
                        "MCP List tools",
                        mcp_method=method,
                        mcp_id=request_id,
                        session_id=session_id,
                        client_ip=client_ip
                    )
                elif method == 'notifications/initialized':
                    await _unified_logger.log(
                        "info",
                        "MCP Initialized notification",
                        mcp_method=method,
                        session_id=session_id,
                        client_ip=client_ip
                    )
                else:
                    await _unified_logger.log(
                        "info",
                        f"MCP Method: {method}",
                        mcp_method=method,
                        mcp_id=request_id,
                        session_id=session_id,
                        client_ip=client_ip
                    )
            except json.JSONDecodeError:
                await _unified_logger.log(
                    "warning",
                    "MCP Non-JSON body",
                    body_preview=str(body[:100]),
                    session_id=session_id
                )
            except Exception as e:
                await _unified_logger.log(
                    "error",
                    f"MCP Parse error: {e}",
                    error=str(e),
                    session_id=session_id
                )
        
        # Handle requests that come before initialization
        if needs_init_injection and method == 'tools/list':
            logger.info(f"[MCP FIX] Intercepting tools/list before initialization")
            
            # For tools/list before initialization, we'll modify the request to be an initialize first
            # Then let the original tools/list be sent after
            modified_request = {
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "experimental": {},
                        "prompts": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "tools": {"listChanged": False}
                    },
                    "clientInfo": {
                        "name": "Claude.ai (auto-init)",
                        "version": "1.0.0"
                    }
                },
                "jsonrpc": "2.0",
                "id": 0
            }
            
            # Replace the body with the initialize request
            original_body = body
            body = json.dumps(modified_request).encode('utf-8')
            logger.info(f"[MCP FIX] Replaced tools/list with initialize request")
        
        # Create receive callable
        async def receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    'type': 'http.request',
                    'body': body,
                    'more_body': False
                }
            else:
                # This simulates waiting for more body that will never come
                await asyncio.Event().wait()
        
        # Queue for streaming response chunks
        response_queue = asyncio.Queue()
        response_started = False
        response_status = 200
        response_headers = {}
        
        async def send(message):
            nonlocal response_started, response_status, response_headers
            if message['type'] == 'http.response.start':
                response_started = True
                response_status = message.get('status', 200)
                # Convert headers to dict
                for name, value in message.get('headers', []):
                    name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                    value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                    response_headers[name_str] = value_str
            elif message['type'] == 'http.response.body':
                body_chunk = message.get('body', b'')
                more_body = message.get('more_body', False)
                await response_queue.put((body_chunk, more_body))
                if not more_body:
                    # Signal end of stream
                    await response_queue.put((None, False))
        
        # Run the MCP app in background
        task = asyncio.create_task(_mcp_app(scope, receive, send))
        
        # Create streaming response generator with keepalive
        async def generate():
            try:
                last_activity = asyncio.get_event_loop().time()
                keepalive_interval = 15  # Send keepalive every 15 seconds (more frequent)
                
                while True:
                    try:
                        # Check for data with timeout
                        chunk, more = await asyncio.wait_for(
                            response_queue.get(),
                            timeout=1.0  # Check every second
                        )
                        last_activity = asyncio.get_event_loop().time()
                        
                        if chunk is None:
                            break
                        if chunk:
                            # Log response chunks for debugging
                            chunk_str = chunk.decode('utf-8', errors='ignore')[:500]
                            if 'data:' in chunk_str:
                                try:
                                    # Extract and log MCP response
                                    data_start = chunk_str.find('data:') + 5
                                    data_str = chunk_str[data_start:].strip()
                                    if data_str and data_str != '[DONE]':
                                        data_json = json.loads(data_str)
                                        if 'result' in data_json:
                                            logger.info(f"[MCP RESPONSE] Result for id={data_json.get('id', 'unknown')}: {str(data_json.get('result', ''))[:200]}")
                                        elif 'error' in data_json:
                                            error_code = data_json.get('error', {}).get('code')
                                            error_msg = data_json.get('error', {}).get('message')
                                            logger.error(f"[MCP RESPONSE] Error for id={data_json.get('id', 'unknown')}: {error_code} - {error_msg}")
                                            
                                            # If we get an initialization error, log additional context
                                            if error_code == -32602 and 'initialization' in str(error_msg).lower():
                                                logger.warning(f"[MCP FIX] Client needs to send initialize first. Session: {session_id}")
                                except:
                                    pass  # Ignore parsing errors for partial chunks
                            yield chunk
                        if not more:
                            logger.info(f"[MCP RESPONSE] Stream completed for session {session_id}")
                            break
                    except asyncio.TimeoutError:
                        # Check if we need to send keepalive
                        current_time = asyncio.get_event_loop().time()
                        if current_time - last_activity > keepalive_interval:
                            # Send SSE comment as keepalive - more frequent to prevent timeouts
                            logger.debug(f"[MCP KEEPALIVE] Sending keepalive for session {session_id}")
                            yield b': keepalive\n\n'
                            last_activity = current_time
                        # Continue waiting for data
                        continue
            except asyncio.CancelledError:
                logger.info(f"[MCP HANDLER] Stream cancelled for session {session_id}")
                # Don't re-raise, just end the stream gracefully
            except Exception as e:
                logger.error(f"[MCP HANDLER] Error in generate for session {session_id}: {e}")
                # Send error event to client before closing
                error_event = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Internal server error",
                        "data": str(e)
                    }
                }
                yield f"event: error\ndata: {json.dumps(error_event)}\n\n".encode('utf-8')
            finally:
                # Cancel the task if not done
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
        
        # Wait for response to start to get headers
        max_wait = 10  # Maximum 10 seconds to wait for response
        wait_time = 0
        while not response_started and wait_time < max_wait:
            await asyncio.sleep(0.01)
            wait_time += 0.01
        
        if not response_started:
            logger.error(f"[MCP HANDLER] Response did not start within {max_wait}s for session {session_id}")
        
        # Check if it's an SSE stream
        content_type = response_headers.get('content-type', '').lower()
        
        # Log response type and headers
        logger.info(f"[MCP RESPONSE] Status={response_status}, Content-Type={content_type}, Session={response_headers.get('mcp-session-id', 'none')}")
        
        if 'text/event-stream' in content_type:
            # Use StreamingResponse for SSE
            logger.info(f"[MCP RESPONSE] Starting SSE stream for session {session_id}")
            return StreamingResponse(
                generate(),
                status_code=response_status,
                headers=response_headers,
                media_type='text/event-stream'
            )
        else:
            # For non-SSE responses, collect all chunks
            logger.info(f"[MCP RESPONSE] Collecting non-SSE response for session {session_id}")
            chunks = []
            async for chunk in generate():
                chunks.append(chunk)
            
            full_response = b''.join(chunks)
            # Log the response content
            try:
                response_json = json.loads(full_response)
                logger.info(f"[MCP RESPONSE] JSON response: {json.dumps(response_json)[:500]}")
            except:
                logger.info(f"[MCP RESPONSE] Non-JSON response: {full_response[:200]}")
            
            return Response(
                content=full_response,
                status_code=response_status,
                headers=response_headers
            )
    
    logger.info("[MCP MOUNT] Added /mcp route handler (no trailing slash)")
    
    # Initialize task group immediately
    logger.info("[MCP MOUNT] Starting MCP task group initialization")
    
    async def run_mcp_session_manager():
        """Run the MCP session manager with its task group."""
        try:
            async with _mcp_session_manager.run():
                logger.info("[MCP MOUNT] MCP session manager started with task group")
                await unified_logger.event(
                    "mcp_server_started",
                    {"tools_count": tool_count, "status": "mounted"}
                )
                # Keep running until cancelled
                await asyncio.Event().wait()
        except asyncio.CancelledError:
            logger.info("[MCP MOUNT] MCP session manager cancelled")
            await unified_logger.event("mcp_server_stopped", {})
        except Exception as e:
            logger.error(f"[MCP MOUNT ERROR] Session manager failed: {e}")
    
    # Start the session manager in a background task immediately
    _mcp_task = asyncio.create_task(run_mcp_session_manager())
    logger.info("[MCP MOUNT] MCP session manager task created")
    
    # Add shutdown event to cleanup
    @app.on_event("shutdown")
    async def shutdown_mcp_task_group():
        """Cleanup MCP task group on application shutdown."""
        global _mcp_task
        
        logger.info("[MCP MOUNT] Shutting down MCP task group")
        if _mcp_task and not _mcp_task.done():
            _mcp_task.cancel()
            try:
                await _mcp_task
            except asyncio.CancelledError:
                pass
        logger.info("[MCP MOUNT] MCP task group shutdown complete")
    
    logger.info("[MCP MOUNT] MCP app mounting complete")