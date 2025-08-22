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
from ....shared.dns_resolver import get_dns_resolver
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
    
    logger.info(f"[MCP MOUNT] mount_mcp_app called. Current _mcp_app: {_mcp_app}")
    
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
    tool_names = list(mcp._tool_manager._tools.keys()) if hasattr(mcp, '_tool_manager') and hasattr(mcp._tool_manager, '_tools') else []
    logger.info(f"[MCP MOUNT] Registered {tool_count} tools")
    if tool_names:
        logger.info(f"[MCP MOUNT] Tool names: {tool_names[:10]}")  # Log first 10 tool names
    else:
        logger.warning("[MCP MOUNT] No tools found in tool manager!")
    
    # Get the streamable HTTP app from the SDK
    _mcp_app = mcp.streamable_http_app()
    
    # Store the session manager for task group initialization
    _mcp_session_manager = mcp._session_manager
    
    # Store MCP server in app state for session interception
    app.state.mcp_server = mcp_server
    
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
        import time
        import asyncio
        from datetime import datetime, timezone
        
        # Start timing
        start_time = time.time()
        
        # Get trace_id from request.state (set by UnifiedLoggingMiddleware)
        trace_id = getattr(request.state, 'trace_id', None)
        if not trace_id:
            # Fallback - this shouldn't happen
            trace_id = f"mcp-no-trace-{int(time.time() * 1000)}"
            logger.warning(f"[MCP] No trace_id in request.state, using fallback: {trace_id}")
        
        # Get client info
        client_ip = request.client.host if request.client else "127.0.0.1"
        user_agent = request.headers.get('user-agent', 'unknown')
        session_id = request.headers.get('mcp-session-id', 'no-session')
        
        # Resolve client hostname
        dns_resolver = get_dns_resolver()
        client_hostname = await dns_resolver.resolve_ptr(client_ip)
        
        # Log to async storage for unified logging
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'trace_id': trace_id,
            'client_ip': client_ip,
            'client_hostname': client_hostname,
            'proxy_hostname': request.headers.get('host', 'localhost'),
            'method': request.method,
            'path': '/mcp',
            'user': 'anonymous',
            'user_agent': user_agent,
            'referrer': request.headers.get('referer', ''),
            'mcp_session_id': session_id,  # MCP-specific session
            'status': 0,  # Will be updated later
            'response_time': 0  # Will be updated later
        }
        
        # Log initial request (we'll update status and response time later)
        if hasattr(request.app.state, 'async_storage'):
            try:
                await request.app.state.async_storage.log_request(log_entry)
            except Exception as e:
                logger.warning(f"[MCP] Failed to log initial request: {e}")
        
        # Simply forward to the mounted app with adjusted path
        # The mounted app at /mcp/ expects the request at the root path /
        from starlette.responses import StreamingResponse, JSONResponse
        
        # Check if Accept header includes required formats
        accept_header = request.headers.get('accept', '')
        
        # If Accept header doesn't include the required formats, add them
        # This is to support Claude.ai which might send browser GET requests
        headers_list = []
        has_event_stream = 'text/event-stream' in accept_header
        has_json = 'application/json' in accept_header
        
        # Track if we already have session header
        has_session_header = False
        
        for k, v in request.headers.items():
            if k.lower() == 'mcp-session-id':
                has_session_header = True
            # Pass Accept header as-is to respect client preference!
            # Don't force SSE when client doesn't want it
            headers_list.append((k.encode(), v.encode()))
        
        # Log what the client actually wants
        if not has_event_stream and has_json:
            logger.info(f"[MCP HANDLER] Client wants JSON only (no SSE)")
        elif has_event_stream and not has_json:
            logger.info(f"[MCP HANDLER] Client wants SSE only")
        elif has_event_stream and has_json:
            logger.info(f"[MCP HANDLER] Client accepts both JSON and SSE")
        
        # Handle GET requests differently - they don't have a body
        if request.method == 'GET':
            # GET requests are for establishing SSE stream
            body = b''  # No body for GET
            logger.info(f"[MCP HANDLER] GET request for SSE stream from {client_ip}")
            await _unified_logger.log(
                "info",
                "MCP GET request for SSE stream",
                trace_id=trace_id,
                method="GET",
                client_ip=client_ip,
                client_hostname=client_hostname,
                proxy_hostname=request.headers.get('host', 'localhost'),
                mcp_session_id=session_id,
                accept=accept_header
            )
        else:
            # POST/PUT/etc have body
            body = await request.body()
        
        body_sent = False
        
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
        
        # Track if we need to inject initialization
        needs_init_injection = False
        
        # Log request body for MCP protocol messages (only for non-GET)
        if body and request.method != 'GET':
            try:
                body_json = json.loads(body)
                method = body_json.get('method', 'unknown')
                request_id = body_json.get('id', 'no-id')
                
                # Log tools/list requests
                if method == 'tools/list':
                    logger.info(f"[MCP] Tools/list request from {client_ip} with session {session_id}")
                
                # Log initialize requests
                if method == 'initialize':
                    logger.info(f"[MCP] Initialize request from {client_ip}")
                
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
                    import time
                    list_start = time.time()
                    await _unified_logger.log(
                        "info",
                        "MCP List tools request received",
                        mcp_method=method,
                        mcp_id=request_id,
                        session_id=session_id,
                        client_ip=client_ip
                    )
                    # Log what tools are available
                    if hasattr(request.app.state, 'mcp_server'):
                        mcp_srv = request.app.state.mcp_server
                        if hasattr(mcp_srv, 'mcp') and hasattr(mcp_srv.mcp, '_tool_manager'):
                            tool_count = len(mcp_srv.mcp._tool_manager._tools)
                            tool_names = list(mcp_srv.mcp._tool_manager._tools.keys()) if hasattr(mcp_srv.mcp._tool_manager, '_tools') else []
                            list_elapsed = (time.time() - list_start) * 1000
                            await _unified_logger.log(
                                "info",
                                f"MCP Server has {tool_count} tools available (enumeration took {list_elapsed:.2f}ms)",
                                tool_count=tool_count,
                                tool_names=tool_names[:10],  # Log first 10 tool names
                                session_id=session_id,
                                enumeration_ms=list_elapsed
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
        
        # In stateless mode, all requests are automatically initialized
        # No need for special handling
        
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
        actual_session_id = None  # Track the actual session ID from response headers
        
        async def send(message):
            nonlocal response_started, response_status, response_headers, actual_session_id
            if message['type'] == 'http.response.start':
                response_started = True
                response_status = message.get('status', 200)
                # Convert headers to dict
                for name, value in message.get('headers', []):
                    name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                    value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                    response_headers[name_str] = value_str
                    
                    # Store session ID for future use
                    if name_str.lower() == 'mcp-session-id' and value_str and value_str != 'none':
                        actual_session_id = value_str  # Capture the actual session ID
                        logger.info(f"[MCP] Session ID in response headers: {value_str}")
            elif message['type'] == 'http.response.body':
                body_chunk = message.get('body', b'')
                more_body = message.get('more_body', False)
                await response_queue.put((body_chunk, more_body))
                if not more_body:
                    # Signal end of stream  
                    await response_queue.put((None, False))
        
        # Run the MCP app in background
        if _mcp_app is None:
            logger.error("[MCP HANDLER] ERROR: _mcp_app is None! MCP not properly initialized")
            return Response(
                content="Bad Request: MCP server not initialized",
                status_code=400
            )
        
        # Track timing for tools/list requests
        # Use perf_counter for accurate timing
        is_tools_list = b'"method": "tools/list"' in body or b'"method":"tools/list"' in body
        if is_tools_list:
            app_start = time.perf_counter()
            logger.debug(f"[MCP TIMING] Starting FastMCP app processing for tools/list")  # Changed to debug
        
        task = asyncio.create_task(_mcp_app(scope, receive, send))
        
        if is_tools_list:
            app_elapsed = (time.perf_counter() - app_start) * 1000
            if app_elapsed > 10:  # Only log if slow
                logger.warning(f"[MCP TIMING] FastMCP app task slow: {app_elapsed:.2f}ms")
        
        # Create streaming response generator with keepalive
        async def generate(is_sse=False):
            nonlocal actual_session_id
            chunk_count = 0
            total_bytes = 0
            try:
                last_activity = asyncio.get_event_loop().time()
                keepalive_interval = 15  # Send keepalive every 15 seconds (more frequent)
                
                # For GET requests establishing SSE, send initial comment
                if request.method == 'GET' and is_sse:
                    yield b': SSE stream established\n\n'
                    logger.info(f"[MCP SSE] Established SSE stream for session {session_id}")
                
                while True:
                    try:
                        # Check for data with timeout
                        chunk, more = await asyncio.wait_for(
                            response_queue.get(),
                            timeout=1.0  # Check every second
                        )
                        last_activity = asyncio.get_event_loop().time()
                        
                        if chunk is None:
                            # End of stream - close it
                            logger.info(f"[MCP RESPONSE] End of stream after {chunk_count} chunks, {total_bytes} bytes")
                            return  # Properly terminate the generator
                        if chunk:
                            chunk_count += 1
                            total_bytes += len(chunk)
                            
                            # Log progress for tools/list
                            if is_tools_list and chunk_count == 1:
                                # Skip logging in hot path unless slow
                                elapsed_ms = (time.perf_counter() - app_start)*1000
                                if elapsed_ms > 100:  # Only log if slow
                                    logger.warning(f"[MCP TIMING] Slow first chunk: {elapsed_ms:.2f}ms, size: {len(chunk)} bytes")
                            
                            # Log response chunks for debugging
                            # For large responses, we need to check more than 500 chars
                            chunk_str = chunk.decode('utf-8', errors='ignore')
                            response_complete = False
                            
                            # For tools/list, the response is huge (54KB) so check the full chunk
                            if 'data:' in chunk_str[:1000]:
                                try:
                                    # Extract and log MCP response
                                    data_start = chunk_str.find('data:') + 5
                                    data_str = chunk_str[data_start:].strip()
                                    if data_str and data_str != '[DONE]':
                                        data_json = json.loads(data_str)
                                        
                                        # Check if this is a complete JSON-RPC response
                                        if 'jsonrpc' in data_json and 'id' in data_json and ('result' in data_json or 'error' in data_json):
                                            # This is a complete response - we should close after sending it
                                            response_complete = True
                                            req_id = data_json.get('id', 'unknown')
                                            logger.info(f"[MCP RESPONSE] Complete JSON-RPC response detected for id={req_id}, will close stream")
                                        
                                        if 'result' in data_json:
                                            result = data_json.get('result', {})
                                            req_id = data_json.get('id', 'unknown')
                                            
                                            # Log initialize response (sessionId should be in headers per MCP spec)
                                            if req_id == 0:
                                                # Log with unified logger
                                                if _unified_logger:
                                                    await _unified_logger.log(
                                                        "info",
                                                        "MCP Initialize response received",
                                                        session_id=actual_session_id or "none",
                                                        session_in_header=actual_session_id is not None,
                                                        protocol_version=result.get('protocolVersion'),
                                                        client_ip=client_ip
                                                    )
                                            
                                            # Special logging for tools/list response WITH TIMING
                                            if req_id == 1 and isinstance(result, dict) and 'tools' in result:
                                                tools_list = result.get('tools', [])
                                                if is_tools_list:
                                                    tools_elapsed = (time.perf_counter() - app_start) * 1000 if 'app_start' in locals() else 0
                                                    if tools_elapsed > 100:  # Only log if slow
                                                        logger.warning(f"[MCP TIMING] Slow tools/list: {tools_elapsed:.2f}ms - returning {len(tools_list)} tools")
                                                logger.info(f"[MCP RESPONSE] Tools/list response - returning {len(tools_list)} tools")
                                                if tools_list:
                                                    logger.info(f"[MCP RESPONSE] Tool names: {[t.get('name', 'unknown') for t in tools_list[:5]]}")
                                                    # Log tool sizes to check if serialization is the issue
                                                    tool_sizes = [len(json.dumps(t)) for t in tools_list[:5]]
                                                    logger.info(f"[MCP RESPONSE] Tool JSON sizes (bytes): {tool_sizes}")
                                                else:
                                                    logger.warning(f"[MCP RESPONSE] Empty tools list returned!")
                                            else:
                                                logger.info(f"[MCP RESPONSE] Result for id={req_id}: {str(result)[:200]}")
                                        elif 'error' in data_json:
                                            error_code = data_json.get('error', {}).get('code')
                                            error_msg = data_json.get('error', {}).get('message')
                                            logger.error(f"[MCP RESPONSE] Error for id={data_json.get('id', 'unknown')}: {error_code} - {error_msg}")
                                            
                                            # If we get an initialization error, log additional context
                                            if error_code == -32602 and 'initialization' in str(error_msg).lower():
                                                logger.warning(f"[MCP FIX] Client needs to send initialize first. Session: {session_id}")
                                except Exception as e:
                                    if is_tools_list:
                                        logger.warning(f"[MCP TIMING] Failed to parse tools/list response: {str(e)[:200]}")
                                    pass  # Ignore parsing errors for partial chunks
                            
                            # CRITICAL FIX: For large SSE chunks, add explicit flush
                            # The 29KB tools/list response needs immediate transmission
                            if is_sse and len(chunk) > 10000:
                                # Large SSE response - yield with flush signal
                                yield chunk
                                # SSE requires double newline to flush
                                if not chunk.endswith(b'\n\n'):
                                    yield b'\n\n'  # Force flush
                            else:
                                # Normal chunk
                                yield chunk
                            
                            # If we've sent a complete JSON-RPC response, close the stream
                            if response_complete:
                                logger.info(f"[MCP RESPONSE] Closing SSE stream after complete response for session {session_id}")
                                logger.info(f"[MCP RESPONSE] End of stream after {chunk_count} chunks, {total_bytes} bytes")
                                return  # Properly terminate the generator
                                
                            # For tools/list specifically, if we've sent the large chunk, close
                            # Lower threshold since 29KB is still causing timeouts
                            if is_tools_list and chunk_count == 1 and len(chunk) > 25000:
                                logger.info(f"[MCP TIMING] Closing stream after sending {len(chunk)} byte tools/list response")
                                logger.info(f"[MCP RESPONSE] End of stream after {chunk_count} chunks, {total_bytes} bytes")
                                return  # Properly terminate the generator
                                
                        # When response is complete, close the stream
                        if not more:
                            logger.debug(f"[MCP RESPONSE] Response completed for session {session_id}, closing stream")
                            logger.info(f"[MCP RESPONSE] End of stream after {chunk_count} chunks, {total_bytes} bytes")
                            # For MCP, we should close the SSE stream after sending the response
                            # This matches the behavior of the working mcp-echo-server
                            return  # Properly terminate the generator
                    except asyncio.TimeoutError:
                        # Check if we need to send keepalive
                        current_time = asyncio.get_event_loop().time()
                        
                        # Log if we're stuck waiting for tools/list
                        if is_tools_list:
                            if chunk_count == 0 and (current_time - last_activity) > 2:
                                logger.warning(f"[MCP TIMING] No chunks received after {(time.perf_counter() - app_start)*1000:.2f}ms - FastMCP may be hanging!")
                            elif chunk_count > 0 and (current_time - last_activity) > 2:
                                logger.warning(f"[MCP TIMING] Stuck after {chunk_count} chunks ({total_bytes} bytes) - waiting {(time.perf_counter() - app_start)*1000:.2f}ms total")
                        
                        if current_time - last_activity > keepalive_interval:
                            # Send SSE comment as keepalive - more frequent to prevent timeouts
                            logger.debug(f"[MCP KEEPALIVE] Sending keepalive for session {session_id}")
                            yield b': keepalive\n\n'
                            last_activity = current_time
                        # Continue waiting for data
                        continue
            except asyncio.CancelledError:
                logger.warning(f"[MCP HANDLER] Stream cancelled for session {session_id} - Client likely disconnected")
                # Send connection closed error before ending
                error_event = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Connection closed",
                        "data": "Client disconnected"
                    }
                }
                yield f"event: error\ndata: {json.dumps(error_event)}\n\n".encode('utf-8')
            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                logger.error(f"[MCP HANDLER] Error in generate for session {session_id}: {e}\nTraceback:\n{error_trace}")
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
        
        # Wait for response to start to get headers from MCP server
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
        logger.info(f"[MCP RESPONSE] All headers: {json.dumps(response_headers, indent=2)}")
        
        if 'text/event-stream' in content_type:
            # Use StreamingResponse for SSE
            logger.info(f"[MCP RESPONSE] Starting SSE stream for session {session_id}")
            
            # Add headers to prevent connection drops
            response_headers['Cache-Control'] = 'no-cache'
            response_headers['Connection'] = 'keep-alive'
            response_headers['X-Accel-Buffering'] = 'no'  # Disable proxy buffering
            
            # Log response with updated status and time
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            if hasattr(request.app.state, 'async_storage'):
                # Create new log entry with final status and response time
                final_log_entry = log_entry.copy()
                final_log_entry['status'] = response_status
                final_log_entry['response_time'] = response_time
                final_log_entry['message'] = f"{request.method} /mcp {response_status} {response_time:.0f}ms"
                # Use fire-and-forget since we're returning a streaming response
                asyncio.create_task(request.app.state.async_storage.log_request(final_log_entry))
            
            # CRITICAL FIX: Disable buffering for SSE streams
            # The 3-second delay was caused by response buffering
            response_headers['X-Accel-Buffering'] = 'no'  # Nginx
            response_headers['Cache-Control'] = 'no-cache, no-transform'
            
            return StreamingResponse(
                generate(is_sse=True),
                status_code=response_status,
                headers=response_headers,
                media_type='text/event-stream'
            )
        else:
            # For non-SSE responses, collect all chunks
            logger.info(f"[MCP RESPONSE] Collecting non-SSE response for session {session_id}")
            chunks = []
            async for chunk in generate(is_sse=False):
                chunks.append(chunk)
            
            full_response = b''.join(chunks)
            # Log the response content
            try:
                response_json = json.loads(full_response)
                logger.info(f"[MCP RESPONSE] JSON response: {json.dumps(response_json)[:500]}")
            except:
                logger.info(f"[MCP RESPONSE] Non-JSON response: {full_response[:200]}")
            
            # Log response with updated status and time
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            if hasattr(request.app.state, 'async_storage'):
                # Create new log entry with final status and response time
                final_log_entry = log_entry.copy()
                final_log_entry['status'] = response_status
                final_log_entry['response_time'] = response_time
                final_log_entry['message'] = f"{request.method} /mcp {response_status} {response_time:.0f}ms"
                # Use fire-and-forget since we're returning a streaming response
                asyncio.create_task(request.app.state.async_storage.log_request(final_log_entry))
            
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