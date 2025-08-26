# MCP Pure Implementation Plan & Architecture Decision Records

## Executive Summary

This document outlines the complete plan to fix the MCP (Model Context Protocol) endpoint streaming issues that prevent Claude.ai from seeing available tools. The root cause is the MCPASGIMiddleware buffering SSE streams instead of allowing them to stream properly. The solution is to remove this middleware entirely and mount the Starlette app directly on FastAPI.

## Problem Statement

### Current Issue
Claude.ai (IP: 34.162.102.82) cannot see tools when connecting to https://auth.atratest.org/mcp. Logs show:
- "Streaming error: Attempted to read or stream content, but the stream has been closed"
- SSE data (327 bytes) is generated but never properly streamed to the client
- Connection closes before Claude.ai can read the response

### Root Cause Analysis

1. **MCPASGIMiddleware buffers all SSE data**:
   - Intercepts `/mcp` requests at ASGI level
   - Captures response headers and body in arrays
   - Waits for the entire response to complete
   - Then tries to send all buffered data at once
   - Connection closes immediately after

2. **This breaks SSE fundamentally**:
   - SSE (Server-Sent Events) requires real-time streaming
   - Buffering defeats the entire purpose of SSE
   - Client expects gradual data arrival, not bulk delivery
   - Connection lifecycle is broken by buffering

3. **Middleware was unnecessary**:
   - Originally created to bypass FastAPI's BaseHTTPMiddleware SSE bug
   - With pure MCP implementation, we don't use FastAPI middleware
   - MCPStarletteApp already handles SSE correctly with StreamingResponse
   - Adding interception layer only causes problems

## Architecture Decision Records (ADRs)

### ADR-001: Remove MCPASGIMiddleware Completely

**Status**: Proposed

**Context**: 
- MCPASGIMiddleware was created to bypass BaseHTTPMiddleware's SSE bug in Starlette
- The bug causes `RuntimeError: Unexpected message received: http.request` with HTTP/1.1 keep-alive
- We now have a pure MCP implementation that doesn't use FastAPI's middleware stack

**Decision**: 
Remove MCPASGIMiddleware entirely and mount the Starlette app directly using FastAPI's mount() method.

**Consequences**:
- **Positive**: 
  - True SSE streaming without buffering
  - Simpler architecture (removes 300+ lines of complex code)
  - Better performance (no double buffering)
  - Standard FastAPI patterns
- **Negative**: 
  - None identified - the middleware serves no purpose with pure implementation

**Rationale**:
The middleware was a workaround for a problem we no longer have. With our pure implementation, it only adds complexity and breaks streaming.

### ADR-002: Use Standard FastAPI Mount for Starlette Apps

**Status**: Proposed

**Context**:
- FastAPI supports mounting ASGI/WSGI applications via `app.mount()`
- This is the standard pattern for integrating Starlette apps
- No need for custom ASGI middleware wrappers

**Decision**:
Use `app.mount("/mcp", starlette_app)` to mount the MCP Starlette app.

**Consequences**:
- **Positive**:
  - Standard, well-documented pattern
  - Maintains FastAPI's routing for other endpoints
  - Clean separation of concerns
  - Works with all FastAPI features (CORS, etc.)
- **Negative**:
  - None - this is the recommended approach

### ADR-003: Pure MCP Server Implementation

**Status**: Implemented

**Context**:
- FastMCP SDK had a race condition where SSE writer closed in 4ms before data could be sent
- Multiple attempts to fix the SDK failed
- Need full control over the streaming behavior

**Decision**:
Implement MCP protocol from scratch with:
- PureMCPServer: Core protocol implementation
- MCPStarletteApp: Starlette app with proper SSE streaming
- Direct Redis integration for sessions
- UnifiedAsyncLogger throughout

**Consequences**:
- **Positive**:
  - Full control over streaming behavior
  - No external SDK bugs
  - Better integration with our architecture
  - Comprehensive logging and debugging
- **Negative**:
  - More code to maintain
  - Need to track MCP protocol changes

### ADR-004: SSE Implementation Pattern

**Status**: Proposed

**Context**:
- SSE requires specific format: `event: <name>\ndata: <json>\n\n`
- Connections must stay alive for streaming
- Need proper error handling in stream

**Decision**:
Use Starlette's StreamingResponse with async generator:
```python
async def generate_sse():
    yield b": keep-alive\n\n"  # Initial keep-alive
    response = await process_request()
    yield f"event: message\ndata: {json.dumps(response)}\n\n".encode()
    yield b"event: close\ndata: stream_complete\n\n"  # Explicit close
```

**Consequences**:
- **Positive**:
  - Proper SSE format
  - Clean connection lifecycle
  - Error events in stream
- **Negative**:
  - None

## Implementation Plan

### Phase 1: Remove MCPASGIMiddleware

#### 1.1 Update mount_mcp_app Function

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/mcp.py`

```python
def mount_mcp_app(
    app: FastAPI,
    async_storage: UnifiedStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
):
    """Mount MCP Starlette app directly on FastAPI.
    
    This mounts the pure MCP server's Starlette app at /mcp using
    FastAPI's standard mount() method for sub-applications.
    
    Args:
        app: FastAPI application instance
        async_storage: UnifiedStorage for Redis operations
        cert_manager: Optional certificate manager
        docker_manager: Optional Docker manager
        unified_logger: UnifiedAsyncLogger for logging
        
    Returns:
        The FastAPI app (no wrapper needed)
    """
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP MOUNT] Mounting pure MCP server")
    
    # Create integrated MCP server
    mcp_server = IntegratedMCPServer(
        async_storage,
        unified_logger,
        cert_manager,
        docker_manager
    )
    
    # Get the Starlette app
    starlette_app = mcp_server.get_starlette_app()
    
    # Get server info for logging
    mcp = mcp_server.get_server()
    tool_count = len(mcp.tools)
    tool_names = list(mcp.tools.keys())
    
    logger.info(f"[MCP MOUNT] Registered {tool_count} tools")
    if tool_names:
        logger.info(f"[MCP MOUNT] Tool names: {tool_names[:10]}")
    
    # Mount Starlette app directly on FastAPI
    from starlette.routing import Mount
    app.mount("/mcp", starlette_app)
    
    logger.info("[MCP MOUNT] Mounted Starlette app directly at /mcp")
    
    # Log server started event
    if unified_logger:
        asyncio.create_task(unified_logger.event(
            "mcp_server_started",
            {"tools_count": tool_count, "status": "mounted"}
        ))
    
    # Add shutdown handler
    @app.on_event("shutdown")
    async def shutdown_mcp():
        """Cleanup MCP server on shutdown."""
        logger.info("[MCP MOUNT] Shutting down MCP server")
        if unified_logger:
            await unified_logger.event("mcp_server_stopped", {})
    
    logger.info("[MCP MOUNT] MCP mounting complete")
    
    # Return the app unchanged (no wrapper!)
    return app
```

#### 1.2 Remove MCPASGIMiddleware Class

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/mcp.py`

Delete lines 34-322 (entire MCPASGIMiddleware class and its __call__ method).

### Phase 2: Update Registry

#### 2.1 Remove Wrapper Handling

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/registry.py`

```python
# Line 184 - Remove mcp_wrapper variable
# Line 187 - Just call mount_mcp_app, don't store return value
# Line 220 - Always return app

try:
    logger.info("Mounting MCP Starlette app...")
    _mount_mcp_app(app, async_storage, cert_manager, 
                   getattr(app.state, 'docker_manager', None), unified_logger)
    successful_routers.append("MCP (/mcp) - Mounted as Starlette app")
except Exception as e:
    # ... error handling ...

# Line 220
return app  # Always return the app, no wrapper
```

### Phase 3: Fix Main.py

#### 3.1 Remove Wrapper Reference

**File**: `/home/atrawog/oauth-https-proxy/src/main.py`

```python
# Line 246 - Serve the app directly, not wrapped_app
api_task = asyncio.create_task(serve(app, api_config))
```

### Phase 4: Improve SSE Streaming

#### 4.1 Enhanced SSE Generator

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/mcp_starlette_app.py`

```python
async def generate_sse():
    """Generate SSE stream with proper formatting and lifecycle."""
    request_id = f"sse_{secrets.token_hex(4)}"
    
    try:
        logger.debug(f"[MCP APP] Starting SSE generation for {rpc_method} (req: {request_id})")
        
        # Send initial comment to establish connection
        yield b": connection established\n\n"
        
        # Small delay to ensure connection is established
        await asyncio.sleep(0.01)
        
        # Process the request
        response = await self.mcp.process_request(body, session_id)
        
        # Log response details
        response_json = json.dumps(response)
        logger.info(f"[MCP APP] Response for {rpc_method}: {len(response_json)} bytes")
        
        # Format as SSE with proper line endings
        sse_data = f"event: message\ndata: {response_json}\n\n"
        
        # Log SSE transmission
        if self.mcp.logger:
            self.mcp.logger.debug(
                "Sending SSE response",
                trace_id=trace_id,
                session_id=session_id,
                method=rpc_method,
                response_size=len(sse_data),
                request_id=request_id
            )
        
        # Yield the SSE data
        yield sse_data.encode('utf-8')
        
        # Send completion event
        yield b"event: complete\ndata: {\"status\": \"success\"}\n\n"
        
        # Small delay before closing
        await asyncio.sleep(0.01)
        
        logger.debug(f"[MCP APP] SSE generation complete for {rpc_method} (req: {request_id})")
        
    except Exception as e:
        logger.error(f"[MCP APP] Error in SSE generation: {e}")
        
        # Send error as SSE event
        error_data = {
            "error": str(e),
            "type": type(e).__name__,
            "request_id": request_id
        }
        error_event = f"event: error\ndata: {json.dumps(error_data)}\n\n"
        yield error_event.encode('utf-8')
        
        # Log error if available
        if self.mcp.event_publisher:
            await self.mcp.event_publisher.publish_error(
                error=e,
                component="mcp_app",
                context={
                    "session_id": session_id,
                    "request": body,
                    "request_id": request_id
                },
                trace_id=trace_id
            )
```

#### 4.2 Update StreamingResponse Headers

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/mcp_starlette_app.py`

```python
return StreamingResponse(
    generate_sse(),
    media_type="text/event-stream; charset=utf-8",
    headers={
        "Cache-Control": "no-cache, no-store, must-revalidate, private",
        "X-Accel-Buffering": "no",  # Disable nginx buffering
        "Mcp-Session-Id": session_id,
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept",
        "X-Content-Type-Options": "nosniff",
        # Don't set Transfer-Encoding - let Starlette handle it
        # Don't set Content-Length - it's a stream
    }
)
```

### Phase 5: Enhanced Logging

#### 5.1 Add Request Correlation

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/mcp_starlette_app.py`

```python
async def handle_mcp(self, request: Request):
    """Handle MCP requests with proper SSE streaming."""
    
    # Generate or extract request ID
    request_id = request.headers.get("x-request-id", f"mcp_{secrets.token_hex(4)}")
    
    # Extract session ID
    session_id = request.headers.get("mcp-session-id")
    
    # Generate trace ID
    trace_id = f"mcp_req_{request_id}"
    
    # Extract request info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    method = request.method
    
    # Log with correlation
    logger.info(f"[MCP APP] {method} request (ID: {request_id})")
    
    if self.mcp.logger:
        self.mcp.logger.info(
            f"MCP {method} request received",
            trace_id=trace_id,
            request_id=request_id,
            method=method,
            session_id=session_id,
            client_ip=client_ip,
            user_agent=user_agent
        )
```

#### 5.2 Add Response Logging

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/pure_mcp_server.py`

```python
async def handle_tools_list(self, params: dict, session_id: str) -> dict:
    """List available tools with comprehensive logging."""
    trace_id = f"mcp_tools_{secrets.token_hex(4)}"
    
    # Format tools for response
    tools_list = []
    for name, tool in self.tools.items():
        tools_list.append({
            "name": name,
            "description": tool["description"],
            "inputSchema": tool.get("inputSchema", {
                "type": "object",
                "properties": tool.get("parameters", {}),
                "additionalProperties": False
            })
        })
    
    result = {"tools": tools_list}
    
    # Log the actual response being sent
    if self.logger:
        response_json = json.dumps(result)
        self.logger.info(
            f"Tools list response: {len(tools_list)} tools, {len(response_json)} bytes",
            trace_id=trace_id,
            session_id=session_id,
            tools_count=len(tools_list),
            response_size=len(response_json),
            tool_names=list(self.tools.keys())
        )
        
        # TRACE level for full response
        self.logger.trace(
            "Tools list full response",
            trace_id=trace_id,
            response=response_json
        )
    
    return result
```

### Phase 6: Documentation Updates

#### 6.1 Update MCP CLAUDE.md

**File**: `/home/atrawog/oauth-https-proxy/src/api/routers/mcp/CLAUDE.md`

Add new section after "## Architecture":

```markdown
## Architecture (Updated November 2025)

### Pure Implementation Architecture

The MCP server now uses a pure Python implementation mounted directly on FastAPI:

```
Request Flow:
  Client → FastAPI Router → Starlette Mount (/mcp) → MCPStarletteApp → StreamingResponse
```

Components:
1. **PureMCPServer** (`pure_mcp_server.py`): Core MCP protocol implementation
2. **MCPStarletteApp** (`mcp_starlette_app.py`): Starlette app handling HTTP/SSE
3. **Direct Mounting**: Uses FastAPI's standard `app.mount()` method

### Why No Middleware?

The MCPASGIMiddleware was removed because:
- It buffered SSE streams, breaking real-time streaming
- Pure implementation doesn't need to bypass BaseHTTPMiddleware
- Starlette's StreamingResponse handles SSE correctly
- Simpler architecture with standard patterns

See ADR-001 in implementation plan for detailed rationale.
```

#### 6.2 Update Main CLAUDE.md

**File**: `/home/atrawog/oauth-https-proxy/CLAUDE.md`

Update the MCP section:

```markdown
### MCP (Model Context Protocol) Support

The system provides **FULL MCP SUPPORT** for LLM integration:

### MCP Server Implementation ✅
- **Endpoint**: Available at `/mcp` on any configured domain
- **Transport**: Streamable HTTP with SSE (Server-Sent Events)
- **Architecture**: Pure Python implementation with direct Starlette mounting
- **No Middleware**: Removed MCPASGIMiddleware for proper SSE streaming
- **Session Management**: Redis-backed stateful sessions
- **Tool Integration**: Extensible tool system with 6+ built-in tools
```

## Testing Plan

### 1. Unit Testing

```bash
# Test SSE format
curl -N -X POST https://auth.atratest.org/mcp \
  -H "Accept: text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  2>&1 | tee /tmp/sse_test.log

# Verify format
grep "^event:" /tmp/sse_test.log
grep "^data:" /tmp/sse_test.log
```

### 2. Protocol Testing

```python
#!/usr/bin/env python3
# Test MCP protocol flow

import httpx
import json

async def test_mcp_flow():
    url = "https://auth.atratest.org/mcp"
    
    async with httpx.AsyncClient() as client:
        # 1. Initialize
        response = await client.post(url, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        }, headers={"Accept": "text/event-stream"})
        
        print(f"Initialize: {response.status_code}")
        session_id = response.headers.get("mcp-session-id")
        
        # 2. List tools
        response = await client.post(url, json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }, headers={
            "Accept": "text/event-stream",
            "Mcp-Session-Id": session_id
        })
        
        print(f"Tools list: {response.status_code}")
        print(f"Response: {response.text}")
```

### 3. Load Testing

```bash
# Test concurrent connections
for i in {1..10}; do
    curl -N -X POST https://auth.atratest.org/mcp \
      -H "Accept: text/event-stream" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":'$i',"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test'$i'","version":"1.0"}}}' &
done
wait
```

## Monitoring & Metrics

### Key Metrics to Track

1. **SSE Stream Metrics**:
   - Connection duration (p50, p95, p99)
   - Bytes transmitted per stream
   - Stream completion rate
   - Client disconnect reasons

2. **Protocol Metrics**:
   - Request/response latency by method
   - Tool execution time
   - Session duration
   - Error rates by error type

3. **Infrastructure Metrics**:
   - Memory usage (SSE connections can be long-lived)
   - Open connection count
   - Redis session storage size
   - CPU usage during streaming

### Logging Improvements

Add structured logging fields:
- `stream_id`: Unique ID per SSE stream
- `bytes_sent`: Total bytes transmitted
- `chunks_sent`: Number of SSE chunks
- `duration_ms`: Total stream duration
- `disconnect_reason`: Why stream ended

## Rollout Plan

### Phase 1: Development Environment
1. Implement changes in development
2. Run full test suite
3. Monitor for 24 hours

### Phase 2: Staging
1. Deploy to staging environment
2. Test with Claude.ai sandbox
3. Load test with 100 concurrent connections
4. Monitor for 48 hours

### Phase 3: Production
1. Deploy during low-traffic window
2. Monitor error rates closely
3. Test Claude.ai connectivity immediately
4. Keep rollback plan ready

### Rollback Plan
If issues occur:
1. Revert to previous commit
2. Restart API service
3. Clear Redis sessions: `redis-cli --scan --pattern "mcp:session:*" | xargs redis-cli del`
4. Notify users of temporary outage

## Success Criteria

1. **Claude.ai Integration**:
   - Tools appear in Claude.ai interface
   - Tool execution works without errors
   - No streaming timeouts

2. **Performance**:
   - SSE streams start within 100ms
   - No buffering delays
   - Memory usage stable under load

3. **Reliability**:
   - 99.9% success rate for initialize requests
   - No connection drops during streaming
   - Graceful error handling

## Appendix: Removed Code

The following code will be removed:

1. **MCPASGIMiddleware class** (288 lines)
   - Complex buffering logic
   - SSE interception
   - Connection tracking

2. **Global variables** (5 lines)
   - `_mcp_app`
   - `_mcp_session_manager`
   - `_mcp_task_group`
   - `_mcp_task`

3. **Task group management** (50 lines)
   - `run_mcp_session_manager()`
   - Task creation/shutdown

Total lines removed: ~350
Total complexity reduction: Significant

## Conclusion

This plan addresses the root cause of the SSE streaming issue by removing the problematic middleware layer and using standard FastAPI mounting patterns. The result will be a simpler, more reliable, and properly streaming MCP implementation that works correctly with Claude.ai and other MCP clients.