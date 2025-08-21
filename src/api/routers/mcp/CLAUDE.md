# MCP (Model Context Protocol) Server Implementation

## Overview

The MCP server provides a Model Context Protocol endpoint that enables LLMs like Claude.ai to interact with the OAuth HTTPS Proxy system through a standardized protocol. The implementation uses the FastMCP SDK with streamable HTTP transport for real-time bidirectional communication.

## Architecture

### Components

1. **MCP Server** (`mcp_server.py`)
   - FastMCP server with stateful session management
   - 10+ integrated tools for system management
   - Full async/await implementation
   - Protocol version negotiation (2024-11-05, 2025-03-26, 2025-06-18)

2. **MCP Mount** (`mcp_mount.py`)
   - Direct mounting of SDK's Starlette app on FastAPI
   - SSE streaming support with proper async handling
   - Task group initialization for stateful operation
   - Handles both `/mcp` and `/mcp/` endpoints

3. **Registry Integration** (`registry.py`)
   - Automatic MCP server registration on startup
   - Integration with unified endpoint registry

## Endpoint Details

### Main Endpoint
- **URL**: `/mcp` (available on any configured domain)
- **Methods**: GET, POST, PUT, DELETE, OPTIONS, PATCH
- **Transport**: Streamable HTTP (not the outdated HTTP+SSE)
- **Content Types**: 
  - Request: `application/json`
  - Response: `text/event-stream` (SSE) or `application/json`

### Protocol Requirements
- **Accept Header**: Must include both `application/json` and `text/event-stream`
- **Session Management**: Stateful with `Mcp-Session-Id` header
- **Protocol Version**: `Mcp-Protocol-Version` header (defaults to 2025-06-18)

## Available Tools

### System Management
1. **echo** - Test connectivity and message handling
   ```python
   await echo(message="Hello MCP!")
   ```

2. **health_check** - Check system health status
   ```python
   await health_check()
   ```

### Proxy Management
3. **list_proxies** - List all configured proxy targets
   ```python
   await list_proxies(limit=10)
   ```

4. **create_proxy** - Create new proxy configuration
   ```python
   await create_proxy(
       hostname="app.example.com",
       target_url="http://localhost:3000"
   )
   ```

5. **delete_proxy** - Remove proxy configuration
   ```python
   await delete_proxy(hostname="app.example.com")
   ```

### Certificate Management
6. **list_certificates** - View SSL certificates
   ```python
   await list_certificates()
   ```

### Token Management
7. **list_tokens** - List API tokens
   ```python
   await list_tokens()
   ```

### Service Management
8. **list_services** - Docker service management
   ```python
   await list_services()
   ```

### Logging
9. **get_logs** - Access system logs
   ```python
   await get_logs(lines=100, level="ERROR")
   ```

### Admin Tools
10. **run_command** - Execute system commands (admin only)
    ```python
    await run_command(command="docker ps")
    ```

## Implementation Details

### Stateful Session Management

The MCP server runs in stateful mode to maintain session context:

```python
self.mcp = FastMCP(
    "OAuth-HTTPS-Proxy-MCP",
    streamable_http_path="/",
    stateless_http=False  # MUST be stateful for sessions
)
```

### Task Group Initialization

The session manager's task group is initialized on startup:

```python
async def run_mcp_session_manager():
    async with _mcp_session_manager.run():
        logger.info("[MCP MOUNT] MCP session manager started")
        await asyncio.Event().wait()  # Keep running

_mcp_task = asyncio.create_task(run_mcp_session_manager())
```

### SSE Streaming

The `/mcp` handler properly streams SSE responses:

```python
# Check if it's an SSE stream
if 'text/event-stream' in content_type:
    return StreamingResponse(
        generate(),
        status_code=response_status,
        headers=response_headers,
        media_type='text/event-stream'
    )
```

## Claude.ai Integration

### Connection Flow

1. **Initialize Session**
   ```json
   {
     "method": "initialize",
     "params": {
       "protocolVersion": "2025-06-18",
       "capabilities": {},
       "clientInfo": {
         "name": "Anthropic/ClaudeAI",
         "version": "1.0.0"
       }
     },
     "jsonrpc": "2.0",
     "id": 0
   }
   ```

2. **Send Initialized Notification**
   ```json
   {
     "method": "notifications/initialized",
     "jsonrpc": "2.0"
   }
   ```

3. **List Tools**
   ```json
   {
     "method": "tools/list",
     "params": {},
     "jsonrpc": "2.0",
     "id": 1
   }
   ```

4. **Call Tools**
   ```json
   {
     "method": "tools/call",
     "params": {
       "name": "echo",
       "arguments": {
         "message": "Hello from Claude!"
       }
     },
     "jsonrpc": "2.0",
     "id": 2
   }
   ```

### Connection URL

To connect Claude.ai to the MCP server:
1. Use the full URL: `https://your-domain.com/mcp`
2. Claude will automatically handle the protocol negotiation
3. Tools will be discovered and available for use

## Testing

### Manual Testing

Test the MCP endpoint with curl:

```bash
# Initialize session
curl -X POST https://your-domain.com/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"method":"initialize","params":{"protocolVersion":"2025-06-18"},"jsonrpc":"2.0","id":0}'
```

### Python Testing

See `/tmp/test_mcp_claude_flow.py` for comprehensive testing:

```python
async def test_claude_flow(url: str, name: str):
    # 1. Initialize session
    # 2. Send initialized notification
    # 3. List tools
    # 4. Call echo tool
```

## Troubleshooting

### Common Issues

1. **"Task group is not initialized" Error**
   - Ensure the session manager is started with `run()`
   - Check that the task group initialization completes

2. **SSE Stream Hangs**
   - Verify Accept header includes both media types
   - Check that SSE streaming uses `StreamingResponse`

3. **"Invalid request parameters" Error**
   - Ensure all requests include `params` field (even if empty)
   - Check protocol version compatibility

### Debug Logging

Enable debug logging for MCP:

```python
import logging
logging.getLogger("mcp").setLevel(logging.DEBUG)
logging.getLogger("src.api.routers.mcp").setLevel(logging.DEBUG)
```

## Security Considerations

- MCP endpoint is publicly accessible by default
- Tools respect the authentication system (bearer tokens, OAuth)
- Admin tools require admin authentication
- All operations are logged via unified logging system

## Future Enhancements

- [ ] Add resource management tools
- [ ] Implement prompt templates
- [ ] Add sampling capabilities
- [ ] Support for file operations
- [ ] Enhanced error handling and recovery
- [ ] WebSocket transport option
- [ ] Tool result caching

## Related Documentation

- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [MCP Specification](https://modelcontextprotocol.io/specification/2025-06-18)
- [API Documentation](../../CLAUDE.md)
- [OAuth Integration](../../oauth/CLAUDE.md)