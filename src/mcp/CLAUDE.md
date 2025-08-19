# MCP (Model Context Protocol) Server Documentation

## Overview

The MCP module provides a complete implementation of the Model Context Protocol server integrated with oauth-https-proxy's infrastructure. It offers 21 debugging and management tools accessible via JSON-RPC 2.0 protocol.

## Architecture

### Core Components

1. **MCPServer** (`server.py`)
   - Main server class using official `mcp` SDK
   - Manages tool registration and server lifecycle
   - Integrates with Redis and logging infrastructure

2. **RedisStateManager** (`redis_state.py`)
   - Redis-backed state management
   - Session persistence and lifecycle
   - Stateful/stateless mode support

3. **FastAPI Router** (`router.py`)
   - JSON-RPC 2.0 protocol handler
   - Session management via headers
   - Error handling and logging

4. **Tool Modules** (`tools/`)
   - 21 tools across 5 categories
   - Redis-integrated state management
   - Full logging and tracing

## Tool Categories

### Echo Tools (2 tools)
- `echo` - Echo messages with session context
- `replayLastEcho` - Replay previous echo (stateful mode only)

### Debug Tools (4 tools)
- `printHeader` - Get HTTP header values
- `requestTiming` - Request performance metrics
- `corsAnalysis` - CORS configuration analysis
- `environmentDump` - Environment information

### Auth Tools (3 tools)
- `bearerDecode` - JWT token decoding (no verification)
- `authContext` - Current authentication state
- `whoIStheGOAT` - Easter egg tool

### System Tools (2 tools)
- `healthProbe` - Comprehensive health check
- `sessionInfo` - Session management information

### State Tools (10 tools)
- `stateInspector` - Inspect session state
- `sessionHistory` - Activity history
- `stateManipulator` - Direct state manipulation
- `sessionCompare` - Compare two sessions
- `sessionTransfer` - Transfer state between sessions
- `stateBenchmark` - Performance benchmarking
- `sessionLifecycle` - Session lifecycle management
- `stateValidator` - Validate state against schema
- `requestTracer` - Request flow tracing
- `modeDetector` - Server mode detection

## API Endpoints

### HTTP Endpoints

```
POST /api/v1/mcp/          - Main MCP JSON-RPC endpoint
GET  /api/v1/mcp/health    - Health check
GET  /api/v1/mcp/info      - Server information
```

### JSON-RPC Methods

```json
// Initialize
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "clientInfo": {
      "name": "client-name",
      "version": "1.0.0"
    }
  },
  "id": 1
}

// List tools
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}

// Call tool
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "echo",
    "arguments": {
      "message": "Hello MCP!"
    }
  },
  "id": 3
}
```

## Session Management

### Stateful Mode
- Full session persistence across requests
- Session data stored in Redis
- Configurable timeout (default: 1 hour)
- Session ID via `Mcp-Session-Id` header

### Stateless Mode
- No session persistence
- Request-scoped state only
- Suitable for horizontal scaling
- Lower memory footprint

### Session Headers
```
Mcp-Session-Id: uuid-v4-session-id
```

## Redis Key Schema

### Session Keys
```
mcp:session:{id}                 # Session metadata
mcp:session:{id}:{key}           # Session state values
mcp:request:{id}:{key}           # Request-scoped state
mcp:active_sessions              # Set of active session IDs
```

### Request Context
```
mcp:current_request:{id}:headers # Request headers
mcp:current_request:{id}:timing  # Timing information
mcp:current_request:{id}:auth    # Auth context
```

### Trace Keys
```
mcp:trace:{trace_id}             # Request trace data
```

## Configuration

### Environment Variables
```bash
MCP_MODE=auto|stateful|stateless  # Server mode
MCP_SESSION_TIMEOUT=3600          # Session timeout (seconds)
MCP_ENABLED=true                  # Enable MCP endpoint
MCP_REQUIRE_AUTH=false            # Require OAuth authentication
```

### Mode Detection
The server can automatically detect the appropriate mode:
- Kubernetes: Stateless mode
- AWS Lambda: Stateless mode
- Azure Functions: Stateless mode
- Standalone: Stateful mode (default)

## Usage Examples

### Initialize Session
```bash
curl -X POST http://localhost:9000/api/v1/mcp/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18"},
    "id": 1
  }'
```

### Call Echo Tool
```bash
SESSION_ID="your-session-id"
curl -X POST http://localhost:9000/api/v1/mcp/ \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "echo",
      "arguments": {"message": "Hello World"}
    },
    "id": 2
  }'
```

### Check Health
```bash
curl http://localhost:9000/api/v1/mcp/health
```

## Testing

### Run Tests
```bash
# Run MCP tests
pixi run pytest tests/test_mcp.py -v

# Test specific functionality
pixi run pytest tests/test_mcp.py::TestMCPEndpoint::test_mcp_initialize -v
```

### Manual Testing
```python
import httpx
import json

# Initialize session
async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:9000/api/v1/mcp/",
        json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1
        }
    )
    session_id = response.headers["Mcp-Session-Id"]
    print(f"Session: {session_id}")
```

## Integration with OAuth

The MCP endpoint can optionally require OAuth authentication:

1. Set `MCP_REQUIRE_AUTH=true` in environment
2. Include Bearer token in requests
3. Auth context available to tools via `authContext` tool

## Performance Considerations

### Stateful Mode
- Session data persisted in Redis
- Higher memory usage
- Suitable for development/debugging
- Session cleanup task runs periodically

### Stateless Mode
- No session overhead
- Request-scoped state only
- Suitable for production
- Horizontal scaling ready

### Benchmarking
Use the `stateBenchmark` tool to test performance:
```json
{
  "method": "tools/call",
  "params": {
    "name": "stateBenchmark",
    "arguments": {
      "operations": 1000,
      "data_size": "medium"
    }
  }
}
```

## Error Handling

### JSON-RPC Error Codes
- `-32700`: Parse error
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error

### Error Response Format
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found",
    "data": "Additional error information"
  },
  "id": 1
}
```

## Logging

All MCP operations are logged via UnifiedAsyncLogger:

### Event Types
- `mcp_request` - Incoming request
- `mcp_response` - Successful response
- `mcp_error` - Error occurred
- `mcp_echo` - Echo tool called
- `mcp_auth_decode` - JWT decoded
- `mcp_health_check` - Health check performed
- `mcp_state_*` - State operations

### Log Correlation
Traces include session ID for correlation across requests.

## Security Considerations

1. **JWT Decoding**: `bearerDecode` tool does NOT verify signatures
2. **Environment Variables**: Sensitive values are redacted
3. **State Access**: Tools can access all session state
4. **Auth Integration**: Optional OAuth protection available

## Future Enhancements

1. **WebSocket Transport**: Real-time bidirectional communication
2. **Tool Permissions**: Per-tool access control
3. **Metrics Dashboard**: Prometheus/Grafana integration
4. **Session Replication**: Multi-instance session sharing
5. **Custom Tools**: Plugin system for additional tools

## Troubleshooting

### Session Not Persisting
- Check mode with `modeDetector` tool
- Verify Redis connectivity
- Check session timeout settings

### Tools Not Available
- Verify MCP module is imported
- Check unified_logger initialization
- Review logs for registration errors

### High Memory Usage
- Monitor session count
- Reduce session timeout
- Switch to stateless mode
- Use session cleanup

## Related Documentation

- [API Documentation](../api/CLAUDE.md)
- [Storage Schema](../storage/CLAUDE.md)
- [Logging System](../logging/CLAUDE.md)
- [Main Documentation](../../CLAUDE.md)