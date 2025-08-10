# MCP HTTP Echo Server - Claude Code Documentation

## Overview

This is a **dual-mode MCP echo server** built with **FastMCP 2.0** that provides 21 comprehensive debugging tools. It can run in either stateful mode (with session management) or stateless mode (for horizontal scaling).

## Key Architecture Decisions

### Why FastMCP 2.0?
- Modern Python framework specifically designed for MCP
- Built-in support for multiple transports (HTTP, SSE, STDIO)
- Native context management for state handling
- Simplified tool registration with decorators
- Automatic protocol compliance

### Dual-Mode Design
The server intelligently adapts between two modes:

**Stateful Mode**:
- Full session persistence across requests
- Message queuing for async clients
- Session history and replay capabilities
- Used for: Development, debugging, interactive sessions

**Stateless Mode**:
- No session persistence, request-scoped only
- Horizontally scalable
- Lower memory footprint
- Used for: Production, serverless, high-traffic APIs

### State Management Pattern
```python
# Unified state access through StateAdapter
await StateAdapter.set_state(ctx, "key", value)
value = await StateAdapter.get_state(ctx, "key", default)

# Automatically scopes to:
# - request_* prefix in stateless mode
# - session_{id}_* prefix in stateful mode
```

## Tools Implementation

### Tool Categories

1. **Echo Tools** (2) - Basic echo functionality with state awareness
2. **Debug Tools** (4) - Request introspection and timing
3. **Auth Tools** (3) - JWT decoding and authentication context
4. **System Tools** (2) - Health checks and session info
5. **State Tools** (10) - Advanced state tracking and manipulation

### Tool Registration Pattern
```python
@mcp.tool
async def toolName(ctx: Context, param: type) -> ReturnType:
    """Tool description for MCP discovery."""
    # Tool implementation
```

## Session Management

### SessionManager Class
- Manages session lifecycle in stateful mode
- Background cleanup task for expired sessions
- Message queuing per session
- Thread-safe with asyncio locks

### Session Flow
1. Client sends initialize → Create session
2. Session ID returned in Mcp-Session-Id header
3. Client includes session ID in subsequent requests
4. Session expires after timeout (default 3600s)

## Mode Detection

The server automatically detects the best mode:

```python
def detect_mode():
    if any([
        os.getenv("KUBERNETES_SERVICE_HOST"),  # K8s
        os.getenv("LAMBDA_RUNTIME_DIR"),       # Lambda
        os.getenv("FUNCTIONS_WORKER_RUNTIME"), # Azure
    ]):
        return "stateless"
    return "stateful"  # Default for development
```

## Testing Strategy

### Unit Tests
- Test each tool in isolation
- Mock Context for state operations
- Verify mode-specific behavior

### Integration Tests
```bash
# Test stateful mode
pytest tests/test_stateful.py

# Test stateless mode
pytest tests/test_stateless.py

# Test mode switching
pytest tests/test_dual_mode.py
```

### Performance Testing
Use the built-in `stateBenchmark` tool:
```python
# Benchmark state operations
result = await stateBenchmark(ctx, operations=1000, data_size="medium")
```

## Development Workflow

### Local Development
```bash
# Install in development mode
pip install -e .

# Run with debug logging
mcp-http-echo-server --debug --mode stateful

# Test with curl
curl -X POST localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### Adding New Tools
1. Create tool function in appropriate module
2. Add @mcp.tool decorator
3. Register in corresponding register_*_tools function
4. Handle both stateful and stateless modes

Example:
```python
@mcp.tool
async def newTool(ctx: Context, param: str) -> str:
    """Tool description."""
    if ctx.get_state("stateless_mode"):
        # Stateless behavior
        return f"Stateless: {param}"
    else:
        # Stateful behavior
        session_id = ctx.get_state("session_id")
        return f"Stateful [{session_id[:8]}]: {param}"
```

## Environment Configuration

### Required for Production
```env
MCP_MODE=stateless
MCP_ECHO_HOST=0.0.0.0
MCP_ECHO_PORT=8080
MCP_ECHO_DEBUG=false
```

### Development Settings
```env
MCP_MODE=stateful
MCP_ECHO_DEBUG=true
MCP_SESSION_TIMEOUT=7200
MCP_LOG_FILE=./logs/mcp-echo.log
```

## Deployment Considerations

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: mcp-echo
        image: mcp-echo-server:latest
        env:
        - name: MCP_MODE
          value: "stateless"
```

### AWS Lambda
```python
# handler.py
from mcp_http_echo_server import create_server

server = create_server(stateless_mode=True)
handler = server.mcp.aws_lambda_handler()
```

### Docker Compose
```yaml
services:
  mcp-echo:
    build: .
    ports:
      - "3000:3000"
    environment:
      MCP_MODE: ${MCP_MODE:-auto}
      MCP_ECHO_DEBUG: ${DEBUG:-false}
```

## Performance Optimization

### Stateless Mode
- No session overhead
- Minimal memory usage
- Suitable for horizontal scaling
- Use behind load balancer

### Stateful Mode
- Enable session cleanup task
- Monitor session count
- Set appropriate timeout
- Use Redis for distributed sessions (future enhancement)

## Security Considerations

1. **JWT Decoding**: No signature verification (debugging tool only)
2. **State Manipulation**: Admin tools should be restricted in production
3. **Session Timeout**: Configure based on security requirements
4. **Headers**: Sensitive headers are redacted in logs

## Troubleshooting

### Common Issues

**Session not persisting**:
- Check mode with `modeDetector` tool
- Verify Mcp-Session-Id header is being sent
- Check session timeout settings

**High memory usage**:
- Monitor session count with `sessionInfo`
- Reduce session timeout
- Switch to stateless mode

**Tool not available**:
- Some tools are stateful-only (e.g., replayLastEcho)
- Check mode with `modeDetector`
- Use `--list-tools` to see available tools

## Future Enhancements

1. **Redis Session Storage**: For distributed stateful deployments
2. **Metrics Export**: Prometheus/OpenTelemetry integration
3. **WebSocket Transport**: Real-time bidirectional communication
4. **Custom Tool Plugins**: Dynamic tool loading
5. **Session Persistence**: Save/restore sessions to disk

## Contributing

When contributing:
1. Maintain dual-mode compatibility
2. Add tests for both modes
3. Update tool count in documentation
4. Follow existing patterns for state management
5. Use type hints and docstrings