# MCP HTTP Echo Server

A dual-mode (stateful/stateless) MCP echo server with 21 comprehensive debugging tools, built on FastMCP 2.0.

## Features

- **Dual-Mode Operation**: Run in stateful mode for development/debugging or stateless mode for production scalability
- **21 Debugging Tools**: Comprehensive suite for debugging MCP, authentication, and state management
- **FastMCP 2.0**: Built on the modern FastMCP framework for optimal performance
- **Auto-Detection**: Automatically detects the best mode based on your environment
- **Session Management**: Full session support in stateful mode with message queuing
- **Protocol Compliance**: Supports MCP protocols 2025-06-18, 2025-03-26, and 2024-11-05

## Installation

```bash
# Install with pip
pip install mcp-http-echo-server

# Or install from source
git clone https://github.com/atrawog/mcp-http-proxy.git
cd mcp-http-proxy/mcp-http-echo-server
pip install -e .
```

## Quick Start

```bash
# Run with auto-detected mode
mcp-http-echo-server

# Run in stateless mode for production
mcp-http-echo-server --mode stateless --port 8080

# Run in stateful mode with debug logging
mcp-http-echo-server --mode stateful --debug

# List all available tools
mcp-http-echo-server --list-tools
```

## Available Tools

### Echo Tools (2)
- `echo` - Echo back messages with context information
- `replayLastEcho` - Replay the last echoed message (stateful mode only)

### Debug Tools (4)
- `printHeader` - Display all HTTP headers from the request
- `requestTiming` - Show request timing and performance metrics
- `corsAnalysis` - Analyze CORS configuration
- `environmentDump` - Display environment configuration

### Auth Tools (3)
- `bearerDecode` - Decode JWT Bearer tokens (no signature verification)
- `authContext` - Display complete authentication context
- `whoIStheGOAT` - AI-powered programming excellence analyzer

### System Tools (2)
- `healthProbe` - Perform deep health check of service
- `sessionInfo` - Display session information and statistics

### State Tools (10)
- `stateInspector` - Deep inspection of state storage
- `sessionHistory` - Show session event history
- `stateManipulator` - Manipulate state for debugging
- `sessionCompare` - Compare multiple sessions
- `sessionTransfer` - Export/import/clone sessions
- `stateBenchmark` - Benchmark state operations
- `sessionLifecycle` - Display session lifecycle information
- `stateValidator` - Validate state consistency
- `requestTracer` - Trace request flow and context
- `modeDetector` - Detect and explain operational mode

## Modes

### Stateful Mode
- Full session management with persistence
- Message queuing for async clients
- Session history and replay capabilities
- Best for: Development, debugging, interactive sessions
- Limitations: Single instance, higher memory usage

### Stateless Mode
- No session persistence
- Request-scoped state only
- Horizontally scalable
- Best for: Production, serverless, high-traffic APIs
- Limitations: No replay, no session history

### Auto Mode
Automatically detects the best mode based on environment:
- Kubernetes → Stateless
- AWS Lambda → Stateless
- Docker/Local → Stateful

## Configuration

### Environment Variables
```bash
MCP_ECHO_HOST=0.0.0.0              # Host to bind to
MCP_ECHO_PORT=3000                 # Port to bind to
MCP_ECHO_DEBUG=true                # Enable debug logging
MCP_MODE=auto                      # Server mode (auto/stateful/stateless)
MCP_SESSION_TIMEOUT=3600           # Session timeout in seconds
MCP_PROTOCOL_VERSIONS=2025-06-18   # Supported protocol versions
MCP_STATELESS=false                # Force stateless mode
```

### Command Line Options
```bash
Options:
  --host HOST                 Host to bind to (default: 0.0.0.0)
  --port PORT                 Port to bind to (default: 3000)
  --mode {auto,stateful,stateless}  Server mode (default: auto)
  --stateless                 Run in stateless mode
  --stateful                  Run in stateful mode
  --protocol-versions VERSIONS  Comma-separated protocol versions
  --session-timeout SECONDS  Session timeout for stateful mode
  --transport {http,stdio,sse}  Transport type (default: http)
  --debug                     Enable debug mode
  --log-file PATH            Log file path
  --list-tools               List all available tools
  --version                  Show version
```

## Docker Usage

```dockerfile
FROM python:3.11-slim

RUN pip install mcp-http-echo-server

EXPOSE 3000

CMD ["mcp-http-echo-server", "--host", "0.0.0.0", "--mode", "stateless"]
```

```bash
# Build and run
docker build -t mcp-echo-server .
docker run -p 3000:3000 mcp-echo-server
```

## Examples

### Testing with curl
```bash
# Initialize session
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18"},"id":1}'

# Call echo tool
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"message":"Hello!"}},"id":2}'
```

### MCP Client Configuration
```json
{
  "mcpServers": {
    "echo-server": {
      "url": "http://localhost:3000/mcp",
      "transport": "http",
      "stateless": false
    }
  }
}
```

## Performance

### Stateless Mode
- Requests per second: 10,000+
- Memory usage: ~50MB
- Startup time: <1s
- Horizontal scaling: Yes

### Stateful Mode
- Requests per second: 5,000+
- Memory usage: ~100MB + session storage
- Startup time: <1s
- Session capacity: 10,000+ concurrent

## Architecture

```
FastMCP Framework
    ├── Server Core
    │   ├── Dual-mode support
    │   ├── Session management
    │   └── State adapter
    ├── Tools (21)
    │   ├── Echo tools (2)
    │   ├── Debug tools (4)
    │   ├── Auth tools (3)
    │   ├── System tools (2)
    │   └── State tools (10)
    └── Transports
        ├── HTTP (with SSE)
        ├── STDIO
        └── SSE (legacy)
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

Apache-2.0

## Author

Andreas Trawoeger (atrawog@gmail.com)