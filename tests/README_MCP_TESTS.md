# MCP Testing Guide

## Overview

This directory contains comprehensive tests for the MCP (Model Context Protocol) server implementation in oauth-https-proxy.

## Test Files

- `test_mcp.py` - Basic MCP endpoint tests (protocol compliance)
- `test_mcp_tools.py` - Comprehensive test of all 21 MCP tools

## Running Tests

### Prerequisites

1. Ensure the server is running:
```bash
just up        # Start with Docker
# OR
just dev       # Run locally
```

2. Verify Redis is available:
```bash
just redis-cli ping
```

### Test Commands

```bash
# Run all tests (includes MCP tests)
just test

# Run only MCP tests
just test-mcp

# Quick MCP protocol test
just test-mcp-quick

# Check if MCP server is working
just test-mcp-server

# Run specific test file
just test test_mcp_tools.py

# Run with verbose output
pixi run pytest tests/test_mcp_tools.py -v -s
```

## MCP Client Test Structure

The `test_mcp_tools.py` file includes:

### MCPClient Class
A complete MCP client implementation that:
- Manages JSON-RPC communication
- Handles session management
- Provides tool calling interface

### Test Categories

1. **TestMCPTools** - Tests all 21 individual tools:
   - Echo tools (2)
   - Debug tools (4)
   - Auth tools (3)
   - System tools (2)
   - State tools (10)

2. **TestMCPIntegration** - Integration tests:
   - Full workflow tests
   - Error handling
   - Concurrent sessions

3. **Performance Tests** (marked as @pytest.mark.slow):
   - High-volume request testing
   - Concurrency testing

## Tool Test Coverage

All 21 tools are tested:

### Echo Tools
- `echo` - Message echoing
- `replayLastEcho` - Echo replay (stateful mode)

### Debug Tools
- `printHeader` - HTTP header inspection
- `requestTiming` - Performance metrics
- `corsAnalysis` - CORS configuration
- `environmentDump` - Environment variables

### Auth Tools
- `bearerDecode` - JWT decoding
- `authContext` - Authentication state
- `whoIStheGOAT` - Easter egg

### System Tools
- `healthProbe` - Health checking
- `sessionInfo` - Session details

### State Tools
- `stateInspector` - State examination
- `sessionHistory` - Activity history
- `stateManipulator` - State CRUD operations
- `sessionCompare` - Session comparison
- `sessionTransfer` - State migration
- `stateBenchmark` - Performance testing
- `sessionLifecycle` - Lifecycle management
- `stateValidator` - Schema validation
- `requestTracer` - Request tracing
- `modeDetector` - Mode detection

## Debugging Failed Tests

If tests fail:

1. Check server is running:
```bash
just test-mcp-server
```

2. Check logs:
```bash
just logs-follow
```

3. Verify Redis connectivity:
```bash
just redis-cli
> ping
> keys mcp:*
```

4. Run individual test with debugging:
```bash
pixi run pytest tests/test_mcp_tools.py::TestMCPTools::test_echo_tool -v -s --log-cli-level=DEBUG
```

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Start services
  run: just up-detached

- name: Wait for services
  run: sleep 10

- name: Run MCP tests
  run: just test-mcp
```

## Performance Expectations

- Server should handle 10+ requests/second minimum
- All tools should respond within 1 second
- Session operations should be sub-100ms

## Troubleshooting

### Common Issues

1. **Connection refused**: Server not running
   - Solution: `just up` or `just dev`

2. **Session not found**: Stateless mode active
   - Check with `modeDetector` tool

3. **Redis errors**: Redis not available
   - Solution: Check Redis with `just redis-cli`

4. **Import errors**: Dependencies not installed
   - Solution: `pixi install`