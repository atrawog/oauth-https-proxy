# MCP Compliance Testing Documentation

## Overview

This directory contains comprehensive testing tools for verifying MCP (Model Context Protocol) server compliance with the official specifications:
- [Session Management](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management)
- [Server Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [Protocol Transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http)

## Test Tools

### test_mcp_compliance.py
Comprehensive compliance testing suite that verifies all MCP specification requirements.

**Features:**
- 16+ compliance tests across 5 categories
- Detailed pass/fail reporting with spec references
- Performance metrics and warnings
- Category-based testing for focused validation

**Usage:**
```bash
# Run full compliance test
pixi run python scripts/test_mcp_compliance.py --url https://auth.example.com/mcp

# Run specific category
pixi run python scripts/test_mcp_compliance.py --url https://localhost/mcp --category session_basic

# Verbose output
pixi run python scripts/test_mcp_compliance.py --url https://localhost/mcp --verbose

# Using just commands (recommended)
just mcp-test                                    # Test localhost
just mcp-test https://auth.example.com/mcp      # Test specific URL
just mcp-test-verbose                           # Verbose mode
```

**Test Categories:**
- `session_basic` - Session ID format and cryptographic security
- `session_advanced` - State persistence, timeout, header handling
- `tools_basic` - Tool naming, descriptions, schema validation
- `tools_advanced` - Error handling, parameter validation, concurrency
- `protocol` - Version negotiation, capabilities, JSON-RPC compliance
- `all` - Run all tests (default)

### test_mcp_stress.py
Stress testing and performance measurement for MCP servers.

**Features:**
- Concurrent session management testing
- Tool performance benchmarking
- Session isolation verification
- Error recovery testing
- Detailed performance metrics

**Usage:**
```bash
# Run stress test with 50 concurrent sessions
pixi run python scripts/test_mcp_stress.py --url https://auth.example.com/mcp --mode stress --sessions 50

# Run all test modes
pixi run python scripts/test_mcp_stress.py --url https://localhost/mcp --mode all

# Using just command (recommended)
just mcp-stress                                  # 50 sessions on localhost
just mcp-stress https://auth.example.com/mcp 100  # 100 sessions on specific URL
```

**Test Modes:**
- `quick` - Basic functionality tests
- `sessions` - Session management tests
- `tools` - Tool performance tests
- `stress` - High-load concurrent testing
- `all` - Run all test modes

## Compliance Requirements

### Session Management (MUST requirements)
1. **Session ID Format**
   - MUST contain only visible ASCII characters (0x21-0x7E)
   - MUST be cryptographically secure and unpredictable
   - MUST have sufficient entropy (32+ bytes recommended)

2. **Session State**
   - MUST maintain state across requests
   - MUST handle concurrent requests within same session
   - MAY implement session timeouts

3. **Session Headers**
   - MUST support `Mcp-Session-Id` header
   - SHOULD follow HTTP case-insensitive header rules

### Tool Requirements (MUST requirements)
1. **Tool Definition**
   - MUST have unique names
   - MUST have descriptions
   - MUST follow JSON Schema for parameters

2. **Tool Execution**
   - MUST return proper errors for invalid tools
   - MUST validate parameters against schema
   - MUST support concurrent execution

### Protocol Requirements
1. **Version Negotiation**
   - MUST negotiate protocol version correctly
   - MUST support at least one valid version
   - SHOULD handle future/unknown versions gracefully

2. **Capabilities**
   - MUST define capabilities object
   - MUST include tools, prompts, resources capabilities
   - SHOULD declare listChanged support

3. **JSON-RPC**
   - MUST comply with JSON-RPC 2.0
   - MUST correlate request/response IDs
   - MUST support notifications (no ID)

## Expected Results

### Fully Compliant Server
```
======================================================================
📊 MCP COMPLIANCE TEST REPORT
======================================================================
Total Tests: 16
Passed: 16
Failed: 0
Pass Rate: 100.0%

🎉 FULLY COMPLIANT - ALL TESTS PASSED!
======================================================================
```

### Common Issues and Fixes

1. **Session ID Cryptographic Security Failed**
   - Issue: Low character variety or insufficient entropy
   - Fix: Use base64 encoding of 32+ random bytes
   - Example: `base64.b64encode(secrets.token_bytes(32))`

2. **Protocol Version Negotiation Failed**
   - Issue: Accepting invalid versions without negotiation
   - Fix: Validate and negotiate to supported version
   - Supported: 2024-11-05, 2025-03-26, 2025-06-18

3. **Tool Schema Validation Failed**
   - Issue: Missing or invalid JSON Schema
   - Fix: Ensure all tools have valid `inputSchema` if parameters exist

4. **Session State Persistence Failed**
   - Issue: State not maintained across requests
   - Fix: Store session data in Redis or persistent storage

## Integration with CI/CD

Add to your CI/CD pipeline:

```yaml
# GitHub Actions example
- name: Run MCP Compliance Tests
  run: |
    pixi run python scripts/test_mcp_compliance.py \
      --url https://staging.example.com/mcp \
      --category all
```

```bash
# Jenkins/Shell example
#!/bin/bash
set -e

# Run compliance tests
just mcp-test https://staging.example.com/mcp

# Check exit code
if [ $? -ne 0 ]; then
    echo "MCP compliance tests failed"
    exit 1
fi
```

## Performance Benchmarks

Expected performance for compliant servers:

- Session creation: < 100ms
- Tool discovery: < 50ms (P95)
- Tool execution: < 200ms (simple tools)
- Concurrent sessions: 50+ without errors
- Session isolation: 100% (no cross-contamination)

## Troubleshooting

### Connection Issues
```bash
# Test basic connectivity
curl -X POST https://your-server/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"initialize","params":{"protocolVersion":"2025-06-18"},"jsonrpc":"2.0","id":0}'
```

### Debug Logging
Enable verbose mode to see detailed request/response:
```bash
just mcp-test-verbose https://your-server/mcp
```

### Common Errors

1. **404 on /mcp endpoint**
   - Ensure MCP server is running
   - Check URL includes /mcp path
   - Verify proxy routing configuration

2. **SSL Certificate Errors**
   - Use `--verify=false` for self-signed certificates
   - Ensure certificates are valid for the domain

3. **Timeout Errors**
   - Check network connectivity
   - Verify server performance under load
   - Increase timeout in test scripts if needed

## Contributing

When adding new compliance tests:

1. Add test method to appropriate category
2. Include spec reference in docstring
3. Return `ComplianceTestResult` with proper details
4. Update test count in documentation

Example:
```python
async def test_new_requirement(self) -> ComplianceTestResult:
    """Test description per specification."""
    # Test implementation
    return ComplianceTestResult(
        "Test Name",
        TestCategory.SESSION_BASIC,
        passed=True,
        message="Success message",
        spec_reference="Specification section reference"
    )
```

## Resources

- [MCP Specification](https://modelcontextprotocol.io/specification)
- [Session Management](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management)
- [Server Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http)