# MCP Verification Tools

Comprehensive compliance testing and validation suite for MCP (Model Context Protocol) endpoints. Test your MCP implementation against the official specification with detailed, actionable reports.

## Features

✅ **Complete Specification Coverage** - Tests for all MCP requirements  
✅ **Modular Test Architecture** - Easy to add custom tests  
✅ **Auto-Generated Schema Validation** - Pydantic models from official JSON schema  
✅ **Comprehensive YAML Reports** - Verbose explanations with remediation guidance  
✅ **Multiple Test Categories** - Session, transport, protocol, tools, security, performance  
✅ **Parallel Test Execution** - Fast testing with dependency management  
✅ **Stress Testing** - Performance and concurrency validation  
✅ **Beautiful CLI** - Rich terminal output with progress indicators  

## Quick Start

### Installation

```bash
# Install with pip
pip install -e ./mcp_verification_tools

# Or using the justfile
just mcp-install
```

### Basic Usage

```bash
# Validate a single endpoint
just mcp-verify https://example.com/mcp

# Validate both test endpoints
just mcp-test-both

# Run specific category of tests
just mcp-test-category https://example.com/mcp session

# List all available tests
just mcp-list-tests
```

### Generate Schema Models

Before running tests, generate Pydantic models from the official MCP schema:

```bash
just mcp-generate-schema
```

## Test Categories

### Session Management (`session_management`)
- Session ID character set validation
- Cryptographic security and entropy
- Session persistence across requests
- Session timeout behavior
- Case sensitivity handling

### Transport Compliance (`transport_compliance`)
- HTTP method support (POST/GET)
- SSE (Server-Sent Events) support
- Content negotiation
- Status code validation
- Header handling
- Connection resumability

### Protocol Compliance (`protocol_compliance`)
- JSON-RPC 2.0 format validation
- Protocol version negotiation
- Initialize/shutdown lifecycle
- Error response format
- Batch request handling

### Tools Validation (`tools_validation`)
- Tool discovery (tools/list)
- Input schema validation
- Parameter validation
- Error handling
- Response format

### Security Compliance (`security_compliance`)
- Origin header validation
- DNS rebinding prevention
- Input sanitization
- Session hijacking prevention
- Rate limiting

### Performance Metrics (`performance_metrics`)
- Concurrent session handling
- Message throughput
- Large payload handling
- Connection limits
- Resource usage

## Adding Custom Tests

The modular architecture makes it trivial to add new tests:

```python
# my_custom_test.py
from mcp_verification_tools.core.registry import mcp_test, TestCategory, TestSeverity
from mcp_verification_tools.core.base_test import MCPTestBase
from mcp_verification_tools.models.test_results import TestResult, TestStatus

@mcp_test(
    test_id="CUSTOM-001",
    name="My Custom Test",
    category=TestCategory.CUSTOM,
    severity=TestSeverity.HIGH,
    description="Tests custom functionality",
    spec_url="https://modelcontextprotocol.io/...",
    tags=["custom", "example"]
)
async def test_custom_functionality(client: MCPTestBase) -> TestResult:
    result = client.create_test_result("CUSTOM-001")
    
    # Your test logic here
    response = await client.send_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "your_method"
    })
    
    if response.get("result"):
        result.status = TestStatus.PASSED
        result.actual_behavior = "Custom test passed"
    else:
        result.status = TestStatus.FAILED
        result.failure_reason = "Custom test failed"
    
    return result
```

Add your test to the suite:

```bash
just mcp-add-test my_custom_test.py
```

## YAML Report Format

Reports include comprehensive information for each test:

```yaml
metadata:
  report_version: "1.0.0"
  mcp_specification_version: "2025-06-18"
  endpoint_tested: "https://example.com/mcp"
  compliance_score: 85.5

test_results:
  session_management:
    - test_id: "SM-001"
      test_name: "Session ID Character Set Validation"
      status: "FAILED"
      severity: "CRITICAL"
      
      description: |
        Validates that session IDs contain only visible ASCII characters
        
      failure_reason: |
        Session ID contains non-visible ASCII characters...
        
      impact_assessment:
        compatibility: "HIGH"
        security: "MEDIUM"
        functionality: "HIGH"
        
      remediation:
        priority: "IMMEDIATE"
        steps:
          - "Review session ID generation algorithm"
          - "Use only [A-Za-z0-9-_] characters"
        code_example: |
          import secrets
          def generate_session_id():
              return secrets.token_urlsafe(32)

recommendations:
  critical_fixes:
    - "Fix session ID character validation"
    - "Implement Origin header validation"
```

## Commands Reference

### Testing Commands

```bash
# Basic validation
just mcp-verify <endpoint>

# Verbose validation (includes passing tests)
just mcp-verify-verbose <endpoint>

# Test both reference endpoints
just mcp-test-both

# Category-specific tests
just mcp-test-category <endpoint> <category>
just mcp-security <endpoint>
just mcp-performance <endpoint>

# Tag-based testing
just mcp-test-tags <endpoint> <tags>

# Quick compliance check
just mcp-check <endpoint>

# Stress testing
just mcp-stress <endpoint> [sessions] [duration]
```

### Management Commands

```bash
# List available tests
just mcp-list-tests
just mcp-list-category <category>

# Schema generation
just mcp-generate-schema

# Add custom test
just mcp-add-test <file>

# Report management
just mcp-setup               # Create reports directory
just mcp-view-latest         # View latest report
just mcp-clean-reports       # Clean old reports
```

## CLI Direct Usage

You can also use the CLI directly:

```bash
# Validate endpoint
python -m mcp_verification_tools.cli validate https://example.com/mcp

# With options
python -m mcp_verification_tools.cli validate \
    https://example.com/mcp \
    --category session \
    --verbose \
    --output report.yaml \
    --fail-fast

# List tests
python -m mcp_verification_tools.cli list-tests --format table

# Stress test
python -m mcp_verification_tools.cli stress \
    https://example.com/mcp \
    --sessions 100 \
    --duration 60
```

## Report Interpretation

### Compliance Scores

- **95-100%**: Fully compliant ✅
- **80-94%**: Mostly compliant 👍
- **60-79%**: Partially compliant ⚠️
- **40-59%**: Limited compliance ⚠️
- **0-39%**: Non-compliant ❌

### Severity Levels

- **CRITICAL**: Must fix for compliance
- **HIGH**: Should fix soon  
- **MEDIUM**: Should fix
- **LOW**: Nice to have
- **INFO**: Informational only

### Test Status

- **PASSED** ✅: Test successful
- **FAILED** ❌: Test failed, see remediation
- **WARNING** ⚠️: Test passed with concerns
- **SKIPPED** ⏭️: Test not run
- **ERROR** 💥: Test execution error

## Development

### Project Structure

```
mcp_verification_tools/
├── core/                 # Core framework
│   ├── registry.py      # Test registration
│   ├── base_test.py     # Base test class
│   └── runner.py        # Test orchestration
├── models/              # Data models
│   ├── test_results.py  # Result models
│   └── generated/       # Auto-generated from schema
├── tests/               # Test implementations
│   ├── session/         # Session tests
│   ├── transport/       # Transport tests
│   └── ...              # Other categories
├── reporters/           # Report generators
│   └── yaml_reporter.py # YAML reports
├── schemas/             # Schema files
│   └── generate.py      # Model generation
└── cli.py               # CLI interface
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add your test using the `@mcp_test` decorator
4. Ensure tests are discoverable
5. Submit a pull request

### Testing the Test Suite

```bash
# Run unit tests
pytest tests/

# With coverage
pytest --cov=mcp_verification_tools tests/
```

## Troubleshooting

### Common Issues

**Import errors when running tests**
- Ensure package is installed: `just mcp-install`
- Check Python path includes current directory

**Schema generation fails**
- Install datamodel-code-generator: `pip install datamodel-code-generator[http]`
- Ensure internet connection for schema download

**No tests discovered**
- Check test modules are in `tests/` directory
- Ensure test functions use `@mcp_test` decorator
- Verify __init__.py imports test modules

**Reports directory not found**
- Create it: `just mcp-setup`

## License

MIT License - See LICENSE file for details

## Links

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-06-18/)
- [JSON Schema](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema)
- [Issue Tracker](https://github.com/your-org/mcp-verification-tools/issues)

## Acknowledgments

Built to validate compliance with the Model Context Protocol specification by Anthropic.