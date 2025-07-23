# MCP HTTP Validator

HTTP-based validator for Model Context Protocol (MCP) servers with OAuth 2.0 authorization testing.

## Overview

MCP HTTP Validator is a comprehensive testing tool for validating MCP server implementations against the [MCP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization). It focuses on:

- OAuth 2.0 authorization compliance (RFC 6749, RFC 8707, RFC 9728)
- MCP-specific endpoint validation
- Token audience validation
- Server-Sent Events (SSE) support
- Protected resource metadata compliance

## Features

- **Automatic OAuth Discovery**: Discovers OAuth servers from MCP metadata
- **Zero Configuration**: Automatically registers and saves OAuth clients
- **Full MCP Compliance Testing**: Validates servers against MCP 2025-06-18 specification
- **OAuth Flow Testing**: Complete OAuth 2.0 authorization flow validation
- **Dynamic Client Registration**: Supports RFC 7591 for automatic client setup
- **Client Management**: RFC 7592 support for updating/deleting clients
- **Resource Indicators**: Validates RFC 8707 resource-restricted tokens
- **Multiple Output Formats**: Terminal, JSON, and Markdown reports
- **Credential Management**: Secure .env file storage for OAuth credentials
- **No stdio Dependencies**: Pure HTTP-based testing

## Installation

```bash
pip install mcp-http-validator
```

Or install from source:

```bash
git clone https://github.com/example/mcp-http-validator
cd mcp-http-validator
pip install -e .
```

## Quick Start

### Command Line Usage

1. **Validate an MCP Server** (automatic OAuth discovery):
```bash
# Automatically discovers OAuth server and registers client if needed
mcp-validate https://mcp.example.com

# Use existing access token
mcp-validate https://mcp.example.com --token $ACCESS_TOKEN

# Force new client registration
mcp-validate https://mcp.example.com --force-register
```

2. **Test OAuth Flow**:
```bash
# Automatically discovers OAuth server from MCP metadata
mcp-validate flow https://mcp.example.com
```

3. **Manage OAuth Clients** (RFC 7592):
```bash
# List saved credentials
mcp-validate client list

# Update client configuration
mcp-validate client update https://mcp.example.com --client-name "New Name"

# Delete client registration
mcp-validate client delete https://mcp.example.com
```

### Programmatic Usage

```python
import asyncio
from mcp_http_validator import MCPValidator, ComplianceChecker

async def validate_server():
    async with MCPValidator(
        server_url="https://mcp.example.com",
        auto_register=True  # Automatically discover OAuth and register client
    ) as validator:
        # OAuth client is automatically set up if needed
        await validator.setup_oauth_client()
        
        result = await validator.validate()
        
    checker = ComplianceChecker(result, validator.server_info)
    report = checker.check_compliance()
    
    print(f"Compliance Level: {report.compliance_level}")
    print(f"Success Rate: {result.success_rate:.1f}%")

asyncio.run(validate_server())
```

## Configuration

The validator automatically manages OAuth credentials in a `.env` file:

```env
# Manual access token (optional - for pre-authenticated testing)
MCP_ACCESS_TOKEN=your-access-token

# OAuth credentials are automatically saved per server:
OAUTH_CLIENT_ID_MCP_EXAMPLE_COM=mcp_client_123456
OAUTH_CLIENT_SECRET_MCP_EXAMPLE_COM=secret_abcdef...
OAUTH_REGISTRATION_TOKEN_MCP_EXAMPLE_COM=reg_token_xyz...

# Default credentials (fallback if server-specific not found):
OAUTH_CLIENT_ID=default-client-id
OAUTH_CLIENT_SECRET=default-client-secret
```

The validator will:
1. Discover OAuth servers from MCP server metadata
2. Register OAuth clients automatically (if enabled)
3. Save credentials to `.env` for future use
4. Support RFC 7592 for client management

## Validation Tests

The validator performs the following tests:

### Critical Tests (Required)
- **Protected Resource Metadata**: `/.well-known/oauth-protected-resource` endpoint
- **Authentication Challenge**: Proper 401 responses with WWW-Authenticate header
- **Authenticated Access**: Valid bearer token acceptance

### Important Tests
- **Token Audience Validation**: Validates token `aud` claim contains server URL
- **SSE Support**: Server-Sent Events for MCP protocol

### OAuth Server Tests
- Authorization server metadata discovery
- Resource indicators support (RFC 8707)
- Required endpoints availability
- MCP scope support (`mcp:read`, `mcp:write`)

## Output Formats

### Terminal Output
Rich, colored output with tables and progress indicators:
```
┌─────────────────────────────────────┐
│ MCP Compliance Report               │
│ Server: https://mcp.example.com     │
│ Compliance Level: FULLY_COMPLIANT   │
└─────────────────────────────────────┘
```

### JSON Output
Complete structured data for programmatic processing:
```bash
mcp-validate https://mcp.example.com -o json -f report.json
```

### Markdown Output
Human-readable reports for documentation:
```bash
mcp-validate https://mcp.example.com -o markdown -f report.md
```

## Compliance Levels

- **FULLY_COMPLIANT**: All tests pass (100%)
- **MOSTLY_COMPLIANT**: 90%+ tests pass
- **PARTIALLY_COMPLIANT**: 70%+ tests pass or critical test failed
- **MINIMALLY_COMPLIANT**: Some tests pass but major issues
- **NON_COMPLIANT**: Critical required tests failed

## Advanced Usage

### Custom Validation Tests

```python
from mcp_http_validator import MCPValidator, TestCase, TestSeverity

class CustomValidator(MCPValidator):
    async def test_custom_endpoint(self):
        """Test a custom MCP endpoint."""
        response = await self.client.get(
            f"{self.server_url}/custom",
            headers=self._get_headers()
        )
        
        passed = response.status_code == 200
        error = None if passed else f"Got {response.status_code}"
        
        return passed, error, {"status": response.status_code}
    
    async def validate(self):
        # Add custom test
        custom_test = TestCase(
            id="custom-endpoint",
            name="Custom Endpoint Test",
            description="Validates custom MCP endpoint",
            severity=TestSeverity.MEDIUM,
            category="custom"
        )
        
        result = await self._execute_test(
            custom_test,
            self.test_custom_endpoint
        )
        self.test_results.append(result)
        
        # Run standard tests
        return await super().validate()
```

### OAuth Flow Automation

```python
from mcp_http_validator import MCPValidator, EnvManager

async def automated_oauth_test(mcp_server: str):
    # Automatic OAuth discovery and registration
    async with MCPValidator(mcp_server) as validator:
        # Discovers OAuth server and registers client automatically
        oauth_client = await validator.setup_oauth_client()
        
        if oauth_client:
            # Generate auth URL with discovered OAuth server
            auth_url, state, verifier = oauth_client.generate_authorization_url(
                resources=[mcp_server]
            )
            
            print(f"Visit: {auth_url}")
            code = input("Enter code: ")
            
            # Exchange for token
            token = await oauth_client.exchange_code_for_token(
                code, verifier, [mcp_server]
            )
            
            # Test access
            success, error, _ = await oauth_client.test_mcp_server_with_token(
                mcp_server, token.access_token
            )
            print(f"Access: {'✓' if success else '✗'} {error or 'OK'}")

# RFC 7592 Client Management
async def manage_oauth_client(mcp_server: str):
    env_manager = EnvManager()
    credentials = env_manager.get_oauth_credentials(mcp_server)
    
    async with MCPValidator(mcp_server) as validator:
        auth_server = await validator.discover_oauth_server()
        
        async with OAuthTestClient(
            auth_server,
            registration_access_token=credentials["registration_token"]
        ) as client:
            # Get current config
            config = await client.get_client_configuration()
            
            # Update client
            await client.update_client_configuration({
                "client_name": "Updated Name"
            })
            
            # Or delete client
            # await client.delete_client_registration()
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## See Also

- [MCP Specification](https://modelcontextprotocol.io/specification)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Dynamic Client Registration RFC 7591](https://tools.ietf.org/html/rfc7591)
- [Dynamic Client Registration Management RFC 7592](https://tools.ietf.org/html/rfc7592)
- [Resource Indicators RFC 8707](https://tools.ietf.org/html/rfc8707)
- [Protected Resource Metadata RFC 9728](https://tools.ietf.org/html/rfc9728)