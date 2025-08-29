"""
Protocol version negotiation tests for MCP.

Tests version negotiation requirements from:
https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="LC-003",
    name="Protocol Version Negotiation",
    category=TestCategory.PROTOCOL,
    severity=TestSeverity.HIGH,
    description="""
    Validates protocol version negotiation.
    If server doesn't support requested version, it MUST respond with another version it supports.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle",
    spec_section="Version Negotiation",
    spec_requirement="Server MUST respond with supported version if requested version unsupported",
    tags=["lifecycle", "version", "negotiation"],
    timeout=10
)
async def test_version_negotiation(client: MCPTestBase) -> TestResult:
    """Test protocol version negotiation."""
    
    result = client.create_test_result(
        test_id="LC-003",
        test_name="Protocol Version Negotiation",
        category=TestCategory.PROTOCOL.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Send initialize with current version (2025-06-18)
    2. Send initialize with old version (2024-01-01)
    3. Send initialize with future version (2026-01-01)
    4. Verify server responds with supported version when needed
    """
    
    result.expected_behavior = """
    - Server accepts supported versions
    - Server responds with alternative version if unsupported
    - Server doesn't crash on unknown versions
    - Version in response matches what server supports
    """
    
    try:
        import httpx
        
        # Test 1: Current version (should work)
        current_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        response1 = await client.send_request(current_request)
        current_accepted = response1.get('result') is not None
        current_version = response1.get('result', {}).get('protocolVersion', '')
        
        # Test 2: Old version
        old_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-01-01",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        # Create new client for clean test
        old_client = MCPTestBase(client.endpoint)
        response2 = await old_client.send_request(old_request)
        old_response_version = None
        
        if response2.get('result'):
            old_response_version = response2['result'].get('protocolVersion')
        elif response2.get('error'):
            # Server rejected old version
            old_response_version = 'rejected'
        
        await old_client.cleanup()
        
        # Test 3: Future version
        future_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-01-01",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        future_client = MCPTestBase(client.endpoint)
        response3 = await future_client.send_request(future_request)
        future_response_version = None
        
        if response3.get('result'):
            future_response_version = response3['result'].get('protocolVersion')
        elif response3.get('error'):
            future_response_version = 'rejected'
        
        await future_client.cleanup()
        
        # Analyze results
        issues = []
        
        # Check if server handles version negotiation
        if old_response_version == 'rejected':
            issues.append("Server rejected old version instead of negotiating")
        
        if future_response_version == 'rejected':
            issues.append("Server rejected future version instead of negotiating")
        
        if future_response_version and future_response_version != 'rejected':
            if future_response_version == "2026-01-01":
                issues.append("Server accepted unsupported future version")
        
        if issues:
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            Version negotiation partially working:
            - Current version (2025-06-18): {current_version} ✓
            - Old version (2024-01-01): {old_response_version}
            - Future version (2026-01-01): {future_response_version}
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Version negotiation working correctly:
            - Current version: {current_version} ✓
            - Old version response: {old_response_version}
            - Future version response: {future_response_version}
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="LC-004",
    name="Protocol Version Header Persistence",
    category=TestCategory.PROTOCOL,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that client MUST include protocol version header on subsequent HTTP requests
    after initialization.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle",
    spec_section="Version Negotiation",
    spec_requirement="Client MUST include protocol version header on subsequent HTTP requests",
    tags=["lifecycle", "version", "headers"],
    timeout=10
)
async def test_version_header_persistence(client: MCPTestBase) -> TestResult:
    """Test that protocol version header is required after initialization."""
    
    result = client.create_test_result(
        test_id="LC-004",
        test_name="Protocol Version Header Persistence",
        category=TestCategory.PROTOCOL.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session with protocol version
    2. Send subsequent request WITH protocol version header
    3. Send subsequent request WITHOUT protocol version header
    4. Verify server handles missing header appropriately
    """
    
    result.expected_behavior = """
    - Server accepts requests with protocol version header
    - Server may reject or warn about missing version header
    - Consistent behavior across all post-initialization requests
    """
    
    try:
        # Initialize first
        await client.initialize_session()
        session_id = client.session_id
        
        if not session_id:
            result.status = TestStatus.ERROR
            result.actual_behavior = "No session ID returned"
            result.failure_reason = "Cannot test without session"
            return result
        
        # Test request
        test_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        import httpx
        
        # Test 1: WITH protocol version header (should work)
        with_header_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            response_with = await with_header_client.post(
                client.endpoint,
                json=test_request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json",
                    "MCP-Protocol-Version": "2025-06-18",
                    "Mcp-Session-Id": session_id
                }
            )
            with_header_works = response_with.status_code in [200, 202]
        finally:
            await with_header_client.aclose()
        
        # Test 2: WITHOUT protocol version header
        without_header_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            response_without = await without_header_client.post(
                client.endpoint,
                json=test_request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json",
                    "Mcp-Session-Id": session_id
                    # Missing MCP-Protocol-Version
                }
            )
            without_header_works = response_without.status_code in [200, 202]
        finally:
            await without_header_client.aclose()
        
        # The spec says client MUST include it, but doesn't say server must reject without it
        if with_header_works and not without_header_works:
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server enforces protocol version header requirement:
            - With version header: Accepted ✓
            - Without version header: Rejected ✓
            """
        elif with_header_works and without_header_works:
            result.status = TestStatus.WARNING
            result.actual_behavior = """
            Server accepts requests regardless of version header:
            - With version header: Accepted ✓
            - Without version header: Accepted (should consider rejecting)
            
            Note: Clients MUST include the header, but server enforcement is optional.
            """
        else:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Unexpected server behavior:
            - With version header: {'Accepted' if with_header_works else 'Rejected'}
            - Without version header: {'Accepted' if without_header_works else 'Rejected'}
            """
            result.failure_reason = "Server should accept requests with protocol version header"
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result