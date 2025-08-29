"""
HTTP header requirements tests for MCP streamable transport.

Tests that required headers are properly handled according to:
https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="TR-001",
    name="Accept Header Requirements",
    category=TestCategory.TRANSPORT,
    severity=TestSeverity.HIGH,
    description="""
    Validates that the server properly handles the Accept header requirements.
    Client MUST include both 'application/json' and 'text/event-stream' in Accept header.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http",
    spec_section="Streamable HTTP",
    spec_requirement="Client MUST include Accept header with application/json and text/event-stream",
    tags=["transport", "headers", "http"],
    timeout=10
)
async def test_accept_header_requirements(client: MCPTestBase) -> TestResult:
    """Test that server handles Accept header requirements correctly."""
    
    result = client.create_test_result(
        test_id="TR-001",
        test_name="Accept Header Requirements",
        category=TestCategory.TRANSPORT.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Send request with correct Accept header (both types)
    2. Send request with only application/json
    3. Send request with only text/event-stream
    4. Send request without Accept header
    5. Verify server accepts correct header and handles others appropriately
    """
    
    result.expected_behavior = """
    - Server accepts requests with both media types in Accept header
    - Server may accept partial Accept headers (implementation choice)
    - Server responds with either application/json or text/event-stream
    - Response Content-Type matches one of the accepted types
    """
    
    try:
        # Test 1: Correct Accept header (both types)
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-test",
                    "version": "1.0.0"
                }
            }
        }
        
        # This should work (correct headers)
        response1 = await client.send_request(
            request,
            headers={"Accept": "text/event-stream, application/json"}
        )
        
        # Check response content type
        content_type = client.evidence.headers.get('content-type', '').lower()
        valid_response_type = ('application/json' in content_type or 
                              'text/event-stream' in content_type)
        
        if not valid_response_type:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"Server responded with unexpected Content-Type: {content_type}"
            result.failure_reason = "Server must respond with either application/json or text/event-stream"
            return result
        
        # Test 2: Only application/json (may or may not work)
        try:
            response2 = await client.send_request(
                request,
                headers={"Accept": "application/json"}
            )
            json_only_works = True
        except Exception:
            json_only_works = False
        
        # Test 3: Only text/event-stream (may or may not work)  
        try:
            response3 = await client.send_request(
                request,
                headers={"Accept": "text/event-stream"}
            )
            sse_only_works = True
        except Exception:
            sse_only_works = False
        
        # Test 4: No Accept header (should still work with defaults)
        try:
            response4 = await client.send_request(request, headers={})
            no_accept_works = True
        except Exception:
            no_accept_works = False
        
        result.status = TestStatus.PASSED
        result.actual_behavior = f"""
        Accept header handling:
        - Both types accepted: ✓
        - JSON only: {'✓' if json_only_works else '✗'}
        - SSE only: {'✓' if sse_only_works else '✗'}
        - No Accept header: {'✓' if no_accept_works else '✗'}
        - Response Content-Type: {content_type}
        """
        
        # Store evidence
        if not result.evidence:
            result.evidence = client.evidence
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="TR-002",
    name="Protocol Version Header",
    category=TestCategory.TRANSPORT,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that the MCP-Protocol-Version header is properly handled.
    Client MUST include MCP-Protocol-Version header with the protocol version.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http",
    spec_section="Streamable HTTP",
    spec_requirement="Client MUST include MCP-Protocol-Version header with protocol version",
    tags=["transport", "headers", "protocol"],
    timeout=10
)
async def test_protocol_version_header(client: MCPTestBase) -> TestResult:
    """Test protocol version header handling."""
    
    result = client.create_test_result(
        test_id="TR-002",
        test_name="Protocol Version Header",
        category=TestCategory.TRANSPORT.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Send request with correct protocol version header
    2. Send request without protocol version header
    3. Send request with unsupported protocol version
    4. Verify server handles each case appropriately
    """
    
    result.expected_behavior = """
    - Server accepts requests with valid protocol version
    - Server assumes version 2025-03-26 if header missing (SHOULD behavior)
    - Server may reject unsupported protocol versions
    - Server indicates supported versions in response or error
    """
    
    try:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-test",
                    "version": "1.0.0"
                }
            }
        }
        
        # Test 1: With correct protocol version
        headers = {
            "Accept": "text/event-stream, application/json",
            "MCP-Protocol-Version": "2025-06-18"
        }
        
        response1 = await client.send_request(request, headers=headers)
        correct_version_works = response1.get("result") is not None
        
        # Test 2: Without protocol version header (should assume default)
        headers_no_version = {
            "Accept": "text/event-stream, application/json"
        }
        
        try:
            response2 = await client.send_request(request, headers=headers_no_version)
            no_version_works = response2.get("result") is not None
        except Exception:
            no_version_works = False
        
        # Test 3: With old/unsupported version
        headers_old = {
            "Accept": "text/event-stream, application/json",
            "MCP-Protocol-Version": "2024-01-01"
        }
        
        try:
            response3 = await client.send_request(request, headers=headers_old)
            old_version_accepted = True
            old_version_error = None
        except Exception as e:
            old_version_accepted = False
            old_version_error = str(e)
        
        # Determine pass/fail
        if not correct_version_works:
            result.status = TestStatus.FAILED
            result.actual_behavior = "Server rejected valid protocol version header"
            result.failure_reason = "Server must accept valid MCP-Protocol-Version header"
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Protocol version handling:
            - Valid version (2025-06-18): ✓
            - No version header: {'✓' if no_version_works else '✗ (should assume default)'}
            - Old version (2024-01-01): {'✓ Accepted' if old_version_accepted else '✗ Rejected'}
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result