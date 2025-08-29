"""
Origin header validation tests for MCP security.

Tests security requirements from:
https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="SEC-001",
    name="Origin Header Validation",
    category=TestCategory.SECURITY,
    severity=TestSeverity.CRITICAL,
    description="""
    Validates that server MUST validate the Origin header on all incoming connections
    to prevent DNS rebinding attacks.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http",
    spec_section="Security",
    spec_requirement="Servers MUST validate the Origin header to prevent DNS rebinding attacks",
    tags=["security", "origin", "dns-rebinding"],
    timeout=10
)
async def test_origin_header_validation(client: MCPTestBase) -> TestResult:
    """Test that server validates Origin header to prevent DNS rebinding attacks."""
    
    result = client.create_test_result(
        test_id="SEC-001",
        test_name="Origin Header Validation",
        category=TestCategory.SECURITY.value,
        severity=TestSeverity.CRITICAL.value
    )
    
    result.methodology = """
    1. Send request with valid/expected Origin header
    2. Send request with malicious Origin header (external domain)
    3. Send request with no Origin header
    4. Send request with localhost Origin
    5. Verify server rejects suspicious origins
    """
    
    result.expected_behavior = """
    - Server accepts requests from expected origins
    - Server rejects requests from external/malicious origins
    - Server handles missing Origin header appropriately
    - Clear security error for rejected origins
    """
    
    try:
        import httpx
        
        # Initialize session first
        await client.initialize_session()
        session_id = client.session_id
        
        if not session_id:
            result.status = TestStatus.ERROR
            result.actual_behavior = "No session ID returned"
            result.failure_reason = "Cannot test without session"
            return result
        
        test_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        base_headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",
            "MCP-Protocol-Version": "2025-06-18",
            "Mcp-Session-Id": session_id
        }
        
        # Test 1: Expected origin (same as endpoint)
        from urllib.parse import urlparse
        parsed = urlparse(client.endpoint)
        expected_origin = f"{parsed.scheme}://{parsed.netloc}"
        
        valid_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            headers_valid = {**base_headers, "Origin": expected_origin}
            response_valid = await valid_client.post(
                client.endpoint,
                json=test_request,
                headers=headers_valid
            )
            valid_accepted = response_valid.status_code in [200, 202]
        finally:
            await valid_client.aclose()
        
        # Test 2: Malicious external origin
        malicious_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            headers_malicious = {**base_headers, "Origin": "https://evil.example.com"}
            response_malicious = await malicious_client.post(
                client.endpoint,
                json=test_request,
                headers=headers_malicious
            )
            malicious_rejected = response_malicious.status_code >= 400
        finally:
            await malicious_client.aclose()
        
        # Test 3: No Origin header
        no_origin_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            # No Origin header
            response_no_origin = await no_origin_client.post(
                client.endpoint,
                json=test_request,
                headers=base_headers
            )
            no_origin_status = response_no_origin.status_code
        finally:
            await no_origin_client.aclose()
        
        # Test 4: Localhost origin (should usually be accepted)
        localhost_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        try:
            headers_localhost = {**base_headers, "Origin": "http://localhost"}
            response_localhost = await localhost_client.post(
                client.endpoint,
                json=test_request,
                headers=headers_localhost
            )
            localhost_accepted = response_localhost.status_code in [200, 202]
        finally:
            await localhost_client.aclose()
        
        # Analyze results
        if not malicious_rejected:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            CRITICAL SECURITY FAILURE: Server accepts requests from malicious origins!
            - Valid origin ({expected_origin}): {'Accepted ✓' if valid_accepted else 'Rejected ✗'}
            - Malicious origin (evil.example.com): Accepted ✗ (MUST reject)
            - No Origin header: Status {no_origin_status}
            - Localhost origin: {'Accepted' if localhost_accepted else 'Rejected'}
            
            Server is vulnerable to DNS rebinding attacks!
            """
            
            result.failure_reason = """
            Server MUST validate Origin header to prevent DNS rebinding attacks.
            Accepting requests from arbitrary origins is a critical security vulnerability.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="LOW",
                security="CRITICAL",
                functionality="LOW",
                description="""
                DNS rebinding vulnerability allows attackers to:
                - Bypass same-origin policy
                - Access internal services
                - Steal sensitive data
                - Execute unauthorized commands
                """
            )
            
            result.remediation = Remediation(
                priority="IMMEDIATE",
                steps=[
                    "Implement Origin header validation",
                    "Whitelist allowed origins",
                    "Reject requests from unknown origins",
                    "Return 403 Forbidden for invalid origins",
                    "Log security violations"
                ],
                code_example="""
# Example: Origin header validation
ALLOWED_ORIGINS = [
    "http://localhost",
    "http://127.0.0.1",
    "https://yourdomain.com"
]

async def validate_origin(request):
    origin = request.headers.get('Origin')
    
    # No origin might be okay for non-browser clients
    if not origin:
        # Decide based on your security requirements
        return True  # or False for strict security
    
    # Check against whitelist
    if origin not in ALLOWED_ORIGINS:
        return False
    
    return True

async def handle_request(request):
    if not validate_origin(request):
        return JSONResponse(
            status_code=403,
            content={"error": "Forbidden: Invalid Origin"}
        )
    
    # Process request...
"""
            )
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Server properly validates Origin header:
            - Valid origin ({expected_origin}): {'Accepted ✓' if valid_accepted else 'Rejected'}
            - Malicious origin (evil.example.com): Rejected ✓
            - No Origin header: Status {no_origin_status}
            - Localhost origin: {'Accepted ✓' if localhost_accepted else 'Rejected'}
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result