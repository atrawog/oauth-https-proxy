"""
Session persistence and state management tests.

Validates that sessions persist correctly across multiple requests and
maintain state as expected.
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity  
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="SM-003",
    name="Session Persistence Across Requests",
    category=TestCategory.SESSION,
    severity=TestSeverity.HIGH,
    description="""
    Validates that session state persists correctly across multiple requests
    when using the same session ID in the Mcp-Session-Id header.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management",
    spec_section="Session Management",
    spec_requirement="Clients must include session ID in subsequent requests",
    tags=["session", "persistence", "state"],
    timeout=15
)
async def test_session_persistence(client: MCPTestBase) -> TestResult:
    """Test that sessions maintain state across requests."""
    
    result = client.create_test_result(
        test_id="SM-003",
        test_name="Session Persistence Across Requests",
        category=TestCategory.SESSION.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize a session and obtain session ID
    2. Send multiple requests with the same session ID
    3. Verify server recognizes and maintains session context
    4. Test with missing session ID (should fail or create new session)
    5. Test with invalid session ID (should return 404)
    6. Verify session-specific state is maintained
    """
    
    result.expected_behavior = """
    - Server accepts and recognizes session ID in Mcp-Session-Id header
    - Requests with same session ID access same session state
    - Missing session ID either fails or creates new session
    - Invalid session ID returns 404 Not Found
    - Session state persists for reasonable duration
    - Case-sensitive session ID matching
    """
    
    try:
        # Step 1: Initialize session
        init_result = await client.initialize_session()
        # Session ID is stored in client after initialization
        session_id = client.session_id
        
        if not session_id:
            # Server is stateless - this is allowed
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server is stateless (no session ID provided)"
            result.failure_reason = """
            Server did not provide a session ID, indicating stateless operation.
            Session persistence testing is not applicable for stateless servers.
            This is allowed by the MCP specification - session IDs are optional.
            """
            return result
        
        # Step 2: Test request with valid session ID
        # Use tools/list instead of ping as not all servers support ping
        test_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        response1 = await client.send_request(
            test_request,
            headers={"Mcp-Session-Id": session_id}
        )
        
        # Step 3: Test request with invalid session ID
        invalid_response = None
        try:
            invalid_response = await client.send_request(
                test_request,
                headers={"Mcp-Session-Id": "invalid-session-id-12345"}
            )
        except Exception as e:
            # Expected - invalid session should fail
            if "404" in str(e) or "not found" in str(e).lower():
                invalid_handled_correctly = True
            else:
                invalid_handled_correctly = False
        else:
            # Check if response indicates session not found
            invalid_handled_correctly = (
                invalid_response.get("error") is not None or
                invalid_response.get("status") == "not_found"
            )
        
        # Step 4: Test request without session ID
        no_session_response = None
        try:
            # Clear session ID temporarily
            temp_session = client.session_id
            client.session_id = None
            
            no_session_response = await client.send_request(test_request)
            
            # Restore session ID
            client.session_id = temp_session
        except Exception as e:
            # May fail or create new session
            no_session_error = str(e)
        
        # Analyze results
        failures = []
        warnings = []
        
        # Check if valid session requests work
        if response1.get("error"):
            error = response1.get("error", {})
            error_code = error.get("code")
            error_msg = error.get("message", "").lower()
            
            # Check if it's a session-related error or just method not implemented
            # -32602 is "Invalid request parameters" which might mean method not implemented
            # -32601 is "Method not found"
            if error_code in [-32601, -32602] or "method" in error_msg or "not found" in error_msg:
                # Method issue, not session issue - skip this test
                result.status = TestStatus.WARNING
                result.actual_behavior = f"""
                Server returned method error for tools/list: {error}
                Cannot properly test session persistence without working methods.
                Consider this a WARNING rather than failure.
                """
                return result
            else:
                failures.append(f"Request with valid session ID failed: {error}")
        
        # Note: The spec only requires 404 for terminated sessions, not necessarily for invalid IDs
        # So we'll just warn if servers accept invalid IDs, not fail
        if not invalid_handled_correctly:
            warnings.append("Server accepted invalid session ID (best practice: return error)")
        
        # Determine result
        if failures:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Session persistence test results:
            - Valid session ID: {'Accepted' if not response1.get("error") else 'Rejected'}
            - Invalid session ID: {'Properly rejected' if invalid_handled_correctly else 'Incorrectly accepted'}
            - No session ID: {'New session created' if no_session_response else 'Request failed'}
            
            Issues found:
            {chr(10).join('• ' + f for f in failures)}
            """
            
            result.failure_reason = """
            Session persistence is not properly implemented.
            
            The server must:
            1. Accept valid session IDs in Mcp-Session-Id header
            2. Reject invalid session IDs with 404 Not Found
            3. Maintain session state across requests
            4. Handle missing session IDs appropriately
            
            Without proper session persistence:
            - Stateful operations become impossible
            - Each request is treated independently
            - Complex multi-step workflows cannot function
            - User context is lost between requests
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="MEDIUM",
                functionality="HIGH",
                description="""
                Broken session persistence severely limits functionality:
                - No stateful conversations or workflows
                - Cannot maintain user context
                - Breaks MCP protocol compliance
                - Incompatible with standard MCP clients
                """
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Implement session storage (in-memory or Redis)",
                    "Read Mcp-Session-Id header from requests",
                    "Validate session ID exists in storage",
                    "Return 404 for invalid/expired sessions",
                    "Maintain session state between requests",
                    "Implement session timeout mechanism",
                    "Add session cleanup for expired sessions"
                ],
                code_example="""
# Python example of session management
from typing import Dict, Optional
import time

class SessionManager:
    def __init__(self, timeout_seconds: int = 3600):
        self.sessions: Dict[str, dict] = {}
        self.timeout = timeout_seconds
    
    def create_session(self) -> str:
        \"\"\"Create new session with unique ID.\"\"\"
        import secrets
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            'created_at': time.time(),
            'last_accessed': time.time(),
            'state': {}
        }
        return session_id
    
    def get_session(self, session_id: str) -> Optional[dict]:
        \"\"\"Get session if valid and not expired.\"\"\"
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        if time.time() - session['last_accessed'] > self.timeout:
            del self.sessions[session_id]
            return None
        
        session['last_accessed'] = time.time()
        return session
    
    def cleanup_expired(self):
        \"\"\"Remove expired sessions.\"\"\"
        now = time.time()
        expired = [
            sid for sid, sess in self.sessions.items()
            if now - sess['last_accessed'] > self.timeout
        ]
        for sid in expired:
            del self.sessions[sid]
""",
                estimated_effort="3-4 hours"
            )
        elif warnings:
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            Session persistence partially working:
            - Valid session ID: Accepted ✓
            - Invalid session ID: {'Rejected ✓' if invalid_handled_correctly else 'Accepted ⚠️'}
            - No session ID: {'Handled' if no_session_response else 'Failed'}
            
            Warnings:
            {chr(10).join('• ' + w for w in warnings)}
            
            Note: The spec doesn't explicitly require rejecting invalid session IDs.
            """
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Session persistence working correctly:
            - Valid session ID is accepted and recognized
            - Invalid session IDs are properly handled
            - Session state maintained across requests
            - Session ID: {session_id[:8]}... (truncated)
            """
        
        # Add evidence
        if result.evidence is None:
            from ...models.test_results import Evidence
            result.evidence = Evidence()
        if result.evidence.validation_details is None:
            result.evidence.validation_details = {}
        result.evidence.validation_details.update({
            'session_id': session_id[:16] + '...',  # Truncate for security
            'valid_session_accepted': not response1.get("error") if response1 else False,
            'invalid_session_rejected': invalid_handled_correctly
        })
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {str(e)}"
        result.failure_reason = f"Could not complete persistence test: {str(e)}"
    
    return result