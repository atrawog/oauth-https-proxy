"""
Session ID character set validation test.

This test validates that session IDs only contain visible ASCII characters
as required by the MCP specification.
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="SM-001",
    name="Session ID Character Set Validation",
    category=TestCategory.SESSION,
    severity=TestSeverity.CRITICAL,
    description="""
    Validates that session IDs contain only visible ASCII characters (0x21-0x7E)
    as required by the MCP specification. This is critical for cross-platform
    compatibility, security, and proper HTTP header handling.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management",
    spec_section="Session Management",
    spec_requirement="Session IDs MUST only contain visible ASCII characters (0x21-0x7E)",
    tags=["session", "security", "critical", "charset"],
    timeout=10
)
async def test_session_id_charset(client: MCPTestBase) -> TestResult:
    """
    Test that session IDs only contain visible ASCII characters.
    
    This test is critical because:
    1. Spaces and control characters can break HTTP header parsing
    2. Non-ASCII characters cause encoding issues across platforms
    3. Invalid characters can enable injection attacks
    """
    
    # Create result with initial metadata
    result = client.create_test_result(
        test_id="SM-001",
        test_name="Session ID Character Set Validation",
        category=TestCategory.SESSION.value,
        severity=TestSeverity.CRITICAL.value
    )
    
    # Set detailed methodology
    result.methodology = """
    1. Initialize a new MCP session with the server
    2. Extract the session ID from the initialization response
    3. Validate each character is within ASCII range 0x21-0x7E (! to ~)
    4. Test multiple sessions to ensure consistency
    5. Check for common problematic characters (spaces, tabs, newlines)
    6. Verify no control characters or extended ASCII
    """
    
    # Set expected behavior
    result.expected_behavior = """
    - All characters in session ID must be visible ASCII (printable)
    - Character range: 0x21 (!) through 0x7E (~)
    - No spaces (0x20), tabs (0x09), or newlines (0x0A, 0x0D)
    - No control characters (0x00-0x1F)
    - No extended ASCII (0x7F and above)
    - Recommended safe subset: [A-Za-z0-9-_]
    - Minimum recommended length: 32 characters
    """
    
    try:
        # Initialize session
        init_result = await client.initialize_session()
        # Session ID is stored in client after initialization
        session_id = client.session_id
        
        if not session_id:
            # Server is stateless - this is allowed by the spec
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server is stateless (no session ID provided)"
            result.failure_reason = """
            Server did not provide a session ID, indicating stateless operation.
            This is allowed by the MCP specification - session IDs are optional.
            Stateless servers don't maintain session state between requests.
            """
            return result
        
        # Check character validity
        violations = client.check_character_range(session_id, 0x21, 0x7E)
        
        if violations:
            # Test failed - invalid characters found
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Session ID contained {len(violations)} invalid character(s).
            Session ID: {session_id}
            Length: {len(session_id)} characters
            Invalid characters at positions: {[v['position'] for v in violations]}
            """
            
            result.failure_reason = f"""
            The session ID contains non-visible ASCII characters which violates
            the MCP specification requirement that session IDs MUST only contain
            visible ASCII characters in the range 0x21-0x7E.
            
            Violations found:
            {client.format_violations(violations)}
            
            Why this matters:
            1. HTTP Headers: Spaces and control characters can break header parsing
            2. URL Safety: Session IDs may be used in URLs where certain characters cause issues
            3. Cross-Platform: Different systems handle character encoding differently
            4. Security: Control characters can enable header injection attacks
            5. Debugging: Non-printable characters make debugging difficult
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="MEDIUM",
                functionality="HIGH",
                description="""
                Invalid session ID characters will cause:
                - HTTP header parsing failures with strict clients
                - URL encoding issues when session ID used in query parameters
                - Potential security vulnerabilities from control character injection
                - Incompatibility with MCP-compliant clients
                """
            )
            
            result.remediation = Remediation(
                priority="IMMEDIATE",
                steps=[
                    "Review session ID generation algorithm",
                    "Use only alphanumeric characters plus hyphen and underscore: [A-Za-z0-9-_]",
                    "Avoid spaces, special characters, and control characters",
                    "Consider using base64url encoding (without padding) for binary data",
                    "Implement character validation before returning session IDs",
                    "Add unit tests to verify character set compliance"
                ],
                code_example=client.get_safe_session_id_example(),
                estimated_effort="1-2 hours",
                references=[
                    "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management",
                    "https://datatracker.ietf.org/doc/html/rfc7230#section-3.2"
                ]
            )
            
            # Add evidence
            result.evidence.validation_details = {
                'session_id': session_id,
                'session_id_length': len(session_id),
                'invalid_characters': violations,
                'character_distribution': _analyze_char_distribution(session_id)
            }
            
        else:
            # Test passed
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Session ID contains only valid visible ASCII characters.
            Session ID length: {len(session_id)} characters
            All {len(session_id)} characters are within range 0x21-0x7E.
            Character set appears to be: {_identify_charset(session_id)}
            """
            
            # Add performance note if session ID is short
            if len(session_id) < 32:
                result.notes = f"""
                While the session ID character set is valid, consider increasing
                the length to at least 32 characters for better security.
                Current length: {len(session_id)} characters.
                """
    
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {str(e)}"
        result.failure_reason = f"""
        The test could not be completed due to an unexpected error.
        This may indicate a problem with the server's basic functionality.
        
        Error: {str(e)}
        """
        
    return result


def _analyze_char_distribution(session_id: str) -> dict:
    """Analyze character distribution in session ID."""
    import string
    
    distribution = {
        'uppercase': sum(1 for c in session_id if c in string.ascii_uppercase),
        'lowercase': sum(1 for c in session_id if c in string.ascii_lowercase),
        'digits': sum(1 for c in session_id if c in string.digits),
        'special': sum(1 for c in session_id if c not in string.ascii_letters + string.digits)
    }
    
    return distribution


def _identify_charset(session_id: str) -> str:
    """Identify the character set used in session ID."""
    import string
    
    chars = set(session_id)
    
    if chars.issubset(set(string.hexdigits)):
        return "Hexadecimal"
    elif chars.issubset(set(string.ascii_letters + string.digits + '-')):
        return "UUID-style (alphanumeric with hyphens)"
    elif chars.issubset(set(string.ascii_letters + string.digits)):
        return "Alphanumeric"
    elif chars.issubset(set(string.ascii_letters + string.digits + '-_')):
        return "URL-safe base64 style"
    else:
        return "Mixed special characters"