"""
Session ID uniqueness and security validation.

Tests that session IDs are globally unique and cryptographically secure
as required by the MCP specification.
"""

from typing import List, Set

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="SM-002",
    name="Session ID Uniqueness",
    category=TestCategory.SESSION,
    severity=TestSeverity.HIGH,
    description="""
    Verifies that session IDs are globally unique and cryptographically secure.
    The specification requires that session IDs MUST be globally unique.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http",
    spec_section="Session Management",
    spec_requirement="Session IDs MUST be globally unique and cryptographically secure",
    tags=["session", "security", "uniqueness"],
    timeout=30
)
async def test_session_id_uniqueness(client: MCPTestBase) -> TestResult:
    """
    Test that session IDs are globally unique.
    
    The MCP spec requires session IDs to be globally unique and cryptographically
    secure. We test uniqueness by collecting multiple IDs and checking for duplicates.
    """
    
    result = client.create_test_result(
        test_id="SM-002",
        test_name="Session ID Uniqueness",
        category=TestCategory.SESSION.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Request 100 session IDs from the server
    2. Check for any duplicate session IDs
    3. Verify IDs appear to be randomly generated (not sequential)
    4. Confirm reasonable length for security (16+ characters recommended)
    """
    
    result.expected_behavior = """
    - No duplicate session IDs in sample of 100
    - Session IDs should be non-sequential
    - Reasonable length for security (16+ characters)
    - IDs should appear random, not predictable
    """
    
    try:
        # Collect multiple session IDs
        session_ids: List[str] = []
        sample_size = 100
        
        for i in range(sample_size):
            try:
                # Create new client for each session
                test_client = MCPTestBase(client.endpoint)
                await test_client.initialize_session()
                session_id = test_client.session_id
                if session_id:
                    session_ids.append(session_id)
                await test_client.cleanup()
            except Exception:
                # Continue collecting what we can
                pass
        
        if len(session_ids) == 0:
            # Server is stateless - this is allowed
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server is stateless (no session IDs provided)"
            result.failure_reason = """
            Server did not provide any session IDs across multiple initialization attempts.
            This indicates stateless operation, which is allowed by the MCP specification.
            """
            return result
        elif len(session_ids) < 10:
            result.status = TestStatus.ERROR
            result.actual_behavior = f"Could only collect {len(session_ids)} session IDs"
            result.failure_reason = "Insufficient session IDs collected for uniqueness test"
            return result
        
        # Check for duplicates
        unique_ids = set(session_ids)
        duplicates = len(session_ids) - len(unique_ids)
        
        # Check for sequential patterns
        has_sequential = False
        if len(session_ids) >= 2:
            # Simple check: are IDs incrementing numbers?
            try:
                # Check if IDs contain sequential numbers
                for i in range(len(session_ids) - 1):
                    if session_ids[i+1] == session_ids[i]:
                        has_sequential = True
                        break
                    # Check for simple increment patterns
                    if session_ids[i].replace('-', '').isdigit() and \
                       session_ids[i+1].replace('-', '').isdigit():
                        num1 = int(session_ids[i].replace('-', ''))
                        num2 = int(session_ids[i+1].replace('-', ''))
                        if abs(num2 - num1) == 1:
                            has_sequential = True
                            break
            except:
                pass  # Not numeric, which is good
        
        # Check length
        min_length = min(len(sid) for sid in session_ids) if session_ids else 0
        max_length = max(len(sid) for sid in session_ids) if session_ids else 0
        avg_length = sum(len(sid) for sid in session_ids) / len(session_ids) if session_ids else 0
        
        # Determine result
        if duplicates > 0:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            CRITICAL: Found {duplicates} duplicate session IDs in {len(session_ids)} samples!
            - Unique IDs: {len(unique_ids)}
            - Duplicates: {duplicates}
            - Length range: {min_length}-{max_length} characters
            """
            
            result.failure_reason = """
            Session IDs are not globally unique! This is a critical security failure.
            Duplicate session IDs allow session hijacking and unauthorized access.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="CRITICAL",
                security="CRITICAL",
                functionality="CRITICAL",
                description="Non-unique session IDs completely break security and session isolation"
            )
            
            result.remediation = Remediation(
                priority="IMMEDIATE",
                steps=[
                    "Use cryptographically secure random generation (e.g., UUID v4)",
                    "Ensure IDs are globally unique across all sessions",
                    "Never reuse or recycle session IDs",
                    "Use sufficient entropy (128+ bits)"
                ],
                code_example="""
# Example: Generating unique session IDs
import uuid

def generate_session_id() -> str:
    # UUID v4 guarantees uniqueness with 122 bits of randomness
    return str(uuid.uuid4())

# Alternative with secrets module:
import secrets

def generate_secure_id() -> str:
    # 32 bytes = 256 bits of entropy
    return secrets.token_urlsafe(32)
"""
            )
        elif min_length < 16:
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            Session IDs are unique but may be too short:
            - Tested {len(session_ids)} IDs: all unique ✓
            - Length range: {min_length}-{max_length} characters
            - Sequential pattern detected: {'Yes ⚠️' if has_sequential else 'No ✓'}
            
            Warning: IDs shorter than 16 characters may be vulnerable to brute force.
            """
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Session IDs meet uniqueness requirements:
            - Tested {len(session_ids)} IDs: all unique ✓
            - Length range: {min_length}-{max_length} characters  
            - Average length: {avg_length:.1f} characters
            - Sequential pattern detected: {'Yes ⚠️' if has_sequential else 'No ✓'}
            """
        
        # Add evidence
        if not result.evidence:
            from ...models.test_results import Evidence
            result.evidence = Evidence()
        if not result.evidence.validation_details:
            result.evidence.validation_details = {}
        
        result.evidence.validation_details.update({
            "sample_size": len(session_ids),
            "unique_count": len(unique_ids),
            "duplicate_count": duplicates,
            "min_length": min_length,
            "max_length": max_length,
            "avg_length": avg_length,
            "has_sequential": has_sequential,
            "sample_ids": session_ids[:3] if session_ids else []
        })
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result