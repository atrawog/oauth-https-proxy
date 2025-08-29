"""
Resource URI validation tests for MCP.

Tests that resource URIs comply with RFC3986 and are properly validated:
https://modelcontextprotocol.io/specification/2025-06-18/server/resources
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="RES-003",
    name="Resource URI Validation",
    category=TestCategory.RESOURCES,
    severity=TestSeverity.HIGH,
    description="""
    Validates that resource URIs MUST be in accordance with RFC3986 and
    servers MUST validate all resource URIs.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
    spec_section="Resource URIs",
    spec_requirement="URIs MUST be in accordance with RFC3986, servers MUST validate all resource URIs",
    tags=["resources", "uri", "validation", "rfc3986"],
    timeout=10
)
async def test_resource_uri_validation(client: MCPTestBase) -> TestResult:
    """Test that server properly validates resource URIs."""
    
    result = client.create_test_result(
        test_id="RES-003",
        test_name="Resource URI Validation",
        category=TestCategory.RESOURCES.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session and check for resources capability
    2. Try to read resources with valid RFC3986 URIs
    3. Try to read resources with invalid URIs
    4. Verify server properly validates and rejects invalid URIs
    """
    
    result.expected_behavior = """
    - Server accepts valid RFC3986 URIs
    - Server rejects invalid URIs with appropriate error
    - Clear error messages for invalid URIs
    - No security vulnerabilities from URI parsing
    """
    
    try:
        # Initialize
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for resources capability
        capabilities = init_result.get('capabilities', {})
        has_resources_capability = 'resources' in capabilities
        
        if not has_resources_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not declare resources capability - test skipped"
            return result
        
        # First, get list of available resources
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }
        
        list_response = await client.send_request(list_request)
        
        if list_response.get('error'):
            result.status = TestStatus.ERROR
            result.actual_behavior = f"Cannot list resources: {list_response['error'].get('message', '')}"
            return result
        
        resources = list_response.get('result', {}).get('resources', [])
        
        # Test various URIs
        test_cases = []
        
        # If we have actual resources, test with the first one
        if resources and resources[0].get('uri'):
            valid_uri = resources[0]['uri']
            
            # Test 1: Valid URI from list
            read_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": {"uri": valid_uri}
            }
            
            try:
                read_response = await client.send_request(read_request)
                valid_uri_works = read_response.get('result') is not None
                test_cases.append(f"Valid URI ({valid_uri}): {'✓ Accepted' if valid_uri_works else '✗ Rejected'}")
            except Exception as e:
                test_cases.append(f"Valid URI ({valid_uri}): Error - {e}")
        
        # Test 2: Invalid URIs that violate RFC3986
        invalid_uris = [
            ("spaces in uri", "URIs cannot contain unencoded spaces"),
            ("http://[invalid", "Invalid IPv6 literal"),
            ("://no-scheme", "Missing URI scheme"),
            ("http://", "Empty authority"),
            ("../relative", "Relative paths not allowed as full URI"),
            ("\x00null\x00byte", "Null bytes not allowed"),
            ("http://example.com/path with spaces", "Unencoded spaces in path")
        ]
        
        for invalid_uri, reason in invalid_uris:
            invalid_request = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {"uri": invalid_uri}
            }
            
            try:
                invalid_response = await client.send_request(invalid_request)
                if invalid_response.get('error'):
                    test_cases.append(f"Invalid URI ({invalid_uri[:20]}...): ✓ Rejected")
                else:
                    test_cases.append(f"Invalid URI ({invalid_uri[:20]}...): ✗ ACCEPTED (should reject: {reason})")
            except Exception:
                test_cases.append(f"Invalid URI ({invalid_uri[:20]}...): ✓ Rejected with exception")
        
        # Analyze results
        security_issues = [tc for tc in test_cases if "✗ ACCEPTED" in tc]
        
        if security_issues:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            URI validation has security issues:
            
            Test results:
            {chr(10).join(test_cases)}
            
            Security vulnerabilities found - server accepts invalid URIs!
            """
            
            result.failure_reason = """
            Server MUST validate all resource URIs according to RFC3986.
            Accepting invalid URIs can lead to security vulnerabilities.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="MEDIUM",
                security="HIGH",
                functionality="MEDIUM",
                description="Invalid URI handling can lead to path traversal or injection attacks"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Implement strict RFC3986 URI validation",
                    "Reject URIs with invalid characters",
                    "Validate URI scheme and structure",
                    "Sanitize and validate all URI components"
                ],
                code_example="""
# Example: URI validation
from urllib.parse import urlparse

def validate_resource_uri(uri: str) -> bool:
    try:
        # Parse URI
        parsed = urlparse(uri)
        
        # Check for required components
        if not parsed.scheme:
            return False
        
        # Check for invalid characters
        if any(c in uri for c in [' ', '\\x00', '\\n', '\\r']):
            return False
        
        # Additional validation...
        return True
    except Exception:
        return False
"""
            )
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            URI validation working correctly:
            
            Test results:
            {chr(10).join(test_cases) if test_cases else 'No resources available to test'}
            
            Server properly validates URIs according to RFC3986.
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="RES-004",
    name="Binary Data Encoding",
    category=TestCategory.RESOURCES,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that binary data MUST be properly encoded when returned from resources.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
    spec_section="Resources",
    spec_requirement="Binary data MUST be properly encoded",
    tags=["resources", "binary", "encoding"],
    timeout=10
)
async def test_binary_data_encoding(client: MCPTestBase) -> TestResult:
    """Test that binary resource data is properly encoded."""
    
    result = client.create_test_result(
        test_id="RES-004",
        test_name="Binary Data Encoding",
        category=TestCategory.RESOURCES.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session and check for resources capability
    2. List available resources
    3. Read any binary resources (e.g., images, files)
    4. Verify binary data is properly base64 encoded
    """
    
    result.expected_behavior = """
    - Binary resources have mimeType indicating binary content
    - Binary data is base64 encoded in contents
    - Base64 data is valid and decodable
    - No raw binary in JSON responses
    """
    
    try:
        # Initialize
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for resources capability
        capabilities = init_result.get('capabilities', {})
        has_resources_capability = 'resources' in capabilities
        
        if not has_resources_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not declare resources capability - test skipped"
            return result
        
        # List resources
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }
        
        list_response = await client.send_request(list_request)
        
        if list_response.get('error'):
            result.status = TestStatus.ERROR
            result.actual_behavior = f"Cannot list resources: {list_response['error'].get('message', '')}"
            return result
        
        resources = list_response.get('result', {}).get('resources', [])
        
        # Look for binary resources (images, pdfs, etc.)
        binary_mime_types = [
            'image/', 'application/pdf', 'application/octet-stream',
            'video/', 'audio/', 'application/zip'
        ]
        
        binary_resources = [
            r for r in resources
            if any(mime in r.get('mimeType', '') for mime in binary_mime_types)
        ]
        
        if not binary_resources:
            # No binary resources to test
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "No binary resources found to test encoding"
            return result
        
        # Test first binary resource
        test_resource = binary_resources[0]
        read_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {"uri": test_resource['uri']}
        }
        
        read_response = await client.send_request(read_request)
        
        if read_response.get('error'):
            result.status = TestStatus.ERROR
            result.actual_behavior = f"Cannot read binary resource: {read_response['error'].get('message', '')}"
            return result
        
        resource_data = read_response.get('result', {})
        contents = resource_data.get('contents', [])
        
        # Check encoding
        issues = []
        for content in contents:
            if content.get('mimeType', '').startswith(tuple(binary_mime_types)):
                # This is binary content
                text_data = content.get('text', '')
                
                # Try to decode as base64
                import base64
                try:
                    decoded = base64.b64decode(text_data, validate=True)
                    # Successfully decoded
                except Exception as e:
                    issues.append(f"Invalid base64 encoding: {e}")
                
                # Check for raw binary (non-ASCII characters)
                try:
                    text_data.encode('ascii')
                except UnicodeEncodeError:
                    issues.append("Binary data contains non-ASCII characters (not base64)")
        
        if issues:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Binary data encoding issues found:
            - Resource: {test_resource['uri']}
            - MIME type: {test_resource.get('mimeType', 'unknown')}
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
            
            result.failure_reason = "Binary data MUST be properly encoded (base64)"
            
            result.remediation = Remediation(
                priority="MEDIUM",
                steps=[
                    "Encode all binary data as base64",
                    "Set appropriate mimeType for binary content",
                    "Validate base64 encoding before sending"
                ],
                code_example="""
# Example: Encoding binary data
import base64

def encode_binary_resource(data: bytes, mime_type: str):
    return {
        "mimeType": mime_type,
        "text": base64.b64encode(data).decode('ascii')
    }
"""
            )
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Binary data properly encoded:
            - Resource: {test_resource['uri']}
            - MIME type: {test_resource.get('mimeType', 'unknown')}
            - Base64 encoding: ✓ Valid
            - No raw binary in response: ✓
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result