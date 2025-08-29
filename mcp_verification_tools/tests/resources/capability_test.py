"""
Resources capability tests for MCP.

Tests that servers properly declare and implement resources capability:
https://modelcontextprotocol.io/specification/2025-06-18/server/resources
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="RES-001",
    name="Resources Capability Declaration",
    category=TestCategory.RESOURCES,
    severity=TestSeverity.HIGH,
    description="""
    Validates that servers MUST declare the resources capability if they support resources.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
    spec_section="Resources",
    spec_requirement="Servers MUST declare the resources capability",
    tags=["resources", "capability", "initialization"],
    timeout=10
)
async def test_resources_capability_declaration(client: MCPTestBase) -> TestResult:
    """Test that server properly declares resources capability."""
    
    result = client.create_test_result(
        test_id="RES-001",
        test_name="Resources Capability Declaration",
        category=TestCategory.RESOURCES.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session with the server
    2. Check if server declares resources capability
    3. If resources capability declared, verify resources/list works
    4. If not declared, verify resources/list fails appropriately
    """
    
    result.expected_behavior = """
    - Server declares resources capability if it supports resources
    - If capability declared, resources/list method works
    - If capability not declared, resources methods should fail/not exist
    - Capability declaration matches actual implementation
    """
    
    try:
        # Initialize and check capabilities
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            result.failure_reason = "Cannot test without successful initialization"
            return result
        
        # Check for resources capability
        capabilities = init_result.get('capabilities', {})
        has_resources_capability = 'resources' in capabilities
        resources_capability = capabilities.get('resources', {})
        
        # Try to list resources
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }
        
        try:
            list_response = await client.send_request(list_request)
            resources_list_works = list_response.get('result') is not None
            error_message = list_response.get('error', {}).get('message', '')
        except Exception as e:
            resources_list_works = False
            error_message = str(e)
        
        # Analyze consistency
        if has_resources_capability and resources_list_works:
            # Check if capability details are present
            supports_subscribe = resources_capability.get('subscribe', False)
            supports_list_changed = resources_capability.get('listChanged', False)
            
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Resources capability properly declared and implemented:
            - Resources capability declared: ✓
            - Resources/list method works: ✓
            - Supports subscribe: {'✓' if supports_subscribe else '✗'}
            - Supports list changed: {'✓' if supports_list_changed else '✗'}
            """
        elif not has_resources_capability and not resources_list_works:
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server correctly does not declare resources capability:
            - Resources capability declared: ✗
            - Resources/list method: Fails as expected
            - Consistent behavior: ✓
            """
        elif has_resources_capability and not resources_list_works:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Inconsistent resources capability declaration:
            - Resources capability declared: ✓
            - Resources/list method: Failed ✗
            - Error: {error_message}
            
            Server declares resources capability but doesn't implement it!
            """
            
            result.failure_reason = """
            Server MUST only declare resources capability if it actually implements resources.
            Declaring capability without implementation breaks client expectations.
            """
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Remove resources capability if not implemented",
                    "OR implement resources/list method",
                    "Ensure capability declaration matches implementation"
                ]
            )
        else:  # not has_resources_capability and resources_list_works
            result.status = TestStatus.FAILED
            result.actual_behavior = """
            Server implements resources without declaring capability:
            - Resources capability declared: ✗
            - Resources/list method: Works ✓
            
            Server MUST declare resources capability if it supports resources!
            """
            
            result.failure_reason = """
            Server MUST declare resources capability if it implements resources.
            Clients rely on capability declaration to know which features are available.
            """
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Add resources capability to initialize response",
                    "Include subscribe and listChanged flags if supported"
                ],
                code_example="""
# Example: Declaring resources capability
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "resources": {
                "subscribe": true,  # If subscription supported
                "listChanged": true  # If list change notifications supported
            }
        },
        "serverInfo": {
            "name": "example-server",
            "version": "1.0.0"
        }
    }
}"""
            )
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="RES-002",
    name="Resources List Method",
    category=TestCategory.RESOURCES,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that resources/list method works correctly when resources capability is declared.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
    spec_section="Listing Resources",
    spec_requirement="Resources list should return available resources",
    tags=["resources", "list", "method"],
    timeout=10
)
async def test_resources_list_method(client: MCPTestBase) -> TestResult:
    """Test resources/list method functionality."""
    
    result = client.create_test_result(
        test_id="RES-002",
        test_name="Resources List Method",
        category=TestCategory.RESOURCES.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session and check for resources capability
    2. Call resources/list method
    3. Verify response format and structure
    4. Check pagination if applicable
    """
    
    result.expected_behavior = """
    - resources/list returns result with resources array
    - Each resource has required fields (uri, name, etc.)
    - Pagination works if next_cursor provided
    - Error returned if resources not supported
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
            result.status = TestStatus.FAILED
            result.actual_behavior = f"resources/list returned error: {list_response['error'].get('message', 'Unknown error')}"
            result.failure_reason = "Server declares resources capability but resources/list fails"
            return result
        
        resources_result = list_response.get('result', {})
        resources = resources_result.get('resources', [])
        next_cursor = resources_result.get('nextCursor')
        
        # Check resource structure
        valid_resources = True
        issues = []
        
        for resource in resources:
            # Check required fields
            if 'uri' not in resource:
                valid_resources = False
                issues.append("Resource missing required 'uri' field")
            if 'name' not in resource:
                valid_resources = False
                issues.append("Resource missing required 'name' field")
        
        if valid_resources:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            resources/list working correctly:
            - Response includes resources array: ✓
            - Found {len(resources)} resource(s)
            - All resources have required fields: ✓
            - Pagination cursor: {'Present' if next_cursor else 'Not present'}
            """
        else:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            resources/list has structure issues:
            - Response includes resources array: ✓
            - Found {len(resources)} resource(s)
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
            result.failure_reason = "Resources don't have required fields"
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result