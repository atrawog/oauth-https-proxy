"""
Tools capability tests for MCP.

Tests that servers properly declare and implement tools capability:
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="TOOL-001",
    name="Tools Capability Declaration",
    category=TestCategory.TOOLS,
    severity=TestSeverity.HIGH,
    description="""
    Validates that servers MUST declare the tools capability if they support tools.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Tools",
    spec_requirement="Servers that support tools MUST declare the tools capability",
    tags=["tools", "capability", "initialization"],
    timeout=10
)
async def test_tools_capability_declaration(client: MCPTestBase) -> TestResult:
    """Test that server properly declares tools capability."""
    
    result = client.create_test_result(
        test_id="TOOL-001",
        test_name="Tools Capability Declaration",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session with the server
    2. Check if server declares tools capability
    3. If tools capability declared, verify tools/list works
    4. If not declared, verify tools/list fails appropriately
    5. Check consistency between declaration and implementation
    """
    
    result.expected_behavior = """
    - Server declares tools capability if it supports tools
    - If capability declared, tools/list method works
    - If capability not declared, tools methods should fail/not exist
    - Capability declaration matches actual implementation
    - Optional listChanged flag indicates change notification support
    """
    
    try:
        # Initialize and check capabilities
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            result.failure_reason = "Cannot test without successful initialization"
            return result
        
        # Check for tools capability
        capabilities = init_result.get('capabilities', {})
        has_tools_capability = 'tools' in capabilities
        tools_capability = capabilities.get('tools', {})
        
        # Try to list tools
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        try:
            list_response = await client.send_request(list_request)
            tools_list_works = list_response.get('result') is not None
            error_message = list_response.get('error', {}).get('message', '')
        except Exception as e:
            tools_list_works = False
            error_message = str(e)
        
        # Analyze consistency
        if has_tools_capability and tools_list_works:
            # Check capability details
            supports_list_changed = tools_capability.get('listChanged', False)
            
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Tools capability properly declared and implemented:
            - Tools capability declared: ✓
            - Tools/list method works: ✓
            - Supports list changed notifications: {'✓' if supports_list_changed else '✗'}
            - Consistent behavior: ✓
            """
        elif not has_tools_capability and not tools_list_works:
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server correctly does not declare tools capability:
            - Tools capability declared: ✗
            - Tools/list method: Fails as expected
            - Consistent behavior: ✓
            """
        elif has_tools_capability and not tools_list_works:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Inconsistent tools capability declaration:
            - Tools capability declared: ✓
            - Tools/list method: Failed ✗
            - Error: {error_message}
            
            Server declares tools capability but doesn't implement it!
            """
            
            result.failure_reason = """
            Server MUST only declare tools capability if it actually implements tools.
            Declaring capability without implementation breaks client expectations.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="LOW",
                functionality="HIGH",
                description="Clients will expect tools to work but calls will fail"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Remove tools capability if not implemented",
                    "OR implement tools/list method",
                    "Ensure capability declaration matches implementation"
                ],
                code_example="""
# Example: Declaring tools capability
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "tools": {
                "listChanged": true  # If tool list change notifications supported
            }
        },
        "serverInfo": {
            "name": "example-server",
            "version": "1.0.0"
        }
    }
}"""
            )
        else:  # not has_tools_capability and tools_list_works
            result.status = TestStatus.FAILED
            result.actual_behavior = """
            Server implements tools without declaring capability:
            - Tools capability declared: ✗
            - Tools/list method: Works ✓
            
            Server MUST declare tools capability if it supports tools!
            """
            
            result.failure_reason = """
            Server MUST declare tools capability if it implements tools.
            Clients rely on capability declaration to know which features are available.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="LOW",
                functionality="HIGH",
                description="Clients won't know tools are available"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Add tools capability to initialize response",
                    "Include listChanged flag if change notifications supported"
                ]
            )
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result