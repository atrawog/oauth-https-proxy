"""
Tool notification tests for MCP.

Tests that servers properly implement tool notifications according to:
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="TOOL-006",
    name="Tool List Change Notifications",
    category=TestCategory.TOOLS,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that servers declaring listChanged capability for tools properly
    send notifications when the tool list changes.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Tool Notifications",
    spec_requirement="Servers declaring listChanged SHOULD send notifications when tool list changes",
    tags=["tools", "notifications", "listChanged"],
    timeout=10
)
async def test_tool_list_change_notifications(client: MCPTestBase) -> TestResult:
    """Test that servers properly handle tool list change notifications."""
    
    result = client.create_test_result(
        test_id="TOOL-006",
        test_name="Tool List Change Notifications",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session and check tools capability
    2. Check if server declares listChanged capability for tools
    3. If listChanged declared, verify notification would use correct format
    4. Check consistency between capability and implementation
    5. Document expected notification behavior
    """
    
    result.expected_behavior = """
    - If listChanged: true, server SHOULD send notifications
    - Notification method: notifications/tools/list_changed
    - If listChanged: false or absent, no notifications expected
    - Notifications sent when tools are added, removed, or modified
    - JSON-RPC notification format (no id field)
    """
    
    try:
        # Initialize and check capabilities
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for tools capability and listChanged
        capabilities = init_result.get('capabilities', {})
        tools_capability = capabilities.get('tools', {})
        
        if not tools_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not have tools capability"
            return result
        
        supports_list_changed = tools_capability.get('listChanged', False)
        
        # Test notification format expectations
        if supports_list_changed:
            # Server claims to support list change notifications
            
            # Verify tools/list works (required for listChanged to make sense)
            list_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
            
            list_response = await client.send_request(list_request)
            tools_list_works = not list_response.get('error')
            
            if not tools_list_works:
                result.status = TestStatus.WARNING
                result.actual_behavior = f"""
                Server declares listChanged but tools/list doesn't work:
                - listChanged declared: ✓
                - tools/list error: {list_response.get('error', {}).get('message', '')}
                - Inconsistent: Can't notify about changes if list doesn't work
                """
                
                result.failure_reason = """
                Server declares listChanged capability but tools/list fails.
                This is inconsistent - notifications require a working list method.
                """
            else:
                result.status = TestStatus.PASSED
                result.actual_behavior = f"""
                Server declares listChanged capability correctly:
                - Tools capability: ✓
                - listChanged declared: ✓ ({supports_list_changed})
                - tools/list method: ✓ Working
                - Expected notification method: notifications/tools/list_changed
                - Expected notification format: JSON-RPC notification (no id)
                
                Expected notification structure:
                {{
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed"
                }}
                
                Note: Actual notification delivery cannot be tested without:
                1. Ability to monitor server-sent notifications
                2. Ability to trigger tool list changes (add/remove tools)
                """
                
                # Add evidence
                if result.evidence is None:
                    from ...models.test_results import Evidence
                    result.evidence = Evidence()
                if result.evidence.validation_details is None:
                    result.evidence.validation_details = {}
                result.evidence.validation_details['listChanged'] = supports_list_changed
                result.evidence.validation_details['notification_method'] = 'notifications/tools/list_changed'
                result.evidence.validation_details['tools_list_works'] = tools_list_works
        else:
            # Server doesn't declare listChanged - this is valid
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server correctly does not declare listChanged capability:
            - Tools capability: ✓
            - listChanged: Not declared (notifications not supported)
            - This is valid - tool list change notifications are optional
            - No notifications will be sent when tools change
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="TOOL-007",
    name="Tool Notification Capability Consistency",
    category=TestCategory.TOOLS,
    severity=TestSeverity.LOW,
    description="""
    Validates that tool notification capabilities are consistent with implementation.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Capabilities",
    spec_requirement="Capability declarations should match implementation",
    tags=["tools", "notifications", "capabilities", "consistency"],
    timeout=10
)
async def test_tool_notification_consistency(client: MCPTestBase) -> TestResult:
    """Test that tool notification capabilities match implementation."""
    
    result = client.create_test_result(
        test_id="TOOL-007",
        test_name="Tool Notification Capability Consistency",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.LOW.value
    )
    
    result.methodology = """
    1. Check tools capability declaration
    2. Verify listChanged flag presence and value
    3. Check if tools can actually change (dynamic vs static)
    4. Verify consistency between capability and nature of tools
    5. Provide recommendations based on findings
    """
    
    result.expected_behavior = """
    - Static tool sets: listChanged should be false or absent
    - Dynamic tool sets: listChanged may be true
    - If listChanged: true, tools should be able to change
    - Capability should reflect actual behavior
    """
    
    try:
        # Initialize and check capabilities
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for tools capability
        capabilities = init_result.get('capabilities', {})
        tools_capability = capabilities.get('tools', {})
        
        if not tools_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not have tools capability"
            return result
        
        supports_list_changed = tools_capability.get('listChanged', False)
        
        # Get tool list to analyze
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        list_response = await client.send_request(list_request)
        
        if list_response.get('error'):
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            Cannot analyze tool notification consistency:
            - Tools capability declared: ✓
            - listChanged: {supports_list_changed}
            - tools/list error: {list_response['error'].get('message', '')}
            """
            return result
        
        tools = list_response.get('result', {}).get('tools', [])
        tool_count = len(tools)
        
        # Analyze consistency
        recommendations = []
        
        if supports_list_changed and tool_count == 0:
            recommendations.append("Server declares listChanged but has no tools - consider if this is needed")
        
        if not supports_list_changed and tool_count > 10:
            recommendations.append("Large tool set without listChanged - consider if tools are truly static")
        
        # Check tool names for patterns suggesting dynamic behavior
        dynamic_indicators = ['create', 'delete', 'register', 'add', 'remove', 'dynamic']
        has_dynamic_tools = any(
            any(indicator in tool.get('name', '').lower() for indicator in dynamic_indicators)
            for tool in tools
        )
        
        if has_dynamic_tools and not supports_list_changed:
            recommendations.append("Tools suggest dynamic behavior but listChanged not declared")
        
        if recommendations:
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            Tool notification capability may need review:
            - Tools capability: ✓
            - listChanged declared: {supports_list_changed}
            - Tool count: {tool_count}
            - Has dynamic tool patterns: {has_dynamic_tools}
            
            Recommendations:
            {chr(10).join('• ' + r for r in recommendations)}
            """
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Tool notification capability appears consistent:
            - Tools capability: ✓
            - listChanged declared: {supports_list_changed}
            - Tool count: {tool_count}
            - Configuration appears appropriate for tool set
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result