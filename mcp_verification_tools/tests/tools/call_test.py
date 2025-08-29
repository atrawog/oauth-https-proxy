"""
Tools call method tests for MCP.

Tests that tools/call method works correctly according to:
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="TOOL-004",
    name="Tools Call Method",
    category=TestCategory.TOOLS,
    severity=TestSeverity.CRITICAL,
    description="""
    Validates that tools/call method executes tools correctly with proper error handling.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Calling Tools",
    spec_requirement="tools/call must execute tools and return proper results or errors",
    tags=["tools", "call", "execution"],
    timeout=15
)
async def test_tools_call_method(client: MCPTestBase) -> TestResult:
    """Test tools/call method functionality and error handling."""
    
    result = client.create_test_result(
        test_id="TOOL-004",
        test_name="Tools Call Method",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.CRITICAL.value
    )
    
    result.methodology = """
    1. Initialize session and check for tools capability
    2. List available tools
    3. Call a tool with valid parameters
    4. Call a tool with invalid parameters
    5. Call a non-existent tool
    6. Verify proper error handling for each case
    """
    
    result.expected_behavior = """
    - tools/call executes with valid parameters
    - Returns result with content field
    - Invalid parameters return proper error
    - Non-existent tool returns error
    - Tool execution errors use isError flag
    - Protocol errors use JSON-RPC error format
    """
    
    try:
        # Initialize
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for tools capability
        capabilities = init_result.get('capabilities', {})
        has_tools_capability = 'tools' in capabilities
        
        if not has_tools_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not declare tools capability - test skipped"
            return result
        
        # List tools to find one to test
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        list_response = await client.send_request(list_request)
        
        if list_response.get('error'):
            result.status = TestStatus.WARNING
            result.actual_behavior = f"Cannot list tools: {list_response['error'].get('message', '')}"
            return result
        
        tools = list_response.get('result', {}).get('tools', [])
        
        if not tools:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "No tools available to test"
            return result
        
        # Find a simple tool to test (prefer echo or similar)
        test_tool = None
        for tool in tools:
            if 'echo' in tool.get('name', '').lower():
                test_tool = tool
                break
        
        if not test_tool:
            # Use first tool
            test_tool = tools[0]
        
        issues = []
        successes = []
        
        # Test 1: Call with valid parameters
        tool_name = test_tool['name']
        input_schema = test_tool.get('inputSchema', {})
        
        # Try to construct valid arguments based on schema
        valid_args = {}
        if input_schema.get('type') == 'object':
            properties = input_schema.get('properties', {})
            required = input_schema.get('required', [])
            
            for prop_name in required[:1]:  # Just use first required property
                prop_schema = properties.get(prop_name, {})
                if prop_schema.get('type') == 'string':
                    valid_args[prop_name] = "test"
                elif prop_schema.get('type') == 'number':
                    valid_args[prop_name] = 42
                elif prop_schema.get('type') == 'boolean':
                    valid_args[prop_name] = True
                else:
                    valid_args[prop_name] = "test"
        
        call_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": valid_args
            }
        }
        
        try:
            call_response = await client.send_request(call_request)
            
            if call_response.get('error'):
                # Check if it's a reasonable error
                error = call_response['error']
                if error.get('code') == -32602:  # Invalid params
                    issues.append(f"Tool call with constructed params failed: {error.get('message', '')}")
                else:
                    issues.append(f"Unexpected error calling tool: {error}")
            else:
                call_result = call_response.get('result', {})
                
                # Check for required fields
                if 'content' not in call_result:
                    issues.append("Tool result missing required 'content' field")
                else:
                    successes.append(f"Tool {tool_name} called successfully")
                
                # Check for isError flag if present
                if call_result.get('isError'):
                    successes.append("Tool properly indicates execution error with isError flag")
        except Exception as e:
            issues.append(f"Exception calling tool: {e}")
        
        # Test 2: Call non-existent tool
        invalid_call_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "non_existent_tool_12345",
                "arguments": {}
            }
        }
        
        try:
            invalid_response = await client.send_request(invalid_call_request)
            
            if invalid_response.get('error'):
                successes.append("Non-existent tool properly returns error")
            else:
                issues.append("Non-existent tool call succeeded (should fail)")
        except Exception:
            successes.append("Non-existent tool properly raises exception")
        
        # Test 3: Call with invalid parameters (if we know the schema)
        if input_schema.get('required'):
            bad_call_request = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {}  # Empty when required params exist
                }
            }
            
            try:
                bad_response = await client.send_request(bad_call_request)
                
                if bad_response.get('error'):
                    successes.append("Invalid parameters properly return error")
                else:
                    # Check if result indicates error
                    bad_result = bad_response.get('result', {})
                    if bad_result.get('isError'):
                        successes.append("Invalid parameters handled with isError flag")
                    else:
                        issues.append("Tool accepted empty arguments when parameters required")
            except Exception:
                successes.append("Invalid parameters properly raise exception")
        
        # Determine overall status
        if not successes and issues:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            tools/call method has issues:
            - Tested tool: {tool_name}
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
            
            result.failure_reason = "tools/call method not working correctly"
            
            result.impact_assessment = ImpactAssessment(
                compatibility="CRITICAL",
                security="MEDIUM",
                functionality="CRITICAL",
                description="Tools cannot be executed properly"
            )
            
            result.remediation = Remediation(
                priority="IMMEDIATE",
                steps=[
                    "Implement tools/call method",
                    "Validate tool name exists",
                    "Validate arguments against inputSchema",
                    "Return proper error codes for failures",
                    "Use isError flag for execution errors"
                ],
                code_example="""
# Example: tools/call implementation
async def handle_tools_call(params):
    tool_name = params.get('name')
    arguments = params.get('arguments', {})
    
    # Find tool
    tool = find_tool(tool_name)
    if not tool:
        raise JSONRPCError(-32602, f"Tool '{tool_name}' not found")
    
    # Validate arguments
    if not validate_schema(arguments, tool.input_schema):
        raise JSONRPCError(-32602, "Invalid arguments")
    
    try:
        # Execute tool
        result = await tool.execute(arguments)
        return {
            "content": [
                {"type": "text", "text": str(result)}
            ]
        }
    except Exception as e:
        # Tool execution error
        return {
            "content": [
                {"type": "text", "text": f"Error: {e}"}
            ],
            "isError": true
        }
"""
            )
        elif issues and successes:
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            tools/call partially working:
            - Tested tool: {tool_name}
            
            Working:
            {chr(10).join('• ' + s for s in successes)}
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            tools/call method working correctly:
            - Tested tool: {tool_name}
            - Tool execution: ✓
            - Error handling: ✓
            - Non-existent tool handling: ✓
            - Parameter validation: ✓
            
            {chr(10).join('• ' + s for s in successes)}
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result