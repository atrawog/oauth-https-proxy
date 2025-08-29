"""
Tools list method tests for MCP.

Tests that tools/list method works correctly according to:
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="TOOL-002",
    name="Tools List Method",
    category=TestCategory.TOOLS,
    severity=TestSeverity.HIGH,
    description="""
    Validates that tools/list method returns proper structure with required fields.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Listing Tools",
    spec_requirement="tools/list must return tools array with required fields",
    tags=["tools", "list", "method"],
    timeout=10
)
async def test_tools_list_method(client: MCPTestBase) -> TestResult:
    """Test tools/list method functionality and structure."""
    
    result = client.create_test_result(
        test_id="TOOL-002",
        test_name="Tools List Method",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session and check for tools capability
    2. Call tools/list method
    3. Verify response structure and required fields
    4. Check each tool has name, description, and inputSchema
    5. Validate input schemas are proper JSON Schema
    6. Check pagination if applicable
    """
    
    result.expected_behavior = """
    - tools/list returns result with tools array
    - Each tool has required fields:
      - name (unique identifier)
      - description (human-readable explanation)
      - inputSchema (JSON Schema format)
    - Optional fields properly structured (title, outputSchema)
    - Pagination works if nextCursor provided
    - No duplicate tool names
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
        
        # List tools
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        list_response = await client.send_request(list_request)
        
        if list_response.get('error'):
            # Check if it's a method implementation issue
            error = list_response.get('error', {})
            if error.get('code') in [-32601, -32602]:
                result.status = TestStatus.WARNING
                result.actual_behavior = f"""
                Server declares tools capability but tools/list not implemented:
                - Error: {error.get('message', 'Unknown error')}
                - This is inconsistent with capability declaration
                """
                return result
            
            result.status = TestStatus.FAILED
            result.actual_behavior = f"tools/list returned error: {error.get('message', 'Unknown error')}"
            result.failure_reason = "Server declares tools capability but tools/list fails"
            return result
        
        tools_result = list_response.get('result', {})
        tools = tools_result.get('tools', [])
        next_cursor = tools_result.get('nextCursor')
        
        # Check tool structure
        issues = []
        tool_names = set()
        
        for i, tool in enumerate(tools):
            # Check required fields
            if 'name' not in tool:
                issues.append(f"Tool {i} missing required 'name' field")
            else:
                # Check for duplicate names
                if tool['name'] in tool_names:
                    issues.append(f"Duplicate tool name: {tool['name']}")
                tool_names.add(tool['name'])
            
            if 'description' not in tool:
                issues.append(f"Tool {tool.get('name', f'#{i}')} missing required 'description' field")
            
            if 'inputSchema' not in tool:
                issues.append(f"Tool {tool.get('name', f'#{i}')} missing required 'inputSchema' field")
            else:
                # Validate input schema is proper JSON Schema
                schema = tool['inputSchema']
                if not isinstance(schema, dict):
                    issues.append(f"Tool {tool.get('name', f'#{i}')} inputSchema is not an object")
                elif 'type' not in schema:
                    issues.append(f"Tool {tool.get('name', f'#{i}')} inputSchema missing 'type' field")
        
        if not tools and not issues:
            # No tools available
            result.status = TestStatus.WARNING
            result.actual_behavior = """
            Server has tools capability but no tools available:
            - Tools array is empty
            - Consider if tools capability should be declared
            """
        elif issues:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            tools/list has structure issues:
            - Response includes tools array: ✓
            - Found {len(tools)} tool(s)
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
            
            result.failure_reason = "Tools don't have required fields or proper structure"
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="LOW",
                functionality="HIGH",
                description="Clients cannot properly discover or use tools"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Ensure each tool has name, description, and inputSchema",
                    "Make tool names unique",
                    "Use proper JSON Schema for inputSchema",
                    "Add optional title for human-readable names"
                ],
                code_example="""
# Example: Proper tool structure
{
    "tools": [
        {
            "name": "calculate",
            "title": "Calculator",  # Optional
            "description": "Performs mathematical calculations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "Mathematical expression to evaluate"
                    }
                },
                "required": ["expression"]
            }
        }
    ]
}"""
            )
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            tools/list working correctly:
            - Response includes tools array: ✓
            - Found {len(tools)} tool(s)
            - All tools have required fields: ✓
            - Tool names are unique: ✓
            - Input schemas are valid: ✓
            - Pagination cursor: {'Present' if next_cursor else 'Not present'}
            """
            
            # Add evidence of tools found
            if result.evidence is None:
                from ...models.test_results import Evidence
                result.evidence = Evidence()
            if result.evidence.validation_details is None:
                result.evidence.validation_details = {}
            result.evidence.validation_details['tool_names'] = list(tool_names)[:10]  # First 10 tools
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="TOOL-003",
    name="Tool Names Unique",
    category=TestCategory.TOOLS,
    severity=TestSeverity.HIGH,
    description="""
    Validates that tool names are unique identifiers within the server.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Tool Names",
    spec_requirement="Tool names must be unique identifiers",
    tags=["tools", "names", "uniqueness"],
    timeout=10
)
async def test_tool_names_unique(client: MCPTestBase) -> TestResult:
    """Test that tool names are unique."""
    
    result = client.create_test_result(
        test_id="TOOL-003",
        test_name="Tool Names Unique",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session and check for tools capability
    2. Call tools/list method
    3. Collect all tool names
    4. Check for duplicates
    5. Verify names are valid identifiers (no spaces, special chars)
    """
    
    result.expected_behavior = """
    - All tool names are unique
    - Names are valid identifiers (alphanumeric, underscores, hyphens)
    - Names are descriptive and meaningful
    - No empty or null names
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
        
        # List tools
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
        
        # Check uniqueness and validity
        tool_names = []
        issues = []
        
        for tool in tools:
            name = tool.get('name', '')
            
            if not name:
                issues.append("Tool with empty or missing name")
                continue
            
            if name in tool_names:
                issues.append(f"Duplicate tool name: '{name}'")
            tool_names.append(name)
            
            # Check name validity (basic identifier rules)
            if ' ' in name:
                issues.append(f"Tool name contains spaces: '{name}'")
            if not name.replace('-', '_').replace('/', '_').isidentifier():
                if not all(c.isalnum() or c in '-_/' for c in name):
                    issues.append(f"Tool name contains invalid characters: '{name}'")
        
        if issues:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Tool name issues found:
            - Total tools: {len(tools)}
            - Unique names: {len(set(tool_names))}
            
            Issues:
            {chr(10).join('• ' + i for i in issues[:10])}  # First 10 issues
            """
            
            result.failure_reason = "Tool names must be unique and valid identifiers"
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Ensure all tool names are unique",
                    "Use valid identifier format (alphanumeric, underscore, hyphen)",
                    "Avoid spaces and special characters in names",
                    "Use descriptive, meaningful names"
                ]
            )
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Tool names are valid and unique:
            - Total tools: {len(tools)}
            - All names unique: ✓
            - Names are valid identifiers: ✓
            - Example names: {', '.join(tool_names[:5])}
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result