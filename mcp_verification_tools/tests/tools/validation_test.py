"""
Tool parameter validation tests for MCP.

Tests that tool parameters are properly validated according to:
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from typing import Any, Dict
from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="TOOL-005",
    name="Tool Parameter Validation",
    category=TestCategory.TOOLS,
    severity=TestSeverity.HIGH,
    description="""
    Validates that tool parameters are properly validated against their input schemas.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/tools",
    spec_section="Tool Parameters",
    spec_requirement="Servers MUST validate tool inputs against inputSchema",
    tags=["tools", "validation", "parameters", "schema"],
    timeout=10
)
async def test_tool_parameter_validation(client: MCPTestBase) -> TestResult:
    """Test that tool parameters are validated against input schemas."""
    
    result = client.create_test_result(
        test_id="TOOL-005",
        test_name="Tool Parameter Validation",
        category=TestCategory.TOOLS.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session and list available tools
    2. For each tool with inputSchema:
       - Test with valid parameters matching schema
       - Test with wrong types
       - Test with missing required fields
       - Test with extra fields (if additionalProperties: false)
    3. Verify proper validation errors are returned
    """
    
    result.expected_behavior = """
    - Valid parameters are accepted
    - Invalid types are rejected with error
    - Missing required fields are rejected
    - Extra fields handled per schema rules
    - Clear validation error messages
    - Consistent error codes (-32602 for invalid params)
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
        
        # Find a tool with clear schema to test
        test_tool = None
        for tool in tools:
            schema = tool.get('inputSchema', {})
            if schema.get('type') == 'object' and schema.get('properties'):
                test_tool = tool
                break
        
        if not test_tool:
            # Try any tool
            test_tool = tools[0]
        
        tool_name = test_tool['name']
        input_schema = test_tool.get('inputSchema', {})
        
        validation_results = []
        issues = []
        
        # Test cases based on schema
        if input_schema.get('type') == 'object':
            properties = input_schema.get('properties', {})
            required = input_schema.get('required', [])
            additional_properties = input_schema.get('additionalProperties', True)
            
            # Test 1: Valid parameters
            valid_params = {}
            for prop_name, prop_schema in properties.items():
                if prop_name in required:
                    # Generate valid value based on type
                    prop_type = prop_schema.get('type')
                    if prop_type == 'string':
                        valid_params[prop_name] = "test_value"
                    elif prop_type == 'number':
                        valid_params[prop_name] = 42
                    elif prop_type == 'integer':
                        valid_params[prop_name] = 10
                    elif prop_type == 'boolean':
                        valid_params[prop_name] = True
                    elif prop_type == 'array':
                        valid_params[prop_name] = []
                    elif prop_type == 'object':
                        valid_params[prop_name] = {}
                    else:
                        valid_params[prop_name] = "test"
            
            # Call with valid parameters
            valid_call = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": valid_params
                }
            }
            
            try:
                valid_response = await client.send_request(valid_call)
                if valid_response.get('error'):
                    error_code = valid_response['error'].get('code')
                    if error_code == -32602:
                        validation_results.append("Valid params rejected (might be tool-specific logic)")
                    else:
                        validation_results.append(f"Valid params error: {valid_response['error'].get('message', '')}")
                else:
                    validation_results.append("Valid parameters accepted ✓")
            except Exception as e:
                validation_results.append(f"Valid params exception: {e}")
            
            # Test 2: Wrong type for a field
            if required and properties:
                wrong_type_params = dict(valid_params)
                first_required = required[0]
                first_prop = properties.get(first_required, {})
                
                # Intentionally use wrong type
                if first_prop.get('type') == 'string':
                    wrong_type_params[first_required] = 123  # Number instead of string
                elif first_prop.get('type') in ['number', 'integer']:
                    wrong_type_params[first_required] = "not_a_number"  # String instead of number
                else:
                    wrong_type_params[first_required] = None  # Null for any type
                
                wrong_type_call = {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": wrong_type_params
                    }
                }
                
                try:
                    wrong_response = await client.send_request(wrong_type_call)
                    if wrong_response.get('error'):
                        error_code = wrong_response['error'].get('code')
                        if error_code == -32602:
                            validation_results.append("Wrong type properly rejected ✓")
                        else:
                            validation_results.append(f"Wrong type error code: {error_code}")
                    else:
                        issues.append(f"Wrong type accepted for {first_required} (should reject)")
                except Exception:
                    validation_results.append("Wrong type properly rejected with exception ✓")
            
            # Test 3: Missing required field
            if required:
                missing_params = {}
                for prop_name in required[1:]:  # Skip first required field
                    if prop_name in valid_params:
                        missing_params[prop_name] = valid_params[prop_name]
                
                missing_call = {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": missing_params
                    }
                }
                
                try:
                    missing_response = await client.send_request(missing_call)
                    if missing_response.get('error'):
                        error_code = missing_response['error'].get('code')
                        if error_code == -32602:
                            validation_results.append("Missing required field properly rejected ✓")
                        else:
                            validation_results.append(f"Missing field error code: {error_code}")
                    else:
                        # Check if tool handles it with isError
                        if missing_response.get('result', {}).get('isError'):
                            validation_results.append("Missing field handled with isError flag")
                        else:
                            issues.append(f"Missing required field accepted (should reject)")
                except Exception:
                    validation_results.append("Missing required field properly rejected ✓")
            
            # Test 4: Extra fields (if additionalProperties: false)
            if not additional_properties:
                extra_params = dict(valid_params)
                extra_params['extra_field_12345'] = "should_not_be_allowed"
                
                extra_call = {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": extra_params
                    }
                }
                
                try:
                    extra_response = await client.send_request(extra_call)
                    if extra_response.get('error'):
                        validation_results.append("Extra fields properly rejected ✓")
                    else:
                        issues.append("Extra fields accepted when additionalProperties: false")
                except Exception:
                    validation_results.append("Extra fields properly rejected ✓")
        
        # Determine status
        if issues and not validation_results:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Parameter validation not working:
            - Tool tested: {tool_name}
            - Schema type: {input_schema.get('type', 'unknown')}
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
            
            result.failure_reason = "Tool parameters not properly validated"
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="HIGH",
                functionality="HIGH",
                description="Invalid parameters could cause errors or security issues"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Implement JSON Schema validation for tool inputs",
                    "Return -32602 error code for invalid parameters",
                    "Provide clear validation error messages",
                    "Validate types, required fields, and schema constraints"
                ]
            )
        elif issues:
            result.status = TestStatus.WARNING
            result.actual_behavior = f"""
            Parameter validation partially working:
            - Tool tested: {tool_name}
            
            Working:
            {chr(10).join('• ' + v for v in validation_results)}
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Parameter validation working correctly:
            - Tool tested: {tool_name}
            - Schema type: {input_schema.get('type', 'unknown')}
            - Required fields: {', '.join(required) if required else 'none'}
            
            Validation results:
            {chr(10).join('• ' + v for v in validation_results)}
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result