"""
Prompts capability tests for MCP.

Tests that servers properly declare and implement prompts capability:
https://modelcontextprotocol.io/specification/2025-06-18/server/prompts
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="PROMPT-001",
    name="Prompts Capability Declaration",
    category=TestCategory.PROMPTS,
    severity=TestSeverity.HIGH,
    description="""
    Validates that servers MUST declare the prompts capability if they support prompts.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/prompts",
    spec_section="Prompts",
    spec_requirement="Servers that support prompts MUST declare the prompts capability",
    tags=["prompts", "capability", "initialization"],
    timeout=10
)
async def test_prompts_capability_declaration(client: MCPTestBase) -> TestResult:
    """Test that server properly declares prompts capability."""
    
    result = client.create_test_result(
        test_id="PROMPT-001",
        test_name="Prompts Capability Declaration",
        category=TestCategory.PROMPTS.value,
        severity=TestSeverity.HIGH.value
    )
    
    result.methodology = """
    1. Initialize session with the server
    2. Check if server declares prompts capability
    3. If prompts capability declared, verify prompts/list works
    4. If not declared, verify prompts/list fails appropriately
    5. Check consistency between declaration and implementation
    """
    
    result.expected_behavior = """
    - Server declares prompts capability if it supports prompts
    - If capability declared, prompts/list method works
    - If capability not declared, prompts methods should fail/not exist
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
        
        # Check for prompts capability
        capabilities = init_result.get('capabilities', {})
        has_prompts_capability = 'prompts' in capabilities
        prompts_capability = capabilities.get('prompts', {})
        
        # Try to list prompts
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "prompts/list",
            "params": {}
        }
        
        try:
            list_response = await client.send_request(list_request)
            prompts_list_works = list_response.get('result') is not None
            error_message = list_response.get('error', {}).get('message', '')
        except Exception as e:
            prompts_list_works = False
            error_message = str(e)
        
        # Analyze consistency
        if has_prompts_capability and prompts_list_works:
            # Check capability details
            supports_list_changed = prompts_capability.get('listChanged', False)
            
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Prompts capability properly declared and implemented:
            - Prompts capability declared: ✓
            - Prompts/list method works: ✓
            - Supports list changed notifications: {'✓' if supports_list_changed else '✗'}
            - Consistent behavior: ✓
            """
        elif not has_prompts_capability and not prompts_list_works:
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server correctly does not declare prompts capability:
            - Prompts capability declared: ✗
            - Prompts/list method: Fails as expected
            - Consistent behavior: ✓
            """
        elif has_prompts_capability and not prompts_list_works:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            Inconsistent prompts capability declaration:
            - Prompts capability declared: ✓
            - Prompts/list method: Failed ✗
            - Error: {error_message}
            
            Server declares prompts capability but doesn't implement it!
            """
            
            result.failure_reason = """
            Server MUST only declare prompts capability if it actually implements prompts.
            Declaring capability without implementation breaks client expectations.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="LOW",
                functionality="MEDIUM",
                description="Clients will expect prompts to work but calls will fail"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Remove prompts capability if not implemented",
                    "OR implement prompts/list method",
                    "Ensure capability declaration matches implementation"
                ],
                code_example="""
# Example: Declaring prompts capability
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "prompts": {
                "listChanged": true  # If prompt list change notifications supported
            }
        },
        "serverInfo": {
            "name": "example-server",
            "version": "1.0.0"
        }
    }
}"""
            )
        else:  # not has_prompts_capability and prompts_list_works
            result.status = TestStatus.FAILED
            result.actual_behavior = """
            Server implements prompts without declaring capability:
            - Prompts capability declared: ✗
            - Prompts/list method: Works ✓
            
            Server MUST declare prompts capability if it supports prompts!
            """
            
            result.failure_reason = """
            Server MUST declare prompts capability if it implements prompts.
            Clients rely on capability declaration to know which features are available.
            """
            
            result.impact_assessment = ImpactAssessment(
                compatibility="HIGH",
                security="LOW",
                functionality="MEDIUM",
                description="Clients won't know prompts are available"
            )
            
            result.remediation = Remediation(
                priority="HIGH",
                steps=[
                    "Add prompts capability to initialize response",
                    "Include listChanged flag if change notifications supported"
                ]
            )
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="PROMPT-002",
    name="Prompts List Method",
    category=TestCategory.PROMPTS,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that prompts/list method returns proper structure with required fields.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/prompts",
    spec_section="Listing Prompts",
    spec_requirement="prompts/list must return prompts array with required fields",
    tags=["prompts", "list", "method"],
    timeout=10
)
async def test_prompts_list_method(client: MCPTestBase) -> TestResult:
    """Test prompts/list method functionality and structure."""
    
    result = client.create_test_result(
        test_id="PROMPT-002",
        test_name="Prompts List Method",
        category=TestCategory.PROMPTS.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session and check for prompts capability
    2. Call prompts/list method
    3. Verify response structure and required fields
    4. Check each prompt has name (required) and optional fields
    5. Check pagination if applicable
    """
    
    result.expected_behavior = """
    - prompts/list returns result with prompts array
    - Each prompt has required field: name (unique identifier)
    - Optional fields properly structured: title, description, arguments
    - Pagination works if nextCursor provided
    - No duplicate prompt names
    """
    
    try:
        # Initialize
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for prompts capability
        capabilities = init_result.get('capabilities', {})
        has_prompts_capability = 'prompts' in capabilities
        
        if not has_prompts_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not declare prompts capability - test skipped"
            return result
        
        # List prompts
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "prompts/list",
            "params": {}
        }
        
        list_response = await client.send_request(list_request)
        
        if list_response.get('error'):
            # Check if it's a method implementation issue
            error = list_response.get('error', {})
            if error.get('code') in [-32601, -32602]:
                result.status = TestStatus.WARNING
                result.actual_behavior = f"""
                Server declares prompts capability but prompts/list not implemented:
                - Error: {error.get('message', 'Unknown error')}
                - This is inconsistent with capability declaration
                """
                return result
            
            result.status = TestStatus.FAILED
            result.actual_behavior = f"prompts/list returned error: {error.get('message', 'Unknown error')}"
            result.failure_reason = "Server declares prompts capability but prompts/list fails"
            return result
        
        prompts_result = list_response.get('result', {})
        prompts = prompts_result.get('prompts', [])
        next_cursor = prompts_result.get('nextCursor')
        
        # Check prompt structure
        issues = []
        prompt_names = set()
        
        for i, prompt in enumerate(prompts):
            # Check required fields
            if 'name' not in prompt:
                issues.append(f"Prompt {i} missing required 'name' field")
            else:
                # Check for duplicate names
                if prompt['name'] in prompt_names:
                    issues.append(f"Duplicate prompt name: {prompt['name']}")
                prompt_names.add(prompt['name'])
            
            # Check optional fields structure if present
            if 'arguments' in prompt:
                arguments = prompt['arguments']
                if not isinstance(arguments, list):
                    issues.append(f"Prompt {prompt.get('name', f'#{i}')} arguments is not an array")
                else:
                    for arg in arguments:
                        if not isinstance(arg, dict):
                            issues.append(f"Prompt {prompt.get('name', f'#{i}')} has invalid argument structure")
                        elif 'name' not in arg:
                            issues.append(f"Prompt {prompt.get('name', f'#{i}')} argument missing name")
        
        if not prompts and not issues:
            # No prompts available
            result.status = TestStatus.WARNING
            result.actual_behavior = """
            Server has prompts capability but no prompts available:
            - Prompts array is empty
            - Consider if prompts capability should be declared
            """
        elif issues:
            result.status = TestStatus.FAILED
            result.actual_behavior = f"""
            prompts/list has structure issues:
            - Response includes prompts array: ✓
            - Found {len(prompts)} prompt(s)
            
            Issues:
            {chr(10).join('• ' + i for i in issues)}
            """
            
            result.failure_reason = "Prompts don't have required fields or proper structure"
            
            result.impact_assessment = ImpactAssessment(
                compatibility="MEDIUM",
                security="LOW",
                functionality="MEDIUM",
                description="Clients cannot properly discover or use prompts"
            )
            
            result.remediation = Remediation(
                priority="MEDIUM",
                steps=[
                    "Ensure each prompt has unique name field",
                    "Validate argument structure if provided",
                    "Add optional title and description for clarity"
                ],
                code_example="""
# Example: Proper prompt structure
{
    "prompts": [
        {
            "name": "code_review",
            "title": "Code Review",  # Optional
            "description": "Reviews code for quality and issues",  # Optional
            "arguments": [  # Optional
                {
                    "name": "language",
                    "title": "Programming Language",
                    "description": "The language of the code",
                    "required": true
                }
            ]
        }
    ]
}"""
            )
        else:
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            prompts/list working correctly:
            - Response includes prompts array: ✓
            - Found {len(prompts)} prompt(s)
            - All prompts have required fields: ✓
            - Prompt names are unique: ✓
            - Pagination cursor: {'Present' if next_cursor else 'Not present'}
            """
            
            # Add evidence of prompts found
            if result.evidence is None:
                from ...models.test_results import Evidence
                result.evidence = Evidence()
            if result.evidence.validation_details is None:
                result.evidence.validation_details = {}
            result.evidence.validation_details['prompt_names'] = list(prompt_names)[:10]  # First 10 prompts
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result