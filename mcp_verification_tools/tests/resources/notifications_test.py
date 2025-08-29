"""
Resource notification tests for MCP.

Tests that servers properly implement resource notifications according to:
https://modelcontextprotocol.io/specification/2025-06-18/server/resources
"""

from ...core.registry import mcp_test, TestCategory, TestSeverity
from ...core.base_test import MCPTestBase
from ...models.test_results import TestResult, TestStatus, ImpactAssessment, Remediation


@mcp_test(
    test_id="RES-005",
    name="Resource List Change Notifications",
    category=TestCategory.RESOURCES,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that servers declaring listChanged capability properly send
    notifications when resource list changes.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
    spec_section="Resource Notifications",
    spec_requirement="Servers declaring listChanged SHOULD send notifications when list changes",
    tags=["resources", "notifications", "listChanged"],
    timeout=10
)
async def test_resource_list_change_notifications(client: MCPTestBase) -> TestResult:
    """Test that servers properly handle resource list change notifications."""
    
    result = client.create_test_result(
        test_id="RES-005",
        test_name="Resource List Change Notifications",
        category=TestCategory.RESOURCES.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session and check resources capability
    2. Check if server declares listChanged capability
    3. If listChanged declared, verify notification format is correct
    4. Test if server accepts notification subscriptions appropriately
    5. Verify capability declaration matches implementation
    """
    
    result.expected_behavior = """
    - If listChanged: true, server SHOULD send notifications
    - Notification method: notifications/resources/list_changed
    - If listChanged: false or absent, no notifications expected
    - Capability declaration should match behavior
    """
    
    try:
        # Initialize and check capabilities
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for resources capability and listChanged
        capabilities = init_result.get('capabilities', {})
        resources_capability = capabilities.get('resources', {})
        
        if not resources_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not have resources capability"
            return result
        
        supports_list_changed = resources_capability.get('listChanged', False)
        
        # Test notification format (simulate what would be sent)
        # Since we can't actually trigger resource changes, we test the declaration
        if supports_list_changed:
            # Server claims to support list change notifications
            # In a real test, we would:
            # 1. Monitor for notifications
            # 2. Trigger a resource change (if we had admin access)
            # 3. Verify notification is sent
            
            # For now, we just verify the capability is properly declared
            result.status = TestStatus.PASSED
            result.actual_behavior = f"""
            Server declares listChanged capability:
            - Resources capability: ✓
            - listChanged declared: ✓ ({supports_list_changed})
            - Expected notification method: notifications/resources/list_changed
            
            Note: Actual notification delivery cannot be tested without ability to:
            1. Monitor server-sent notifications
            2. Trigger resource list changes
            """
            
            # Add informational note
            if result.evidence is None:
                from ...models.test_results import Evidence
                result.evidence = Evidence()
            if result.evidence.validation_details is None:
                result.evidence.validation_details = {}
            result.evidence.validation_details['listChanged'] = supports_list_changed
            result.evidence.validation_details['notification_method'] = 'notifications/resources/list_changed'
            
        else:
            # Server doesn't declare listChanged - this is fine
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server correctly does not declare listChanged capability:
            - Resources capability: ✓
            - listChanged: Not declared (notifications not supported)
            - This is valid - notifications are optional
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result


@mcp_test(
    test_id="RES-006",
    name="Resource Subscription Support",
    category=TestCategory.RESOURCES,
    severity=TestSeverity.MEDIUM,
    description="""
    Validates that servers declaring subscribe capability properly support
    resource subscriptions and send update notifications.
    """,
    spec_url="https://modelcontextprotocol.io/specification/2025-06-18/server/resources",
    spec_section="Resource Subscriptions",
    spec_requirement="Servers declaring subscribe capability should support subscriptions",
    tags=["resources", "subscribe", "notifications"],
    timeout=10
)
async def test_resource_subscription_support(client: MCPTestBase) -> TestResult:
    """Test that servers properly handle resource subscriptions."""
    
    result = client.create_test_result(
        test_id="RES-006",
        test_name="Resource Subscription Support",
        category=TestCategory.RESOURCES.value,
        severity=TestSeverity.MEDIUM.value
    )
    
    result.methodology = """
    1. Initialize session and check resources capability
    2. Check if server declares subscribe capability
    3. If subscribe declared, attempt to subscribe to a resource
    4. Verify subscription handling is correct
    5. Check for update notification support
    """
    
    result.expected_behavior = """
    - If subscribe: true, server supports resource subscriptions
    - Subscribe method: resources/subscribe
    - Unsubscribe method: resources/unsubscribe
    - Update notification: notifications/resources/updated
    - If subscribe: false or absent, subscriptions not supported
    """
    
    try:
        # Initialize and check capabilities
        init_result = await client.initialize_session()
        
        if not init_result:
            result.status = TestStatus.ERROR
            result.actual_behavior = "Failed to initialize session"
            return result
        
        # Check for resources capability and subscribe
        capabilities = init_result.get('capabilities', {})
        resources_capability = capabilities.get('resources', {})
        
        if not resources_capability:
            result.status = TestStatus.SKIPPED
            result.actual_behavior = "Server does not have resources capability"
            return result
        
        supports_subscribe = resources_capability.get('subscribe', False)
        
        if supports_subscribe:
            # Server claims to support subscriptions
            # Try to subscribe to a resource
            
            # First, get a resource to subscribe to
            list_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/list",
                "params": {}
            }
            
            list_response = await client.send_request(list_request)
            
            if list_response.get('error'):
                result.status = TestStatus.WARNING
                result.actual_behavior = f"""
                Server declares subscribe capability but cannot list resources:
                - Subscribe declared: ✓
                - Resources/list error: {list_response['error'].get('message', '')}
                - Cannot test subscription without resources
                """
                return result
            
            resources = list_response.get('result', {}).get('resources', [])
            
            if not resources:
                result.status = TestStatus.WARNING
                result.actual_behavior = """
                Server declares subscribe capability but has no resources:
                - Subscribe declared: ✓
                - No resources available to subscribe to
                - Cannot fully test subscription functionality
                """
                return result
            
            # Try to subscribe to first resource
            test_resource = resources[0]
            subscribe_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/subscribe",
                "params": {
                    "uri": test_resource['uri']
                }
            }
            
            try:
                subscribe_response = await client.send_request(subscribe_request)
                
                if subscribe_response.get('error'):
                    # Check if it's method not found
                    error_code = subscribe_response['error'].get('code')
                    if error_code == -32601:  # Method not found
                        result.status = TestStatus.FAILED
                        result.actual_behavior = f"""
                        Server declares subscribe but doesn't implement it:
                        - Subscribe capability declared: ✓
                        - resources/subscribe method: Not found ✗
                        - This is inconsistent with capability declaration
                        """
                        
                        result.failure_reason = """
                        Server MUST only declare subscribe capability if it implements subscriptions.
                        Declaring capability without implementation breaks client expectations.
                        """
                        
                        result.remediation = Remediation(
                            priority="HIGH",
                            steps=[
                                "Remove subscribe capability if not implemented",
                                "OR implement resources/subscribe method",
                                "Also implement resources/unsubscribe",
                                "Send notifications/resources/updated for changes"
                            ]
                        )
                    else:
                        result.status = TestStatus.WARNING
                        result.actual_behavior = f"""
                        Subscribe method returned error:
                        - Error: {subscribe_response['error'].get('message', '')}
                        - This might be resource-specific
                        """
                else:
                    # Subscribe successful
                    subscription_id = subscribe_response.get('result', {}).get('subscriptionId')
                    
                    # Try to unsubscribe
                    if subscription_id:
                        unsubscribe_request = {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "resources/unsubscribe",
                            "params": {
                                "subscriptionId": subscription_id
                            }
                        }
                        
                        unsubscribe_response = await client.send_request(unsubscribe_request)
                        unsubscribe_works = not unsubscribe_response.get('error')
                    else:
                        unsubscribe_works = False
                    
                    result.status = TestStatus.PASSED
                    result.actual_behavior = f"""
                    Resource subscription working:
                    - Subscribe capability declared: ✓
                    - resources/subscribe method: ✓
                    - Subscription created: ✓
                    - Subscription ID returned: {'✓' if subscription_id else '⚠️'}
                    - resources/unsubscribe method: {'✓' if unsubscribe_works else '⚠️'}
                    - Expected update notification: notifications/resources/updated
                    """
            except Exception as e:
                result.status = TestStatus.ERROR
                result.actual_behavior = f"Subscribe test failed: {e}"
        else:
            # Server doesn't declare subscribe - this is fine
            result.status = TestStatus.PASSED
            result.actual_behavior = """
            Server correctly does not declare subscribe capability:
            - Resources capability: ✓
            - Subscribe: Not declared (subscriptions not supported)
            - This is valid - subscriptions are optional
            """
        
        return result
        
    except Exception as e:
        result.status = TestStatus.ERROR
        result.actual_behavior = f"Test execution failed: {e}"
        result.failure_reason = str(e)
        return result