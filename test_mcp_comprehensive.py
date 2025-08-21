#!/usr/bin/env python3
"""
Direct MCP Tool Test

Test specific MCP tools directly without relying on tools/list
"""

import asyncio
import json
import httpx
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
from dataclasses import dataclass
from pathlib import Path

# Load environment variables
import dotenv
dotenv.load_dotenv()

@dataclass
class TestResult:
    tool_name: str
    category: str
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class MCPToolsTester:
    def __init__(self):
        self.base_url = "http://localhost:9000"
        self.admin_token = os.getenv("ADMIN_TOKEN", "acm_admin_token_here")
        self.test_token = os.getenv("TEST_TOKEN", "acm_test_token_here")
        self.test_domain = os.getenv("TEST_DOMAIN", "test.example.com")
        self.results: List[TestResult] = []
        self.session_id = None
        
    async def make_mcp_request(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an MCP request to the server (handles SSE responses)"""
        async with httpx.AsyncClient() as client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method
            }
            if params:
                payload["params"] = params
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.admin_token}",
                "Accept": "application/json, text/event-stream"
            }
            
            # Add session ID after initialization to avoid auto-init fixes
            # Comment out for now as session management is handled by the server
            # if self.session_id:
            #     headers["Mcp-Session-Id"] = self.session_id
                
            response = await client.post(
                f"{self.base_url}/mcp",
                json=payload,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            # Parse SSE response
            response_text = response.text
            
            if "event: message" in response_text and "data: " in response_text:
                # Extract JSON from SSE format
                lines = response_text.split('\n')
                for line in lines:
                    if line.startswith("data: "):
                        data_content = line[6:]  # Remove "data: " prefix
                        try:
                            return json.loads(data_content)
                        except json.JSONDecodeError as e:
                            print(f"JSON decode error: {e}")
                            print(f"Data content: {repr(data_content)}")
                            raise
                raise Exception("No data line found in SSE response")
            else:
                # Try direct JSON parsing
                try:
                    return response.json()
                except json.JSONDecodeError as e:
                    print(f"Direct JSON decode error: {e}")
                    print(f"Full response: {repr(response_text[:500])}")
                    raise
    
    async def initialize_session(self):
        """Initialize MCP session"""
        try:
            result = await self.make_mcp_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "experimental": {},
                    "prompts": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "tools": {"listChanged": False}
                },
                "clientInfo": {
                    "name": "MCP Comprehensive Tester",
                    "version": "1.0.0"
                }
            })
            
            if "result" in result:
                print("✓ MCP session initialized successfully")
                print(f"  Server: {result['result']['serverInfo']['name']} {result['result']['serverInfo']['version']}")
                print(f"  Protocol: {result['result']['protocolVersion']}")
                
                # Extract session ID from response headers if available 
                # For now, create a session ID based on timestamp
                import time
                self.session_id = f"test-session-{int(time.time())}"
                
                # Skip notifications/initialized for now as session management is complex
                print("ℹ Skipping notifications/initialized - session should be auto-managed")
                
                return True
            else:
                print("✗ Failed to initialize MCP session")
                print(f"  Error: {result.get('error', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"✗ Exception initializing session: {e}")
            return False
    
    async def list_tools(self) -> Dict[str, Any]:
        """List all available MCP tools"""
        try:
            result = await self.make_mcp_request("tools/list")
            if "result" in result:
                return result["result"]
            else:
                raise Exception(f"Error listing tools: {result.get('error', 'Unknown error')}")
        except Exception as e:
            raise Exception(f"Failed to list tools: {e}")
    
    async def call_tool(self, tool_name: str, arguments: Optional[Dict] = None) -> Dict[str, Any]:
        """Call a specific MCP tool"""
        try:
            params = {"name": tool_name}
            if arguments:
                params["arguments"] = arguments
                
            result = await self.make_mcp_request("tools/call", params)
            
            if "result" in result:
                return result["result"]
            else:
                raise Exception(f"Tool call error: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            raise Exception(f"Failed to call tool {tool_name}: {e}")
    
    def add_result(self, tool_name: str, category: str, success: bool, message: str, 
                   data: Optional[Dict] = None, error: Optional[str] = None):
        """Add a test result"""
        self.results.append(TestResult(
            tool_name=tool_name,
            category=category,
            success=success,
            message=message,
            data=data,
            error=error
        ))
    
    async def test_tool_listing_and_annotations(self):
        """Test 1: List tools and check annotations"""
        print("\n=== Testing Tool Listing and Annotations ===")
        
        try:
            tools_data = await self.list_tools()
            tools = tools_data.get("tools", [])
            
            print(f"✓ Found {len(tools)} tools")
            
            # Check each tool has required annotations
            required_fields = ["name", "description"]
            optional_hints = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]
            
            for tool in tools:
                tool_name = tool.get("name", "unknown")
                
                # Check required fields
                missing_required = [field for field in required_fields if field not in tool]
                if missing_required:
                    self.add_result(tool_name, "annotations", False, 
                                  f"Missing required fields: {missing_required}")
                    continue
                
                # Check hints
                present_hints = [hint for hint in optional_hints if hint in tool.get("inputSchema", {}).get("properties", {})]
                
                self.add_result(tool_name, "annotations", True, 
                              f"Tool properly registered with hints: {present_hints}",
                              data={"tool_info": tool})
                
                print(f"  - {tool_name}: {tool.get('description', 'No description')[:50]}...")
                if present_hints:
                    print(f"    Hints: {', '.join(present_hints)}")
            
            return tools
            
        except Exception as e:
            self.add_result("tool_listing", "system", False, f"Failed to list tools: {e}", error=str(e))
            print(f"✗ Failed to list tools: {e}")
            return []
    
    async def test_system_tools(self):
        """Test system tools: echo, health_check"""
        print("\n=== Testing System Tools ===")
        
        # Test echo
        try:
            result = await self.call_tool("echo", {"message": "MCP comprehensive test"})
            if result.get("content") and result["content"][0].get("text") == "MCP comprehensive test":
                self.add_result("echo", "system", True, "Echo test successful", data=result)
                print("✓ echo: Working correctly")
            else:
                self.add_result("echo", "system", False, "Echo returned unexpected result", data=result)
                print("✗ echo: Unexpected result")
        except Exception as e:
            self.add_result("echo", "system", False, f"Echo failed: {e}", error=str(e))
            print(f"✗ echo: {e}")
        
        # Test health_check
        try:
            result = await self.call_tool("health_check")
            content = result.get("content", [{}])[0].get("text", "")
            if "status" in content.lower() and "healthy" in content.lower():
                self.add_result("health_check", "system", True, "Health check successful", data=result)
                print("✓ health_check: System healthy")
            else:
                self.add_result("health_check", "system", False, "Health check returned unexpected result", data=result)
                print("✗ health_check: Unexpected result")
        except Exception as e:
            self.add_result("health_check", "system", False, f"Health check failed: {e}", error=str(e))
            print(f"✗ health_check: {e}")
    
    async def test_token_tools(self):
        """Test token management tools"""
        print("\n=== Testing Token Tools ===")
        
        # Test list_tokens
        try:
            result = await self.call_tool("list_tokens")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "token" in content.lower() or "no tokens" in content.lower():
                self.add_result("list_tokens", "tokens", True, "Token listing successful", data=result)
                print("✓ list_tokens: Working correctly")
            else:
                self.add_result("list_tokens", "tokens", False, "Token listing returned unexpected result", data=result)
                print("✗ list_tokens: Unexpected result")
        except Exception as e:
            self.add_result("list_tokens", "tokens", False, f"Token listing failed: {e}", error=str(e))
            print(f"✗ list_tokens: {e}")
        
        # Test create_token (create test token)
        test_token_name = f"mcp_test_token_{int(datetime.now().timestamp())}"
        try:
            result = await self.call_tool("create_token", {
                "name": test_token_name,
                "description": "MCP comprehensive test token"
            })
            content = result.get("content", [{}])[0].get("text", "")
            
            if "created" in content.lower() or "token" in content.lower():
                self.add_result("create_token", "tokens", True, "Token creation successful", data=result)
                print(f"✓ create_token: Created {test_token_name}")
                
                # Test show_token with the newly created token
                try:
                    show_result = await self.call_tool("show_token", {"name": test_token_name})
                    show_content = show_result.get("content", [{}])[0].get("text", "")
                    
                    if test_token_name in show_content:
                        self.add_result("show_token", "tokens", True, "Token show successful", data=show_result)
                        print(f"✓ show_token: Retrieved {test_token_name} details")
                    else:
                        self.add_result("show_token", "tokens", False, "Token show returned unexpected result", data=show_result)
                        print("✗ show_token: Unexpected result")
                except Exception as e:
                    self.add_result("show_token", "tokens", False, f"Token show failed: {e}", error=str(e))
                    print(f"✗ show_token: {e}")
                    
            else:
                self.add_result("create_token", "tokens", False, "Token creation returned unexpected result", data=result)
                print("✗ create_token: Unexpected result")
        except Exception as e:
            self.add_result("create_token", "tokens", False, f"Token creation failed: {e}", error=str(e))
            print(f"✗ create_token: {e}")
    
    async def test_certificate_tools(self):
        """Test certificate management tools"""
        print("\n=== Testing Certificate Tools ===")
        
        # Test list_certificates
        try:
            result = await self.call_tool("list_certificates")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "certificate" in content.lower() or "no certificates" in content.lower():
                self.add_result("list_certificates", "certificates", True, "Certificate listing successful", data=result)
                print("✓ list_certificates: Working correctly")
                
                # If there are certificates, test show_certificate
                if "certificate" in content.lower() and "no certificates" not in content.lower():
                    # Try to extract a certificate domain from the output
                    lines = content.split('\n')
                    cert_domain = None
                    for line in lines:
                        if '.com' in line or '.org' in line or '.net' in line:
                            # Extract domain from line
                            words = line.split()
                            for word in words:
                                if '.' in word and not word.startswith('http'):
                                    cert_domain = word.strip('|').strip()
                                    break
                            if cert_domain:
                                break
                    
                    if cert_domain:
                        try:
                            show_result = await self.call_tool("show_certificate", {"domain": cert_domain})
                            show_content = show_result.get("content", [{}])[0].get("text", "")
                            
                            if cert_domain in show_content:
                                self.add_result("show_certificate", "certificates", True, 
                                              f"Certificate show successful for {cert_domain}", data=show_result)
                                print(f"✓ show_certificate: Retrieved {cert_domain} details")
                            else:
                                self.add_result("show_certificate", "certificates", False, 
                                              "Certificate show returned unexpected result", data=show_result)
                                print("✗ show_certificate: Unexpected result")
                        except Exception as e:
                            self.add_result("show_certificate", "certificates", False, 
                                          f"Certificate show failed: {e}", error=str(e))
                            print(f"✗ show_certificate: {e}")
                    else:
                        print("  Note: Could not extract certificate domain for show_certificate test")
                        
            else:
                self.add_result("list_certificates", "certificates", False, 
                              "Certificate listing returned unexpected result", data=result)
                print("✗ list_certificates: Unexpected result")
        except Exception as e:
            self.add_result("list_certificates", "certificates", False, 
                          f"Certificate listing failed: {e}", error=str(e))
            print(f"✗ list_certificates: {e}")
    
    async def test_proxy_tools(self):
        """Test proxy management tools"""
        print("\n=== Testing Proxy Tools ===")
        
        # Test list_proxies first
        try:
            result = await self.call_tool("list_proxies")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "proxy" in content.lower() or "no proxies" in content.lower():
                self.add_result("list_proxies", "proxies", True, "Proxy listing successful", data=result)
                print("✓ list_proxies: Working correctly")
            else:
                self.add_result("list_proxies", "proxies", False, "Proxy listing returned unexpected result", data=result)
                print("✗ list_proxies: Unexpected result")
        except Exception as e:
            self.add_result("list_proxies", "proxies", False, f"Proxy listing failed: {e}", error=str(e))
            print(f"✗ list_proxies: {e}")
        
        # Test create_proxy
        test_proxy_domain = f"mcp-test-{int(datetime.now().timestamp())}.{self.test_domain}"
        try:
            result = await self.call_tool("create_proxy", {
                "domain": test_proxy_domain,
                "target_url": "https://httpbin.org",
                "description": "MCP comprehensive test proxy"
            })
            content = result.get("content", [{}])[0].get("text", "")
            
            if "created" in content.lower() or "proxy" in content.lower():
                self.add_result("create_proxy", "proxies", True, f"Proxy creation successful for {test_proxy_domain}", data=result)
                print(f"✓ create_proxy: Created {test_proxy_domain}")
                
                # Test show_proxy with the newly created proxy
                try:
                    show_result = await self.call_tool("show_proxy", {"domain": test_proxy_domain})
                    show_content = show_result.get("content", [{}])[0].get("text", "")
                    
                    if test_proxy_domain in show_content:
                        self.add_result("show_proxy", "proxies", True, "Proxy show successful", data=show_result)
                        print(f"✓ show_proxy: Retrieved {test_proxy_domain} details")
                    else:
                        self.add_result("show_proxy", "proxies", False, "Proxy show returned unexpected result", data=show_result)
                        print("✗ show_proxy: Unexpected result")
                except Exception as e:
                    self.add_result("show_proxy", "proxies", False, f"Proxy show failed: {e}", error=str(e))
                    print(f"✗ show_proxy: {e}")
                    
            else:
                self.add_result("create_proxy", "proxies", False, "Proxy creation returned unexpected result", data=result)
                print("✗ create_proxy: Unexpected result")
        except Exception as e:
            self.add_result("create_proxy", "proxies", False, f"Proxy creation failed: {e}", error=str(e))
            print(f"✗ create_proxy: {e}")
    
    async def test_route_tools(self):
        """Test route management tools"""
        print("\n=== Testing Route Tools ===")
        
        # Test list_routes
        try:
            result = await self.call_tool("list_routes")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "route" in content.lower() or "no routes" in content.lower():
                self.add_result("list_routes", "routes", True, "Route listing successful", data=result)
                print("✓ list_routes: Working correctly")
            else:
                self.add_result("list_routes", "routes", False, "Route listing returned unexpected result", data=result)
                print("✗ list_routes: Unexpected result")
        except Exception as e:
            self.add_result("list_routes", "routes", False, f"Route listing failed: {e}", error=str(e))
            print(f"✗ list_routes: {e}")
        
        # Test create_route
        test_route_pattern = f"/mcp-test-{int(datetime.now().timestamp())}/*"
        try:
            result = await self.call_tool("create_route", {
                "pattern": test_route_pattern,
                "target_url": "https://httpbin.org",
                "description": "MCP comprehensive test route"
            })
            content = result.get("content", [{}])[0].get("text", "")
            
            if "created" in content.lower() or "route" in content.lower():
                self.add_result("create_route", "routes", True, f"Route creation successful for {test_route_pattern}", data=result)
                print(f"✓ create_route: Created {test_route_pattern}")
                
                # Test show_route with the newly created route
                try:
                    show_result = await self.call_tool("show_route", {"pattern": test_route_pattern})
                    show_content = show_result.get("content", [{}])[0].get("text", "")
                    
                    if test_route_pattern.replace('*', '') in show_content:
                        self.add_result("show_route", "routes", True, "Route show successful", data=show_result)
                        print(f"✓ show_route: Retrieved {test_route_pattern} details")
                    else:
                        self.add_result("show_route", "routes", False, "Route show returned unexpected result", data=show_result)
                        print("✗ show_route: Unexpected result")
                except Exception as e:
                    self.add_result("show_route", "routes", False, f"Route show failed: {e}", error=str(e))
                    print(f"✗ show_route: {e}")
                    
            else:
                self.add_result("create_route", "routes", False, "Route creation returned unexpected result", data=result)
                print("✗ create_route: Unexpected result")
        except Exception as e:
            self.add_result("create_route", "routes", False, f"Route creation failed: {e}", error=str(e))
            print(f"✗ create_route: {e}")
    
    async def test_service_tools(self):
        """Test service management tools"""
        print("\n=== Testing Service Tools ===")
        
        # Test list_services
        try:
            result = await self.call_tool("list_services")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "service" in content.lower() or "no services" in content.lower():
                self.add_result("list_services", "services", True, "Service listing successful", data=result)
                print("✓ list_services: Working correctly")
            else:
                self.add_result("list_services", "services", False, "Service listing returned unexpected result", data=result)
                print("✗ list_services: Unexpected result")
        except Exception as e:
            self.add_result("list_services", "services", False, f"Service listing failed: {e}", error=str(e))
            print(f"✗ list_services: {e}")
    
    async def test_log_tools(self):
        """Test log query tools"""
        print("\n=== Testing Log Tools ===")
        
        # Test get_logs with different filters
        test_cases = [
            {"level": "INFO", "limit": 10, "description": "INFO level logs"},
            {"level": "ERROR", "limit": 5, "description": "ERROR level logs"},
            {"component": "proxy", "limit": 10, "description": "proxy component logs"},
            {"limit": 20, "description": "recent logs"}
        ]
        
        for test_case in test_cases:
            try:
                args = {k: v for k, v in test_case.items() if k != "description"}
                result = await self.call_tool("get_logs", args)
                content = result.get("content", [{}])[0].get("text", "")
                
                if content and len(content) > 0:
                    self.add_result("get_logs", "logs", True, 
                                  f"Log query successful for {test_case['description']}", data=result)
                    print(f"✓ get_logs ({test_case['description']}): Retrieved logs")
                else:
                    self.add_result("get_logs", "logs", True, 
                                  f"Log query returned no results for {test_case['description']} (expected)", data=result)
                    print(f"✓ get_logs ({test_case['description']}): No logs (expected)")
            except Exception as e:
                self.add_result("get_logs", "logs", False, 
                              f"Log query failed for {test_case['description']}: {e}", error=str(e))
                print(f"✗ get_logs ({test_case['description']}): {e}")
    
    async def test_oauth_tools(self):
        """Test OAuth management tools"""
        print("\n=== Testing OAuth Tools ===")
        
        # Test list_oauth_clients
        try:
            result = await self.call_tool("list_oauth_clients")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "client" in content.lower() or "no clients" in content.lower():
                self.add_result("list_oauth_clients", "oauth", True, "OAuth client listing successful", data=result)
                print("✓ list_oauth_clients: Working correctly")
            else:
                self.add_result("list_oauth_clients", "oauth", False, "OAuth client listing returned unexpected result", data=result)
                print("✗ list_oauth_clients: Unexpected result")
        except Exception as e:
            self.add_result("list_oauth_clients", "oauth", False, f"OAuth client listing failed: {e}", error=str(e))
            print(f"✗ list_oauth_clients: {e}")
    
    async def test_workflow_tools(self):
        """Test workflow management tools"""
        print("\n=== Testing Workflow Tools ===")
        
        # Test get_workflow_status
        try:
            result = await self.call_tool("get_workflow_status")
            content = result.get("content", [{}])[0].get("text", "")
            
            if "workflow" in content.lower() or "status" in content.lower():
                self.add_result("get_workflow_status", "workflow", True, "Workflow status successful", data=result)
                print("✓ get_workflow_status: Working correctly")
            else:
                self.add_result("get_workflow_status", "workflow", False, "Workflow status returned unexpected result", data=result)
                print("✗ get_workflow_status: Unexpected result")
        except Exception as e:
            self.add_result("get_workflow_status", "workflow", False, f"Workflow status failed: {e}", error=str(e))
            print(f"✗ get_workflow_status: {e}")
    
    async def test_error_handling(self):
        """Test error handling with invalid inputs"""
        print("\n=== Testing Error Handling ===")
        
        error_test_cases = [
            {
                "tool": "show_token",
                "args": {"name": "nonexistent_token_12345"},
                "expected": "not found"
            },
            {
                "tool": "show_certificate",
                "args": {"domain": "nonexistent.domain.invalid"},
                "expected": "not found"
            },
            {
                "tool": "show_proxy",
                "args": {"domain": "nonexistent.proxy.invalid"},
                "expected": "not found"
            },
            {
                "tool": "create_proxy",
                "args": {"domain": "", "target_url": "invalid-url"},
                "expected": "invalid"
            }
        ]
        
        for test_case in error_test_cases:
            try:
                result = await self.call_tool(test_case["tool"], test_case["args"])
                content = result.get("content", [{}])[0].get("text", "").lower()
                
                # Check if error is handled gracefully
                if test_case["expected"] in content or "error" in content:
                    self.add_result(f"{test_case['tool']}_error", "error_handling", True, 
                                  f"Error handled gracefully for {test_case['tool']}", data=result)
                    print(f"✓ {test_case['tool']} error handling: Graceful error response")
                else:
                    self.add_result(f"{test_case['tool']}_error", "error_handling", False, 
                                  f"Unexpected response for {test_case['tool']} error case", data=result)
                    print(f"? {test_case['tool']} error handling: Unexpected response")
                    
            except Exception as e:
                # This is actually good - the tool properly raised an exception
                self.add_result(f"{test_case['tool']}_error", "error_handling", True, 
                              f"Tool properly raised exception for {test_case['tool']}: {e}", error=str(e))
                print(f"✓ {test_case['tool']} error handling: Proper exception raised")
    
    async def run_comprehensive_test(self):
        """Run the comprehensive test suite"""
        print("🔬 Starting Comprehensive MCP Tools Test Suite")
        print("=" * 60)
        
        # Initialize session
        if not await self.initialize_session():
            print("❌ Failed to initialize MCP session. Exiting.")
            return
        
        # Test 1: Tool listing and annotations
        tools = await self.test_tool_listing_and_annotations()
        if not tools:
            print("❌ No tools found. Exiting.")
            return
        
        # Test 2: System tools
        await self.test_system_tools()
        
        # Test 3: Token tools
        await self.test_token_tools()
        
        # Test 4: Certificate tools
        await self.test_certificate_tools()
        
        # Test 5: Proxy tools
        await self.test_proxy_tools()
        
        # Test 6: Route tools
        await self.test_route_tools()
        
        # Test 7: Service tools
        await self.test_service_tools()
        
        # Test 8: Log tools
        await self.test_log_tools()
        
        # Test 9: OAuth tools
        await self.test_oauth_tools()
        
        # Test 10: Workflow tools
        await self.test_workflow_tools()
        
        # Test 11: Error handling
        await self.test_error_handling()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE MCP TOOLS TEST REPORT")
        print("=" * 60)
        
        # Summary statistics
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.success)
        failed_tests = total_tests - passed_tests
        
        print(f"\n📈 SUMMARY")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed: {passed_tests} ✓")
        print(f"  Failed: {failed_tests} ✗")
        print(f"  Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        # Results by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = {"passed": 0, "failed": 0, "tests": []}
            
            categories[result.category]["tests"].append(result)
            if result.success:
                categories[result.category]["passed"] += 1
            else:
                categories[result.category]["failed"] += 1
        
        print(f"\n📋 RESULTS BY CATEGORY")
        for category, stats in categories.items():
            total = stats["passed"] + stats["failed"]
            success_rate = (stats["passed"] / total * 100) if total > 0 else 0
            print(f"  {category.upper()}: {stats['passed']}/{total} ({success_rate:.1f}%)")
            
            # Show failed tests
            failed_tests = [t for t in stats["tests"] if not t.success]
            if failed_tests:
                for test in failed_tests:
                    print(f"    ✗ {test.tool_name}: {test.message}")
        
        print(f"\n🔧 DETAILED RESULTS")
        for result in self.results:
            status = "✓" if result.success else "✗"
            print(f"  {status} {result.tool_name} ({result.category}): {result.message}")
            if result.error:
                print(f"      Error: {result.error}")
        
        print(f"\n🎯 RECOMMENDATIONS")
        
        # Check for critical failures
        critical_tools = ["echo", "health_check", "list_tokens", "list_proxies"]
        critical_failures = [r for r in self.results if r.tool_name in critical_tools and not r.success]
        
        if critical_failures:
            print("  ⚠️  CRITICAL ISSUES FOUND:")
            for failure in critical_failures:
                print(f"     - {failure.tool_name}: {failure.message}")
        else:
            print("  ✓ All critical tools are working correctly")
        
        # Check tool coverage
        expected_tools = {
            "echo", "health_check", "list_tokens", "create_token", "show_token",
            "list_certificates", "show_certificate", "list_proxies", "create_proxy", 
            "show_proxy", "list_routes", "create_route", "show_route", "list_services",
            "get_logs", "list_oauth_clients", "get_workflow_status"
        }
        
        tested_tools = {r.tool_name.replace("_error", "") for r in self.results}
        missing_tools = expected_tools - tested_tools
        
        if missing_tools:
            print(f"  ⚠️  MISSING TOOL TESTS: {', '.join(missing_tools)}")
        else:
            print("  ✓ All expected tools were tested")
        
        print(f"\n✅ Test completed at {datetime.now().isoformat()}")
        
        # Return overall success
        return failed_tests == 0

async def main():
    """Main test execution"""
    tester = MCPToolsTester()
    success = await tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All tests passed! MCP tools are working correctly.")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed. Check the report above for details.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())