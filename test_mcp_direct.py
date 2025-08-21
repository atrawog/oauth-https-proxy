#!/usr/bin/env python3
"""
Direct MCP Tool Test

Test specific MCP tools directly without relying on tools/list
"""

import asyncio
import json
import httpx
import os

# Load environment variables
import dotenv
dotenv.load_dotenv()

class MCPTester:
    def __init__(self):
        self.base_url = "http://localhost:9000"
        self.admin_token = os.getenv("ADMIN_TOKEN", "acm_admin_token_here")
        self.session_id = None
        
    def parse_sse_response(self, response_text: str) -> dict:
        """Parse SSE response and extract JSON"""
        if "event: message" in response_text and "data: " in response_text:
            lines = response_text.split('\n')
            for line in lines:
                if line.startswith("data: "):
                    data_content = line[6:]  # Remove "data: " prefix
                    try:
                        return json.loads(data_content)
                    except json.JSONDecodeError as e:
                        print(f"JSON decode error: {e}")
                        return None
        return None
    
    async def initialize_session(self) -> bool:
        """Initialize MCP session and complete handshake"""
        async with httpx.AsyncClient() as client:
            # Step 1: Send initialize request
            init_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "experimental": {},
                        "prompts": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "tools": {"listChanged": False}
                    },
                    "clientInfo": {
                        "name": "Direct Tester",
                        "version": "1.0.0"
                    }
                }
            }
            
            print(f"Initializing session...")
            init_response = await client.post(
                f"{self.base_url}/mcp",
                json=init_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.admin_token}",
                    "Accept": "application/json, text/event-stream"
                },
                timeout=30.0
            )
            
            if init_response.status_code != 200:
                print(f"Init failed: {init_response.status_code} - {init_response.text}")
                return False
            
            # Extract session ID from response headers
            self.session_id = init_response.headers.get("mcp-session-id")
            
            # Parse response to verify initialization 
            result = self.parse_sse_response(init_response.text)
            if not result or "result" not in result:
                print(f"✗ Init failed: {result}")
                return False
            
            print(f"✓ Session initialized successfully")
            if self.session_id:
                print(f"  Session ID: {self.session_id}")
            else:
                print("  Warning: No session ID in headers")
                return False
            
            # Step 2: Send notifications/initialized to complete handshake
            print("Sending notifications/initialized...")
            notification_payload = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
            
            notification_response = await client.post(
                f"{self.base_url}/mcp",
                json=notification_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.admin_token}",
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Session-Id": self.session_id
                },
                timeout=30.0
            )
            
            if notification_response.status_code == 200:
                print("✓ Initialization handshake completed")
                return True
            else:
                print(f"  Warning: notifications/initialized failed: {notification_response.status_code}")
                # Some servers might not require this, so try to continue
                return True
    
    async def call_tool(self, tool_name: str, arguments: dict = None) -> dict:
        """Call an MCP tool with proper session management"""
        if not self.session_id:
            print("No session ID - initializing first")
            if not await self.initialize_session():
                return None
                
        async with httpx.AsyncClient() as client:
            tool_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name
                }
            }
            
            if arguments:
                tool_payload["params"]["arguments"] = arguments
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.admin_token}",
                "Accept": "application/json, text/event-stream"
            }
            
            # Add session ID to headers
            if self.session_id:
                headers["Mcp-Session-Id"] = self.session_id
            
            print(f"Calling tool: {tool_name} (session: {self.session_id})")
            
            tool_response = await client.post(
                f"{self.base_url}/mcp",
                json=tool_payload,
                headers=headers,
                timeout=30.0
            )
            
            if tool_response.status_code != 200:
                print(f"Tool call failed: {tool_response.status_code} - {tool_response.text}")
                return None
            
            # Parse SSE response
            result = self.parse_sse_response(tool_response.text)
            if result:
                if "result" in result:
                    print(f"✓ Tool result: {result['result']}")
                elif "error" in result:
                    print(f"✗ Tool error: {result['error']}")
                else:
                    print(f"? Unexpected result: {result}")
                return result
            else:
                print(f"Failed to parse response: {tool_response.text[:200]}")
                return None

async def call_mcp_tool(tool_name: str, arguments: dict = None) -> dict:
    """Call an MCP tool using the tester class"""
    tester = MCPTester()
    return await tester.call_tool(tool_name, arguments)

async def main():
    """Test direct MCP tool calls"""
    print("🔧 Testing Direct MCP Tool Calls")
    print("=" * 50)
    
    # Create a single tester instance to maintain session
    tester = MCPTester()
    
    # Test tools that should be registered based on the server code
    test_tools = [
        ("echo", {"message": "Hello MCP"}),
        ("health_check", None),
        ("proxy_list", None),
        ("cert_list", None),
        ("route_list", None),
        ("logs", {"limit": 5}),
    ]
    
    for tool_name, args in test_tools:
        print(f"\n--- Testing {tool_name} ---")
        try:
            result = await tester.call_tool(tool_name, args)
            if result and "result" in result:
                print(f"✓ {tool_name} worked")
            else:
                print(f"✗ {tool_name} failed")
        except Exception as e:
            print(f"✗ {tool_name} exception: {e}")
    
    # Test tools/list to see if we can get tool listing after session is established
    print(f"\n--- Testing tools/list ---")
    try:
        async with httpx.AsyncClient() as client:
            list_payload = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list"
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {tester.admin_token}",
                "Accept": "application/json, text/event-stream"
            }
            
            if tester.session_id:
                headers["Mcp-Session-Id"] = tester.session_id
            
            list_response = await client.post(
                f"{tester.base_url}/mcp",
                json=list_payload,
                headers=headers,
                timeout=30.0
            )
            
            if list_response.status_code == 200:
                result = tester.parse_sse_response(list_response.text)
                if result and "result" in result:
                    tools = result["result"].get("tools", [])
                    print(f"✓ Found {len(tools)} tools:")
                    for tool in tools:
                        print(f"  - {tool.get('name', 'unknown')}: {tool.get('description', 'no description')}")
                else:
                    print(f"✗ tools/list failed to parse: {result}")
            else:
                print(f"✗ tools/list failed: {list_response.status_code} - {list_response.text}")
    except Exception as e:
        print(f"✗ tools/list exception: {e}")

if __name__ == "__main__":
    asyncio.run(main())