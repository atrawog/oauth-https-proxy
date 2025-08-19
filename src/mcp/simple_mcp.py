"""Simple MCP implementation without SDK dependency."""

import logging
from typing import Dict, Any, List, Optional
import asyncio
import inspect

logger = logging.getLogger(__name__)


class SimpleMCP:
    """Simple MCP server without SDK dependency."""
    
    def __init__(self, name: str = "OAuth-HTTPS-Proxy MCP Server"):
        """Initialize simple MCP server.
        
        Args:
            name: Server name
        """
        self.name = name
        self.tools: Dict[str, callable] = {}
        self.tool_descriptions: Dict[str, str] = {}
        self.state: Dict[str, Any] = {}  # Add state attribute for compatibility
        
    def tool(self):
        """Decorator to register tools."""
        def decorator(func):
            # Get tool name and description
            tool_name = func.__name__
            tool_desc = func.__doc__ or f"Tool: {tool_name}"
            
            # Store tool
            self.tools[tool_name] = func
            self.tool_descriptions[tool_name] = tool_desc.strip()
            
            logger.debug(f"Registered tool: {tool_name}")
            return func
        return decorator
    
    def list_tools(self) -> List[Dict[str, str]]:
        """List all registered tools.
        
        Returns:
            List of tool definitions
        """
        tools = []
        for name, desc in self.tool_descriptions.items():
            tools.append({
                "name": name,
                "description": desc.split('\n')[0] if desc else f"Tool: {name}"
            })
        return tools
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a registered tool.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            
        Returns:
            Tool result
            
        Raises:
            ValueError: If tool not found
        """
        if tool_name not in self.tools:
            raise ValueError(f"Tool not found: {tool_name}")
        
        tool_func = self.tools[tool_name]
        
        # Check if it's async
        if asyncio.iscoroutinefunction(tool_func):
            result = await tool_func(**arguments)
        else:
            result = tool_func(**arguments)
        
        return result


# Create a global SimpleMCP instance that can be used like FastMCP
FastMCP = SimpleMCP