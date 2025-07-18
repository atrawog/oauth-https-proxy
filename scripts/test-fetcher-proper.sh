#!/bin/bash
# Test fetcher MCP with proper client

echo "Testing fetcher MCP at http://fetcher.atradev.org"
echo "================================"

# Use npx to run MCP client
echo "Running MCP client inspector..."
npx @modelcontextprotocol/inspector http://fetcher.atradev.org/mcp