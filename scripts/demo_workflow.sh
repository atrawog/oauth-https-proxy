#!/bin/bash
# Demonstration of MCP Proxy Manager workflow

echo "===================================="
echo "MCP PROXY MANAGER - DEMO WORKFLOW"
echo "===================================="
echo
echo "This demo shows the complete workflow:"
echo "1. Create token with email (CLI only)"
echo "2. Use web GUI to manage proxies"
echo "3. Update email settings in GUI"
echo

# Demo token name
TOKEN_NAME="demo-token-$(date +%s)"
EMAIL="demo@example.com"

echo "Step 1: Creating token via CLI"
echo "Command: just token-generate $TOKEN_NAME $EMAIL"
echo
echo "Step 2: View token"
echo "Command: just token-show $TOKEN_NAME"
echo
echo "Step 3: Access web GUI"
echo "- Open http://localhost:80"
echo "- Login with the token shown above"
echo "- Notice: NO email fields in Certificate or Proxy forms"
echo "- Click Settings tab to see/update email"
echo
echo "Step 4: Create proxy target (via GUI or API)"
echo "- In GUI: Go to 'New Proxy Target' tab"
echo "- Enter hostname (e.g., api.example.com)"
echo "- Enter target URL (e.g., http://backend:8080)"
echo "- Certificate will use token's email automatically"
echo
echo "Step 5: Update email (via GUI)"
echo "- Go to Settings tab"
echo "- Enter new email"
echo "- Click 'Update Email'"
echo "- All new certificates will use updated email"
echo
echo "Step 6: View results"
echo "Command: just token-show-certs $TOKEN_NAME"
echo "Command: just cert-list $TOKEN_NAME"
echo
echo "Step 7: Cleanup"
echo "Command: just token-delete $TOKEN_NAME"
echo
echo "===================================="
echo "Key Points:"
echo "- Token creation: CLI only (just commands)"
echo "- Email updates: Web GUI Settings tab"
echo "- No email fields in cert/proxy forms"
echo "- Email inherited from token settings"
echo "===================================="