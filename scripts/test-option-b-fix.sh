#!/bin/bash
# Test script to verify Option B implementation fix

echo "=== Testing Option B Implementation Fix ==="
echo
echo "1. Protected Resource Metadata Check:"
echo "   Resource URI should include /mcp path"
RESOURCE=$(curl -s https://everything-c.atradev.org/.well-known/oauth-protected-resource | jq -r '.resource')
echo "   Resource: $RESOURCE"
if [[ "$RESOURCE" == "https://everything-c.atradev.org/mcp" ]]; then
    echo "   ✅ PASS: Resource includes path"
else
    echo "   ❌ FAIL: Resource missing path"
fi

echo
echo "2. Testing MCP endpoint without token:"
echo "   Should return 401 with proper WWW-Authenticate header"
RESPONSE=$(curl -s -i https://everything-c.atradev.org/mcp | head -20)
echo "$RESPONSE" | grep -E "HTTP|WWW-Authenticate"

echo
echo "3. Expected OAuth Flow (for Claude.ai):"
echo "   a) Authorization request should include:"
echo "      resource=https://everything-c.atradev.org/mcp"
echo
echo "   b) Token request should include:"
echo "      resource=https://everything-c.atradev.org/mcp"
echo
echo "   c) Resulting token should have:"
echo "      aud: [\"https://everything-c.atradev.org/mcp\"]"
echo
echo "   d) Token validation will check:"
echo "      Is 'https://everything-c.atradev.org/mcp' in aud claim? ✅"

echo
echo "4. Fix Summary:"
echo "   - Protected resource metadata: Returns resource WITH path (/mcp)"
echo "   - Token validation: Now expects resource WITH path (/mcp)"
echo "   - Result: Consistent resource URI handling throughout the system"

echo
echo "=== Test Complete ==="
echo
echo "Note: The fix is implemented. Claude.ai now needs to:"
echo "1. Read the 'resource' field from /.well-known/oauth-protected-resource"
echo "2. Use that exact value in the OAuth 'resource' parameter"
echo "3. The resulting tokens will have the correct audience claim"