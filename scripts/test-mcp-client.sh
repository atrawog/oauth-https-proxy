#!/usr/bin/env bash
# Test script for MCP StreamableHTTP Client
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_DIR="${BASE_DIR}/mcp-streamablehttp-client"

echo -e "${BLUE}=== MCP StreamableHTTP Client Testing ===${NC}"
echo ""

# Check if running from correct directory
if [ ! -f "${BASE_DIR}/justfile" ]; then
    echo -e "${RED}Error: Must run from mcp-http-proxy directory${NC}"
    exit 1
fi

# Function to run test and check result
run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✓ ${test_name} passed${NC}"
        return 0
    else
        echo -e "${RED}✗ ${test_name} failed${NC}"
        return 1
    fi
    echo ""
}

# 1. Environment Setup
echo -e "${BLUE}1. Setting up environment...${NC}"
cd "${BASE_DIR}"

# Start services if not running
if ! docker-compose ps | grep -q "certmanager.*Up"; then
    echo "Starting services..."
    just up
    sleep 5
fi

# Ensure echo servers are running
echo "Starting echo servers..."
just mcp-echo-start
sleep 3

# Setup OAuth routes
echo "Setting up OAuth routes..."
just oauth-routes-setup "auth.localhost" ADMIN

# 2. Token Generation
echo -e "\n${BLUE}2. Generating OAuth tokens...${NC}"
cd "${CLIENT_DIR}"

# Check if we need to generate tokens
if [ ! -f .env ] || ! grep -q "MCP_CLIENT_ACCESS_TOKEN" .env; then
    echo "No tokens found, generating new ones..."
    just token-generate https://echo-stateless.localhost/mcp
else
    echo "Tokens found in .env, checking validity..."
    if ! just token-status; then
        echo "Tokens invalid, regenerating..."
        just token-reset
        just token-generate https://echo-stateless.localhost/mcp
    fi
fi

# 3. Basic Connectivity Tests
echo -e "\n${BLUE}3. Running connectivity tests...${NC}"

run_test "Token validation" "just token-test"
run_test "List tools" "just list-tools"
run_test "List resources" "just list-resources"
run_test "List prompts" "just list-prompts"

# 4. Echo Server Tests
echo -e "\n${BLUE}4. Testing echo server functionality...${NC}"

run_test "Simple echo" "just test-echo 'Hello from test script!'"

# Test with JSON content
run_test "Echo with JSON" "just exec 'echo message=\"{\\\"test\\\": \\\"json data\\\"}\"'"

# Test with special characters
run_test "Echo with special chars" "just exec 'echo message=\"Test with special: !@#$%^&*()\"'"

# 5. Stateful Server Tests
echo -e "\n${BLUE}5. Testing stateful server...${NC}"

# Switch to stateful server
echo "Switching to stateful server..."
just token-reset
just token-generate https://echo-stateful.localhost/mcp

# Run stateful tests
run_test "Stateful operations" "just test-stateful"

# 6. OAuth Client Management Tests
echo -e "\n${BLUE}6. Testing OAuth client management...${NC}"

run_test "Get client info" "just client-info"

# 7. Error Handling Tests
echo -e "\n${BLUE}7. Testing error handling...${NC}"

# Test with invalid server
echo "Testing with invalid server URL..."
just token-reset
if MCP_SERVER_URL="https://invalid.server.test/mcp" just token-test 2>&1 | grep -q "error\|failed"; then
    echo -e "${GREEN}✓ Invalid server handled correctly${NC}"
else
    echo -e "${RED}✗ Invalid server not handled properly${NC}"
fi

# Restore valid server
just token-generate https://echo-stateless.localhost/mcp

# 8. Performance Tests
echo -e "\n${BLUE}8. Running performance tests...${NC}"

echo "Testing rapid command execution..."
START_TIME=$(date +%s)
for i in {1..10}; do
    just exec "echo message=\"Performance test $i\"" > /dev/null 2>&1
done
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo -e "${GREEN}✓ Executed 10 commands in ${DURATION} seconds${NC}"

# 9. Concurrent Access Tests
echo -e "\n${BLUE}9. Testing concurrent access...${NC}"

echo "Running parallel requests..."
for i in {1..5}; do
    (just exec "echo message=\"Concurrent request $i\"" > /tmp/mcp-test-$i.log 2>&1) &
done
wait

# Check all completed successfully
CONCURRENT_SUCCESS=true
for i in {1..5}; do
    if ! grep -q "Concurrent request $i" /tmp/mcp-test-$i.log 2>/dev/null; then
        CONCURRENT_SUCCESS=false
        break
    fi
    rm -f /tmp/mcp-test-$i.log
done

if [ "$CONCURRENT_SUCCESS" = true ]; then
    echo -e "${GREEN}✓ Concurrent access handled correctly${NC}"
else
    echo -e "${RED}✗ Concurrent access failed${NC}"
fi

# 10. Summary
echo -e "\n${BLUE}=== Test Summary ===${NC}"
echo ""
echo "Test configuration:"
echo "  - Client directory: ${CLIENT_DIR}"
echo "  - Server URL: $(grep MCP_SERVER_URL ${CLIENT_DIR}/.env | cut -d= -f2-)"
echo "  - Client ID: $(grep MCP_CLIENT_ID ${CLIENT_DIR}/.env | cut -d= -f2- | cut -c1-20)..."
echo ""
echo -e "${GREEN}Testing complete!${NC}"
echo ""
echo "To run the client manually:"
echo "  cd mcp-streamablehttp-client"
echo "  just run                    # Run in proxy mode"
echo "  just exec '<command>'       # Execute single command"
echo ""
echo "To use with Claude Desktop:"
echo "  1. Add to Claude Desktop config:"
echo "     ${CLIENT_DIR}/mcp-streamablehttp-client"
echo "  2. Restart Claude Desktop"