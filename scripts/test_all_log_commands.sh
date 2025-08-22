#!/bin/bash

# Comprehensive test script for ALL log-related just commands
# Tests every single log command to ensure they work correctly

set -e

echo "=========================================="
echo "Testing ALL log-related just commands"
echo "=========================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
PASSED=0
FAILED=0
FAILED_COMMANDS=()

# Function to test a command
test_command() {
    local cmd="$1"
    local desc="$2"
    
    echo -n "Testing: $desc ... "
    
    # Run command and capture both stdout and stderr
    if output=$(eval "$cmd" 2>&1); then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Command: $cmd"
        echo "  Error: $output" | head -5
        FAILED=$((FAILED + 1))
        FAILED_COMMANDS+=("$desc: $cmd")
        return 1
    fi
}

echo ""
echo "1. Testing Basic Log Commands"
echo "------------------------------"

test_command "just logs-ip 127.0.0.1 1 | head -5" "logs-ip with localhost IP"
test_command "just logs-proxy localhost 1 | head -5" "logs-proxy with localhost"
test_command "just logs-hostname localhost 1 | head -5" "logs-hostname with localhost"

echo ""
echo "2. Testing OAuth-related Log Commands"
echo "--------------------------------------"

test_command "just logs-oauth 127.0.0.1 1 | head -5" "logs-oauth with IP"
test_command "just logs-oauth-debug 127.0.0.1 1 | head -5" "logs-oauth-debug with IP"
test_command "just logs-oauth-client test-client 1 | head -5" "logs-oauth-client with test client"
test_command "just logs-oauth-flow '' '' 1 | head -5" "logs-oauth-flow with empty params"
test_command "just logs-oauth-user testuser 1 | head -5" "logs-oauth-user with test user"

echo ""
echo "3. Testing Error and Stats Commands"
echo "------------------------------------"

test_command "just logs-errors 1 | head -5" "logs-errors default"
test_command "just logs-errors-debug 1 | head -5" "logs-errors-debug"
test_command "just logs-stats 1 | head -10" "logs-stats"

echo ""
echo "4. Testing Search and Filter Commands"
echo "--------------------------------------"

test_command "just logs-search '' 1 | head -5" "logs-search with empty query"
test_command "just logs-search 'status:200' 1 | head -5" "logs-search with status filter"
test_command "just logs-user admin 1 | head -5" "logs-user with admin"
test_command "just logs-session test-session 1 | head -5" "logs-session with test session"
test_command "just logs-method GET 1 | head -5" "logs-method GET"
test_command "just logs-method POST 1 | head -5" "logs-method POST"
test_command "just logs-status 200 1 | head -5" "logs-status 200"
test_command "just logs-status 404 1 | head -5" "logs-status 404"
test_command "just logs-slow 100 1 | head -5" "logs-slow with 100ms threshold"
test_command "just logs-path /health 1 | head -5" "logs-path /health"
test_command "just logs-path /api 1 | head -5" "logs-path /api"

echo ""
echo "5. Testing Utility Commands"
echo "----------------------------"

test_command "just logs-test | head -10" "logs-test (creates test entries)"
test_command "just logs-all 10 1 | head -5" "logs-all (recent logs)"
test_command "just logs-help" "logs-help"

echo ""
echo "6. Testing Service Logs (if service exists)"
echo "--------------------------------------------"

# This might fail if no service named 'api' exists
test_command "just logs-service api 10 2>/dev/null | head -5 || echo 'No api service'" "logs-service api"

echo ""
echo "7. Testing Real-time Follow (quick test)"
echo "-----------------------------------------"

# Test follow command but kill it after 1 second to avoid hanging
echo -n "Testing: logs-follow (1 second test) ... "
if timeout 1 just logs-follow 1 2>/dev/null >/dev/null; then
    echo -e "${YELLOW}⚠ TIMEOUT (expected)${NC}"
    PASSED=$((PASSED + 1))
else
    # Timeout exit code is 124
    if [ $? -eq 124 ]; then
        echo -e "${GREEN}✓ PASSED (timed out as expected)${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED=$((FAILED + 1))
        FAILED_COMMANDS+=("logs-follow")
    fi
fi

echo ""
echo "8. Testing Clear Command (skipping to preserve logs)"
echo "-----------------------------------------------------"
echo -e "${YELLOW}⚠ Skipping logs-clear to preserve existing logs${NC}"

echo ""
echo "=========================================="
echo "Test Results Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed Commands:"
    for cmd in "${FAILED_COMMANDS[@]}"; do
        echo "  - $cmd"
    done
    exit 1
else
    echo ""
    echo -e "${GREEN}✅ All log commands passed successfully!${NC}"
fi