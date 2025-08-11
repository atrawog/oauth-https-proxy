#!/bin/bash

# Test script for all just commands affected by async migration
# This script will test each command category and report failures

set -e  # Exit on first error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Testing all affected just commands"
echo "========================================="

# Function to test a command
test_command() {
    local cmd="$1"
    local desc="$2"
    echo -e "${YELLOW}Testing: $desc${NC}"
    if eval "$cmd" > /tmp/test_output.txt 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "Command: $cmd"
        echo "Output:"
        cat /tmp/test_output.txt
        return 1
    fi
}

# Track failures
FAILURES=()

echo ""
echo "=== TOKEN MANAGEMENT TESTS ==="

# Generate a unique test token name
TEST_TOKEN_NAME="test-async-$(date +%s)"
TEST_EMAIL="test@example.com"

# Test token generation
if ! test_command "just token-generate $TEST_TOKEN_NAME $TEST_EMAIL" "Token generation"; then
    FAILURES+=("token-generate")
fi

# Extract the token value for further tests
if [ ${#FAILURES[@]} -eq 0 ]; then
    TOKEN_VALUE=$(just token-show $TEST_TOKEN_NAME 2>/dev/null | jq -r '.token' || echo "")
    if [ -z "$TOKEN_VALUE" ]; then
        echo -e "${RED}Failed to extract token value${NC}"
        FAILURES+=("token-show-extract")
    else
        echo -e "${GREEN}Token extracted: ${TOKEN_VALUE:0:20}...${NC}"
    fi
fi

# Test token list
if ! test_command "just token-list" "Token list (unauthenticated)"; then
    # This might fail without auth, try with token
    if [ ! -z "$TOKEN_VALUE" ]; then
        if ! test_command "just token-list $TOKEN_VALUE" "Token list (authenticated)"; then
            FAILURES+=("token-list")
        fi
    else
        FAILURES+=("token-list")
    fi
fi

# Test token info
if [ ! -z "$TOKEN_VALUE" ]; then
    if ! test_command "curl -s http://localhost:9000/api/v1/tokens/info -H 'Authorization: Bearer $TOKEN_VALUE'" "Token info API"; then
        FAILURES+=("token-info")
    fi
fi

# Test token email update
if [ ! -z "$TOKEN_VALUE" ]; then
    if ! test_command "just token-email $TEST_TOKEN_NAME newemail@example.com $TOKEN_VALUE" "Token email update"; then
        FAILURES+=("token-email")
    fi
fi

# Test token deletion
if [ ! -z "$TOKEN_VALUE" ]; then
    if ! test_command "just token-delete $TEST_TOKEN_NAME $TOKEN_VALUE" "Token deletion"; then
        FAILURES+=("token-delete")
    fi
fi

echo ""
echo "=== ROUTE MANAGEMENT TESTS ==="

# Test route listing
if ! test_command "just route-list" "Route list"; then
    FAILURES+=("route-list")
fi

# Test route creation
ROUTE_ID="test-route-$(date +%s)"
if ! test_command "just route-create /test/$ROUTE_ID service api 50" "Route creation"; then
    FAILURES+=("route-create")
else
    # Test route deletion
    if ! test_command "just route-delete $ROUTE_ID" "Route deletion"; then
        FAILURES+=("route-delete")
    fi
fi

echo ""
echo "=== CERTIFICATE TESTS ==="

# Test certificate listing
if ! test_command "just cert-list" "Certificate list"; then
    FAILURES+=("cert-list")
fi

echo ""
echo "=== PROXY TESTS ==="

# Create a test token for proxy operations
PROXY_TOKEN_NAME="proxy-test-$(date +%s)"
just token-generate $PROXY_TOKEN_NAME proxy@example.com 2>/dev/null
PROXY_TOKEN=$(just token-show $PROXY_TOKEN_NAME 2>/dev/null | jq -r '.token' || echo "")

if [ ! -z "$PROXY_TOKEN" ]; then
    # Test proxy listing
    if ! test_command "just proxy-list $PROXY_TOKEN" "Proxy list"; then
        FAILURES+=("proxy-list")
    fi
    
    # Test proxy creation
    PROXY_HOSTNAME="test-proxy-$(date +%s).localhost"
    if ! test_command "just proxy-create $PROXY_HOSTNAME http://localhost:8080 true true true true proxy@example.com $PROXY_TOKEN" "Proxy creation"; then
        FAILURES+=("proxy-create")
    else
        # Test proxy show
        if ! test_command "just proxy-show $PROXY_HOSTNAME $PROXY_TOKEN" "Proxy show"; then
            FAILURES+=("proxy-show")
        fi
        
        # Test proxy deletion
        if ! test_command "just proxy-delete $PROXY_HOSTNAME false false $PROXY_TOKEN" "Proxy deletion"; then
            FAILURES+=("proxy-delete")
        fi
    fi
    
    # Clean up proxy test token
    just token-delete $PROXY_TOKEN_NAME $PROXY_TOKEN 2>/dev/null
fi

echo ""
echo "=== SERVICE TESTS ==="

# Create a test token for service operations
SERVICE_TOKEN_NAME="service-test-$(date +%s)"
just token-generate $SERVICE_TOKEN_NAME service@example.com 2>/dev/null
SERVICE_TOKEN=$(just token-show $SERVICE_TOKEN_NAME 2>/dev/null | jq -r '.token' || echo "")

if [ ! -z "$SERVICE_TOKEN" ]; then
    # Test service listing
    if ! test_command "just service-list false $SERVICE_TOKEN" "Service list"; then
        FAILURES+=("service-list")
    fi
    
    # Test external service registration
    SERVICE_NAME="test-external-$(date +%s)"
    if ! test_command "just service-register $SERVICE_NAME http://example.com 'Test service' $SERVICE_TOKEN" "External service registration"; then
        FAILURES+=("service-register")
    else
        # Test external service show
        if ! test_command "just service-show-external $SERVICE_NAME $SERVICE_TOKEN" "External service show"; then
            FAILURES+=("service-show-external")
        fi
        
        # Test external service deletion
        if ! test_command "just service-unregister $SERVICE_NAME $SERVICE_TOKEN" "External service deletion"; then
            FAILURES+=("service-unregister")
        fi
    fi
    
    # Clean up service test token
    just token-delete $SERVICE_TOKEN_NAME $SERVICE_TOKEN 2>/dev/null
fi

echo ""
echo "=== LOG TESTS ==="

# Create admin token for log operations
ADMIN_TOKEN_NAME="admin-test-$(date +%s)"
just token-generate $ADMIN_TOKEN_NAME admin@example.com 2>/dev/null
ADMIN_TOKEN=$(just token-show $ADMIN_TOKEN_NAME 2>/dev/null | jq -r '.token' || echo "")

if [ ! -z "$ADMIN_TOKEN" ]; then
    # Test log commands
    if ! test_command "just logs 1 '' '' '' 10 $ADMIN_TOKEN" "Logs query"; then
        FAILURES+=("logs")
    fi
    
    if ! test_command "just logs-stats 1 $ADMIN_TOKEN" "Logs statistics"; then
        FAILURES+=("logs-stats")
    fi
    
    if ! test_command "just logs-errors 1 10 $ADMIN_TOKEN" "Logs errors"; then
        FAILURES+=("logs-errors")
    fi
    
    # Clean up admin token
    just token-delete $ADMIN_TOKEN_NAME $ADMIN_TOKEN 2>/dev/null
fi

echo ""
echo "========================================="
echo "TEST RESULTS"
echo "========================================="

if [ ${#FAILURES[@]} -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Failed tests: ${FAILURES[*]}${NC}"
    echo ""
    echo "Failed command count: ${#FAILURES[@]}"
    exit 1
fi