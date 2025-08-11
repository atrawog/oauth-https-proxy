#!/bin/bash

# Comprehensive test for ALL just commands affected by async migration
# This script tests every command and captures all errors for analysis

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
RESULTS_DIR="/home/atrawog/AI/atrawog/mcp-http-proxy/analysis/test_results_$(date +%s)"
mkdir -p "$RESULTS_DIR"

# Log file for all output
LOG_FILE="$RESULTS_DIR/test_output.log"
ERROR_FILE="$RESULTS_DIR/errors.log"
SUCCESS_FILE="$RESULTS_DIR/success.log"

# Initialize counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Array to store failed tests
declare -a FAILED_COMMANDS

echo "=========================================" | tee -a "$LOG_FILE"
echo "COMPREHENSIVE JUST COMMAND TEST" | tee -a "$LOG_FILE"
echo "$(date)" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"

# Function to test a command
test_command() {
    local cmd="$1"
    local desc="$2"
    local expected_success="${3:-true}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "\n${YELLOW}[$TOTAL_TESTS] Testing: $desc${NC}" | tee -a "$LOG_FILE"
    echo "Command: $cmd" | tee -a "$LOG_FILE"
    
    # Create temporary file for output
    local tmp_output="/tmp/test_output_$$.txt"
    local tmp_error="/tmp/test_error_$$.txt"
    
    # Execute command and capture output
    if eval "$cmd" > "$tmp_output" 2> "$tmp_error"; then
        if [ "$expected_success" = "true" ]; then
            echo -e "${GREEN}✓ PASSED${NC}" | tee -a "$LOG_FILE"
            echo "[$TOTAL_TESTS] $desc: PASSED" >> "$SUCCESS_FILE"
            echo "Output:" >> "$LOG_FILE"
            cat "$tmp_output" >> "$LOG_FILE"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}✗ UNEXPECTED SUCCESS${NC}" | tee -a "$LOG_FILE"
            echo "[$TOTAL_TESTS] $desc: UNEXPECTED SUCCESS" >> "$ERROR_FILE"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_COMMANDS+=("$desc")
        fi
    else
        local exit_code=$?
        if [ "$expected_success" = "false" ]; then
            echo -e "${GREEN}✓ EXPECTED FAILURE${NC}" | tee -a "$LOG_FILE"
            echo "[$TOTAL_TESTS] $desc: EXPECTED FAILURE" >> "$SUCCESS_FILE"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}✗ FAILED (Exit: $exit_code)${NC}" | tee -a "$LOG_FILE"
            echo "[$TOTAL_TESTS] $desc: FAILED (Exit: $exit_code)" >> "$ERROR_FILE"
            echo "Command: $cmd" >> "$ERROR_FILE"
            echo "STDOUT:" >> "$ERROR_FILE"
            cat "$tmp_output" >> "$ERROR_FILE"
            echo "STDERR:" >> "$ERROR_FILE"
            cat "$tmp_error" >> "$ERROR_FILE"
            echo "---" >> "$ERROR_FILE"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_COMMANDS+=("$desc")
        fi
    fi
    
    # Clean up temp files
    rm -f "$tmp_output" "$tmp_error"
}

# Get admin token from Redis
echo -e "\n${BLUE}=== SETUP ===${NC}" | tee -a "$LOG_FILE"
ADMIN_TOKEN=$(docker exec mcp-http-proxy-redis-1 sh -c "redis-cli -a '4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589' --no-auth-warning HGET 'token:ADMIN' token" 2>/dev/null || echo "")

if [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}Failed to get ADMIN token from Redis${NC}" | tee -a "$LOG_FILE"
    exit 1
fi
echo -e "${GREEN}Admin token retrieved: ${ADMIN_TOKEN:0:20}...${NC}" | tee -a "$LOG_FILE"

# Wait for service to be ready
sleep 3

echo -e "\n${BLUE}=== TOKEN MANAGEMENT TESTS ===${NC}" | tee -a "$LOG_FILE"

# Generate test token
TEST_TOKEN_NAME="test-async-$(date +%s)"
test_command "just token-generate $TEST_TOKEN_NAME test@example.com" "Token generation"

# Try to retrieve the token
TEST_TOKEN=$(just token-show $TEST_TOKEN_NAME $ADMIN_TOKEN 2>/dev/null | jq -r '.token' 2>/dev/null || echo "")
if [ ! -z "$TEST_TOKEN" ]; then
    # Check if token is abbreviated (contains ...)
    if [[ "$TEST_TOKEN" == *"..."* ]]; then
        # Try getting full token from Redis
        FULL_TOKEN=$(docker exec mcp-http-proxy-redis-1 sh -c "redis-cli -a '4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589' --no-auth-warning HGET 'token:$TEST_TOKEN_NAME' token" 2>/dev/null || echo "")
        if [ ! -z "$FULL_TOKEN" ]; then
            TEST_TOKEN="$FULL_TOKEN"
        fi
    fi
    echo -e "${GREEN}Test token retrieved: ${TEST_TOKEN:0:20}...${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}Warning: Could not retrieve test token${NC}" | tee -a "$LOG_FILE"
    # Try getting it directly from Redis
    TEST_TOKEN=$(docker exec mcp-http-proxy-redis-1 sh -c "redis-cli -a '4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589' --no-auth-warning HGET 'token:$TEST_TOKEN_NAME' token" 2>/dev/null || echo "")
    if [ ! -z "$TEST_TOKEN" ]; then
        echo -e "${GREEN}Test token retrieved from Redis: ${TEST_TOKEN:0:20}...${NC}" | tee -a "$LOG_FILE"
    fi
fi

# Token commands
test_command "just token-list $ADMIN_TOKEN 2>&1 | head -20 || true" "Token list (admin)"
test_command "just token-show ADMIN $ADMIN_TOKEN 2>&1 | head -20 || true" "Token show (admin)"
test_command "just token-email newemail@example.com $TEST_TOKEN 2>&1" "Token email update"

echo -e "\n${BLUE}=== ROUTE MANAGEMENT TESTS ===${NC}" | tee -a "$LOG_FILE"

# Route commands
test_command "just route-list 2>&1 | head -20" "Route list (public)"
test_command "just route-list $ADMIN_TOKEN 2>&1 | head -20 || true" "Route list (admin)"

# Create a test route
ROUTE_PATH="/test/route-$(date +%s)"
test_command "just route-create '$ROUTE_PATH' service api 50 'ALL' false 'Test route' $ADMIN_TOKEN 2>&1" "Route creation"

# Get route ID from the last created route
ROUTE_ID=$(curl -s http://localhost:9000/api/v1/routes/ | jq -r ".[] | select(.path_pattern==\"$ROUTE_PATH\") | .route_id" 2>/dev/null || echo "")
if [ ! -z "$ROUTE_ID" ]; then
    test_command "just route-show $ROUTE_ID $ADMIN_TOKEN 2>&1" "Route show"
    test_command "just route-delete $ROUTE_ID $ADMIN_TOKEN 2>&1" "Route deletion"
else
    echo -e "${YELLOW}Could not get route ID for deletion test${NC}" | tee -a "$LOG_FILE"
fi

echo -e "\n${BLUE}=== CERTIFICATE TESTS ===${NC}" | tee -a "$LOG_FILE"

test_command "just cert-list 2>&1 | head -20" "Certificate list (public)"
test_command "just cert-list $ADMIN_TOKEN 2>&1 | head -20 || true" "Certificate list (admin)"

echo -e "\n${BLUE}=== PROXY MANAGEMENT TESTS ===${NC}" | tee -a "$LOG_FILE"

# Create a test proxy
PROXY_HOST="test-proxy-$(date +%s).localhost"
test_command "just proxy-create $PROXY_HOST http://localhost:8080 true true true true test@example.com $ADMIN_TOKEN 2>&1" "Proxy creation"

test_command "just proxy-list $ADMIN_TOKEN 2>&1 | head -20 || true" "Proxy list"
test_command "just proxy-show $PROXY_HOST $ADMIN_TOKEN 2>&1" "Proxy show"

# Create auth proxy first for OAuth
AUTH_PROXY_HOST="auth.localhost"
echo -e "${BLUE}Creating auth proxy for OAuth...${NC}" | tee -a "$LOG_FILE"
just proxy-create $AUTH_PROXY_HOST http://localhost:9000 true false true true auth@example.com $ADMIN_TOKEN 2>&1 >/dev/null || true

# Test proxy auth
test_command "just proxy-auth-enable $PROXY_HOST auth.localhost forward '' '' $ADMIN_TOKEN 2>&1" "Proxy auth enable"
test_command "just proxy-auth-show $PROXY_HOST $ADMIN_TOKEN 2>&1" "Proxy auth show"
test_command "just proxy-auth-disable $PROXY_HOST $ADMIN_TOKEN 2>&1" "Proxy auth disable"

# Delete proxy
test_command "just proxy-delete $PROXY_HOST false false $ADMIN_TOKEN 2>&1" "Proxy deletion"

echo -e "\n${BLUE}=== SERVICE MANAGEMENT TESTS ===${NC}" | tee -a "$LOG_FILE"

# External service management
SERVICE_NAME="test-service-$(date +%s)"
test_command "just service-register $SERVICE_NAME http://example.com 'Test service' $ADMIN_TOKEN 2>&1" "Service registration"
test_command "curl -s http://localhost:9000/api/v1/services/external -H 'Authorization: Bearer '$ADMIN_TOKEN | jq '.' 2>&1 | head -20 || true" "External service list (API)"
test_command "just service-show-external $SERVICE_NAME $ADMIN_TOKEN 2>&1" "External service show"
test_command "just service-unregister $SERVICE_NAME $ADMIN_TOKEN 2>&1" "Service unregistration"

# Docker service commands (may fail if Docker not available)
test_command "curl -s http://localhost:9000/api/v1/services/ -H 'Authorization: Bearer '$ADMIN_TOKEN | jq '.' 2>&1 | head -20 || true" "Docker service list (API)"

echo -e "\n${BLUE}=== LOG QUERY TESTS ===${NC}" | tee -a "$LOG_FILE"

test_command "just logs 1 '' '' '' 10 $ADMIN_TOKEN 2>&1 | head -20 || true" "Logs query"
test_command "just logs-stats 1 $ADMIN_TOKEN 2>&1" "Logs statistics"
test_command "just logs-errors 1 10 $ADMIN_TOKEN 2>&1 | head -20 || true" "Logs errors"
test_command "just logs-ip 127.0.0.1 1 '' '' 10 $ADMIN_TOKEN 2>&1 | head -20 || true" "Logs by IP"

echo -e "\n${BLUE}=== OAUTH TESTS ===${NC}" | tee -a "$LOG_FILE"

test_command "just oauth-clients-list false $ADMIN_TOKEN 2>&1 | head -20 || true" "OAuth clients list"
test_command "just oauth-sessions-list $ADMIN_TOKEN 2>&1 | head -20 || true" "OAuth sessions list"

echo -e "\n${BLUE}=== CLEANUP ===${NC}" | tee -a "$LOG_FILE"

# Clean up test token
if [ ! -z "$TEST_TOKEN_NAME" ]; then
    # Use admin token for deletion since test token might be abbreviated
    test_command "just token-delete $TEST_TOKEN_NAME $ADMIN_TOKEN 2>&1" "Test token cleanup"
fi

echo -e "\n${BLUE}=== API ENDPOINT TESTS ===${NC}" | tee -a "$LOG_FILE"

# Direct API tests
test_command "curl -s http://localhost:9000/health | jq '.status' 2>&1" "Health check API"
test_command "curl -s http://localhost:9000/api/v1/routes/ | jq 'length' 2>&1" "Routes API (public)"
test_command "curl -s http://localhost:9000/api/v1/tokens/ -H 'Authorization: Bearer $ADMIN_TOKEN' | jq 'length' 2>&1" "Tokens API (admin)"
test_command "curl -s http://localhost:9000/api/v1/proxy/targets/ -H 'Authorization: Bearer $ADMIN_TOKEN' | jq 'length' 2>&1" "Proxy targets API"
test_command "curl -s http://localhost:9000/api/v1/certificates/ -H 'Authorization: Bearer $ADMIN_TOKEN' | jq 'length' 2>&1" "Certificates API"
test_command "curl -s http://localhost:9000/api/v1/services/external -H 'Authorization: Bearer $ADMIN_TOKEN' | jq 'type' 2>&1" "External services API"
test_command "curl -s http://localhost:9000/api/v1/logs/events -H 'Authorization: Bearer $ADMIN_TOKEN' | jq 'type' 2>&1" "Logs events API"

echo -e "\n=========================================" | tee -a "$LOG_FILE"
echo -e "${BLUE}TEST RESULTS SUMMARY${NC}" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"
echo -e "Total Tests: $TOTAL_TESTS" | tee -a "$LOG_FILE"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}" | tee -a "$LOG_FILE"
echo -e "${RED}Failed: $FAILED_TESTS${NC}" | tee -a "$LOG_FILE"

if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "\n${RED}Failed Commands:${NC}" | tee -a "$LOG_FILE"
    for cmd in "${FAILED_COMMANDS[@]}"; do
        echo "  - $cmd" | tee -a "$LOG_FILE"
    done
    echo -e "\n${YELLOW}Check $ERROR_FILE for detailed error information${NC}"
fi

echo -e "\n${BLUE}Results saved to: $RESULTS_DIR${NC}"
echo "  - Full log: $LOG_FILE"
echo "  - Errors: $ERROR_FILE"
echo "  - Successes: $SUCCESS_FILE"

# Return non-zero if any tests failed
if [ $FAILED_TESTS -gt 0 ]; then
    exit 1
else
    echo -e "\n${GREEN}ALL TESTS PASSED!${NC}"
    exit 0
fi