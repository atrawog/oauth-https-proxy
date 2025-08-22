#!/bin/bash

# Test script for new logging commands
# Tests both just commands and proxy-client commands

set -e

echo "Testing new logging commands..."
echo "================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to test a command
test_command() {
    local cmd="$1"
    local desc="$2"
    
    echo -n "Testing: $desc ... "
    
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo "  Command failed: $cmd"
        return 1
    fi
}

# Test justfile commands
echo ""
echo "Testing justfile commands:"
echo "--------------------------"

test_command "just logs-recent 10" "logs-recent"
test_command "just logs-errors 1 10" "logs-errors"
test_command "just logs-stats 1" "logs-stats"
test_command "just logs-ip 127.0.0.1 1 10" "logs-ip"
test_command "just logs-hostname localhost 1 10" "logs-hostname"
test_command "just logs-proxy api.example.com 1 10" "logs-proxy"
test_command "just logs-oauth 127.0.0.1 1 10" "logs-oauth"
test_command "just logs-user admin 1 10" "logs-user"
test_command "just logs-session test-session 1 10" "logs-session"
test_command "just logs-method GET 1 10" "logs-method"
test_command "just logs-status 200 1 10" "logs-status"
test_command "just logs-path /api 1 10" "logs-path"
test_command "just logs-slow 1000 1 10" "logs-slow"
test_command "just logs-oauth-client test-client 1 10" "logs-oauth-client"
test_command "just logs-search 'status:200' 1 10" "logs-search"

# Test proxy-client commands  
echo ""
echo "Testing proxy-client commands:"
echo "-------------------------------"

test_command "proxy-client log recent --limit 10" "log recent"
test_command "proxy-client log errors --hours 1" "log errors"
test_command "proxy-client log stats --hours 1" "log stats"
test_command "proxy-client log by-ip 127.0.0.1 --hours 1" "log by-ip"
test_command "proxy-client log by-hostname localhost --hours 1" "log by-hostname"
test_command "proxy-client log by-proxy api.example.com --hours 1" "log by-proxy"
test_command "proxy-client log oauth 127.0.0.1 --hours 1" "log oauth"
test_command "proxy-client log by-user admin --hours 1" "log by-user"
test_command "proxy-client log by-session test-session --hours 1" "log by-session"
test_command "proxy-client log by-method GET --hours 1" "log by-method"
test_command "proxy-client log by-status 200 --hours 1" "log by-status"
test_command "proxy-client log by-path /api --hours 1" "log by-path"
test_command "proxy-client log slow --threshold 1000 --hours 1" "log slow"
test_command "proxy-client log by-oauth-client test-client --hours 1" "log by-oauth-client"
test_command "proxy-client log search --query 'status:200' --hours 1" "log search"

echo ""
echo "================================"
echo "Testing complete!"