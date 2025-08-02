#!/usr/bin/env bash
# Test script to verify all logging commands work properly

set -euo pipefail

echo "=== Testing Logging Commands ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to test a command
test_command() {
    local cmd="$1"
    local description="$2"
    
    echo -n "Testing: $description... "
    
    if timeout 5s bash -c "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "  Command: $cmd"
    fi
}

# Test Docker logs commands
echo "🐳 Testing Docker Container Logs:"
test_command "just logs lines=5" "just logs (Docker logs)"
test_command "just logs proxy lines=5" "just logs proxy (specific service)"

echo ""
echo "📋 Testing Application Logs:"

# First, make a test request to generate logs
echo "Making test request to generate logs..."
curl -s http://localhost/health > /dev/null || true
sleep 2

# Test application log commands
test_command "just app-logs hours=1 limit=5" "just app-logs"
test_command "just app-logs-recent limit=5" "just app-logs-recent"
test_command "just app-logs-event-stats hours=1" "just app-logs-event-stats"
test_command "just app-logs-errors hours=1 limit=5" "just app-logs-errors"

# Test search commands (these should work even with no results)
test_command "just app-logs-by-ip 127.0.0.1 hours=1 limit=5" "just app-logs-by-ip"
test_command "just app-logs-search query=health hours=1 limit=5" "just app-logs-search"

echo ""
echo "✅ Testing complete!"
echo ""
echo "Note: Some commands may show no results if there's no matching log data."
echo "The important thing is that they execute without errors."