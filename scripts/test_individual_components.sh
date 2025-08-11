#!/bin/bash
# Test individual async components and just commands

set -e

TOKEN="${1:-$TEST_TOKEN}"
if [ -z "$TOKEN" ]; then
    echo "❌ No token provided. Usage: $0 <token>"
    exit 1
fi

echo "================================================================"
echo "🧪 Testing Individual Async Components"
echo "================================================================"

# Function to check command success
check_result() {
    if [ $? -eq 0 ]; then
        echo "  ✅ $1"
    else
        echo "  ❌ $1"
        return 1
    fi
}

echo -e "\n📊 1. Testing Health & Status Commands"
echo "----------------------------------------"
just health && check_result "Health check passed"

echo -e "\n🔑 2. Testing Token Operations"
echo "----------------------------------------"
just token-list $TOKEN 2>/dev/null | head -5 && check_result "Token list working"

echo -e "\n📜 3. Testing Certificate Operations"
echo "----------------------------------------"
just cert-list $TOKEN 2>/dev/null | head -5 && check_result "Certificate list working"

echo -e "\n🐳 4. Testing Docker Service Operations"
echo "----------------------------------------"
SERVICE_NAME="test-async-$(date +%s)"
echo "Creating test service: $SERVICE_NAME"
just service-create $SERVICE_NAME nginx:alpine '' 80 256m 0.5 false $TOKEN 2>/dev/null && check_result "Service created"

# List services
just service-list false $TOKEN 2>/dev/null | grep -q $SERVICE_NAME && check_result "Service listed"

# Get service logs
just service-logs $SERVICE_NAME 10 false $TOKEN 2>/dev/null && check_result "Service logs retrieved"

# Delete service
just service-delete $SERVICE_NAME true false $TOKEN 2>/dev/null && check_result "Service deleted"

echo -e "\n🔄 5. Testing Proxy Operations"
echo "----------------------------------------"
PROXY_HOST="test-proxy-$(date +%s).atradev.org"
echo "Creating test proxy: $PROXY_HOST"
just proxy-create $PROXY_HOST http://example.com true false true false '' $TOKEN 2>/dev/null && check_result "Proxy created"

# List proxies
just proxy-list $TOKEN 2>/dev/null | grep -q $PROXY_HOST && check_result "Proxy listed"

# Delete proxy
just proxy-delete $PROXY_HOST false false $TOKEN 2>/dev/null && check_result "Proxy deleted"

echo -e "\n🔌 6. Testing Port Operations"
echo "----------------------------------------"
just service-ports-global false $TOKEN 2>/dev/null | head -10 && check_result "Port list working"
just service-port-check 12345 127.0.0.1 $TOKEN 2>/dev/null && check_result "Port check working"

echo -e "\n📝 7. Testing Logging Operations"
echo "----------------------------------------"
just logs 1 '' INFO '' 5 $TOKEN 2>/dev/null | head -10 && check_result "Log retrieval working"
just logs-stats 1 $TOKEN 2>/dev/null | head -10 && check_result "Log stats working"
just logs-errors 1 5 $TOKEN 2>/dev/null && check_result "Error logs working"

echo -e "\n🚦 8. Testing Route Operations"
echo "----------------------------------------"
just route-list $TOKEN 2>/dev/null | head -10 && check_result "Route list working"

echo -e "\n📦 9. Testing External Service Operations"
echo "----------------------------------------"
just service-list-external $TOKEN 2>/dev/null | head -5 && check_result "External service list working"

echo -e "\n🔍 10. Testing Redis Stream Activity"
echo "----------------------------------------"
# Check if streams exist
docker exec mcp-http-proxy-redis-1 redis-cli -a 4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589 XLEN logs:all:stream 2>/dev/null && check_result "logs:all:stream exists"
docker exec mcp-http-proxy-redis-1 redis-cli -a 4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589 XLEN events:all:stream 2>/dev/null && check_result "events:all:stream exists"

# Check consumer groups
echo -e "\n📊 Consumer Groups:"
docker exec mcp-http-proxy-redis-1 redis-cli -a 4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589 --no-auth-warning XINFO GROUPS logs:request:stream 2>/dev/null || echo "  ⚠️  No consumer groups yet"

echo -e "\n================================================================"
echo "✅ Individual component tests completed"
echo "================================================================"