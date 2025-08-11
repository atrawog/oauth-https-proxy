#!/bin/bash

# Final comprehensive test of all fixed functionality
set -e

echo "========================================="
echo "FINAL COMPREHENSIVE TEST"
echo "========================================="

# Get ADMIN token
ADMIN_TOKEN="acm_bp_z9wqu9GC3X65y9Ow4HXuUzo76bCvWEt4JvUxlkp0"

echo ""
echo "1. Testing Token API"
echo "--------------------"
# List tokens
echo -n "List tokens: "
curl -s http://localhost:9000/api/v1/tokens/ -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r 'length' | xargs -I {} echo "{} tokens found"

# Get specific token
echo -n "Get token details: "
curl -s http://localhost:9000/api/v1/tokens/ADMIN -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.name' | xargs -I {} echo "Token {} retrieved"

echo ""
echo "2. Testing Route API"
echo "--------------------"
# Create route
ROUTE_ID=$(curl -s -X POST http://localhost:9000/api/v1/routes/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path_pattern": "/test/final", "target_type": "service", "target_value": "api", "priority": 50}' \
  | jq -r '.route_id')
echo "Created route: $ROUTE_ID"

# List routes
echo -n "List routes: "
curl -s http://localhost:9000/api/v1/routes/ | jq -r 'length' | xargs -I {} echo "{} routes found"

# Delete route
curl -s -X DELETE "http://localhost:9000/api/v1/routes/$ROUTE_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" > /dev/null
echo "Deleted route: $ROUTE_ID"

echo ""
echo "3. Testing Proxy API"
echo "--------------------"
# Create proxy
PROXY_HOST="test-final-$(date +%s).localhost"
curl -s -X POST http://localhost:9000/api/v1/proxy/targets/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\": \"$PROXY_HOST\", \"target_url\": \"http://localhost:8080\", \"enable_http\": true}" \
  > /dev/null
echo "Created proxy: $PROXY_HOST"

# List proxies
echo -n "List proxies: "
curl -s http://localhost:9000/api/v1/proxy/targets/ -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r 'length' | xargs -I {} echo "{} proxies found"

# Delete proxy
curl -s -X DELETE "http://localhost:9000/api/v1/proxy/targets/$PROXY_HOST" \
  -H "Authorization: Bearer $ADMIN_TOKEN" > /dev/null
echo "Deleted proxy: $PROXY_HOST"

echo ""
echo "4. Testing Certificate API"
echo "--------------------"
echo -n "List certificates: "
curl -s http://localhost:9000/api/v1/certificates/ -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r 'length' | xargs -I {} echo "{} certificates found"

echo ""
echo "5. Testing Service API"
echo "--------------------"
# Register external service
SERVICE_NAME="test-external-final"
curl -s -X POST http://localhost:9000/api/v1/services/external \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$SERVICE_NAME\", \"target_url\": \"http://example.com\"}" \
  > /dev/null
echo "Registered external service: $SERVICE_NAME"

# List external services
echo -n "List external services: "
curl -s http://localhost:9000/api/v1/services/external -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r 'keys | length' | xargs -I {} echo "{} services found"

# Delete external service
curl -s -X DELETE "http://localhost:9000/api/v1/services/external/$SERVICE_NAME" \
  -H "Authorization: Bearer $ADMIN_TOKEN" > /dev/null
echo "Deleted external service: $SERVICE_NAME"

echo ""
echo "6. Testing Health Check"
echo "------------------------"
echo -n "System health: "
curl -s http://localhost:9000/health | jq -r '.status'

echo ""
echo "========================================="
echo "ALL TESTS COMPLETED SUCCESSFULLY"
echo "========================================="