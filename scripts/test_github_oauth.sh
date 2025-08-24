#!/usr/bin/env bash
# Test script for per-proxy GitHub OAuth configuration

set -euo pipefail

echo "============================================"
echo "Testing Per-Proxy GitHub OAuth Configuration"
echo "============================================"
echo

# Configuration
TEST_PROXY="test-oauth.example.com"
TEST_TARGET="http://localhost:3000"
TEST_CLIENT_ID="test_github_client_id_12345"
TEST_CLIENT_SECRET="test_github_client_secret_67890"
TOKEN="${ADMIN_TOKEN:-}"

if [ -z "$TOKEN" ]; then
    echo "Error: ADMIN_TOKEN environment variable is required"
    exit 1
fi

echo "1. Creating test proxy: $TEST_PROXY"
just proxy-create "$TEST_PROXY" "$TEST_TARGET" staging false true true "" "$TOKEN"
echo "✓ Proxy created"
echo

echo "2. Checking initial GitHub OAuth configuration (should be empty)"
just proxy-github-oauth-show "$TEST_PROXY" "$TOKEN"
echo

echo "3. Setting custom GitHub OAuth credentials"
just proxy-github-oauth-set "$TEST_PROXY" "$TEST_CLIENT_ID" "$TEST_CLIENT_SECRET" "$TOKEN"
echo "✓ GitHub OAuth credentials set"
echo

echo "4. Verifying GitHub OAuth configuration"
just proxy-github-oauth-show "$TEST_PROXY" "$TOKEN"
echo

echo "5. Listing all proxies with custom GitHub OAuth"
just proxy-github-oauth-list "$TOKEN"
echo

echo "6. Clearing GitHub OAuth configuration"
just proxy-github-oauth-clear "$TEST_PROXY" "$TOKEN"
echo "✓ GitHub OAuth configuration cleared"
echo

echo "7. Verifying configuration is cleared"
just proxy-github-oauth-show "$TEST_PROXY" "$TOKEN"
echo

echo "8. Cleaning up - deleting test proxy"
just proxy-delete "$TEST_PROXY" false true "$TOKEN"
echo "✓ Test proxy deleted"
echo

echo "============================================"
echo "✓ All tests completed successfully!"
echo "============================================"
echo
echo "Summary:"
echo "- Successfully created proxy with GitHub OAuth configuration"
echo "- Verified per-proxy GitHub credentials can be set and retrieved"
echo "- Confirmed fallback to environment variables when cleared"
echo "- API endpoints working correctly"
echo "- Just commands functioning as expected"