#!/usr/bin/env bash
set -euo pipefail

echo "=== Verifying X-HackerOne-Research headers on all proxies ==="
echo ""

# List of all proxies from our update script
PROXIES=(
    "everything-b.atradev.org"
    "everything-d.atradev.org"
    "everything-a.atradev.org"
    "test-resource.localhost"
    "everything-e.atradev.org"
    "everything-g.atradev.org"
    "auth.atradev.org"
    "everything.atradev.org"
    "test-auth2.local"
    "echo-stateful.atradev.org"
    "everything-f.atradev.org"
    "everything-c.atradev.org"
    "test-auth.local"
)

SUCCESS_COUNT=0
FAIL_COUNT=0

for proxy in "${PROXIES[@]}"; do
    
    # Get custom headers for this proxy
    custom_headers=$(just proxy-show "$proxy" 2>/dev/null | jq -r '.custom_headers // {}')
    hackerone_header=$(echo "$custom_headers" | jq -r '."X-HackerOne-Research" // "not set"')
    
    if [ "$hackerone_header" = "atrawog" ]; then
        echo "✅ $proxy: X-HackerOne-Research = $hackerone_header"
        ((SUCCESS_COUNT++))
    elif [ "$hackerone_header" = "not set" ]; then
        echo "❌ $proxy: X-HackerOne-Research header not set"
        ((FAIL_COUNT++))
    else
        echo "⚠️  $proxy: X-HackerOne-Research = $hackerone_header (expected: atrawog)"
        ((FAIL_COUNT++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Total proxies checked: $((SUCCESS_COUNT + FAIL_COUNT))"
echo "Successfully configured: $SUCCESS_COUNT"
echo "Failed/Missing: $FAIL_COUNT"