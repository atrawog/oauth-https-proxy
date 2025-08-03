#!/bin/bash
# Clean up old correlation ID-based logs from Redis

REDIS_PASSWORD="4be8bc87d4a3e8d285354e0aaf7f5a89482815f3b44e5ea35986fdab5cd23589"

echo "=== Cleaning up old correlation ID-based logs from Redis ==="
echo "Pattern: req:*-https-*"
echo

# Count old logs first
OLD_COUNT=$(echo "KEYS req:*-https-*" | docker exec -i mcp-http-proxy-redis-1 redis-cli -a "$REDIS_PASSWORD" 2>&1 | grep -v "Warning" | wc -l)
echo "Found $OLD_COUNT old-format log entries to delete"

if [ "$OLD_COUNT" -gt 0 ]; then
    echo "Deleting old logs..."
    
    # Delete in batches to avoid blocking Redis
    echo "KEYS req:*-https-*" | docker exec -i mcp-http-proxy-redis-1 redis-cli -a "$REDIS_PASSWORD" 2>&1 | grep -v "Warning" | while read key; do
        if [ ! -z "$key" ]; then
            echo "DEL $key" | docker exec -i mcp-http-proxy-redis-1 redis-cli -a "$REDIS_PASSWORD" 2>&1 | grep -v "Warning" > /dev/null
        fi
    done
    
    echo "Old logs deleted."
fi

echo
echo "=== Checking new IP-based logs ==="
NEW_COUNT=$(echo "ZCARD idx:req:all" | docker exec -i mcp-http-proxy-redis-1 redis-cli -a "$REDIS_PASSWORD" 2>&1 | grep -v "Warning")
echo "New RequestLogger has indexed $NEW_COUNT requests"

echo
echo "=== Sample of recent requests from new logger ==="
echo "ZRANGE idx:req:all -5 -1" | docker exec -i mcp-http-proxy-redis-1 redis-cli -a "$REDIS_PASSWORD" 2>&1 | grep -v "Warning"

echo
echo "=== Cleanup complete ==="