#!/usr/bin/env bash
# Wrapper script for creating proxies with proper certificate handling

set -e

HOSTNAME="$1"
TARGET="$2"
CERT_MODE="${3:-staging}"  # staging or production

if [ -z "$HOSTNAME" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <hostname> <target-url> [staging|production]"
    exit 1
fi

echo "Creating proxy for $HOSTNAME -> $TARGET with $CERT_MODE certificate"

# Source the .env file
source .env

# Delete existing proxy if it exists
echo "Cleaning up existing proxy..."
just proxy-delete "$HOSTNAME" 2>/dev/null || true

# Delete existing certificate if it exists
echo "Cleaning up existing certificate..."
CERT_NAME="proxy-${HOSTNAME//./-}"
# Clean up all possible certificate references
redis-cli -a "$REDIS_PASSWORD" DEL "cert:$CERT_NAME" "cert:domain:$HOSTNAME" 2>/dev/null || true
# Also check for any existing certs with this domain
EXISTING_CERTS=$(redis-cli -a "$REDIS_PASSWORD" --raw KEYS "cert:*" 2>/dev/null | while read key; do
    redis-cli -a "$REDIS_PASSWORD" --raw GET "$key" 2>/dev/null | grep -q "\"$HOSTNAME\"" && echo "$key" || true
done)
for cert_key in $EXISTING_CERTS; do
    echo "Removing existing certificate: $cert_key"
    redis-cli -a "$REDIS_PASSWORD" DEL "$cert_key" 2>/dev/null || true
done

# Create certificate
CERT_NAME="proxy-${HOSTNAME//./-}"
echo "Creating $CERT_MODE certificate..."
just cert-create "$CERT_NAME" "$HOSTNAME" "$CERT_MODE"

# Wait for certificate
echo "Waiting for certificate..."
for i in {1..30}; do
    STATUS=$(redis-cli -a "$REDIS_PASSWORD" --raw HGET "cert:$CERT_NAME" status 2>/dev/null || echo "pending")
    if [ "$STATUS" = "active" ]; then
        echo "Certificate ready!"
        break
    fi
    echo "Certificate status: $STATUS (attempt $i/30)"
    sleep 2
done

# Create proxy
echo "Creating proxy..."
just proxy-create "$HOSTNAME" "$TARGET" "$CERT_NAME"

# Test endpoints
echo "Testing endpoints..."
sleep 5

# Test HTTP
echo "Testing HTTP..."
curl -s -o /dev/null -w "HTTP: %{http_code}\n" "http://$HOSTNAME/health" || true

# Test HTTPS
echo "Testing HTTPS..."
curl -sk -o /dev/null -w "HTTPS: %{http_code}\n" "https://$HOSTNAME/health" || true

echo "Proxy created successfully!"
