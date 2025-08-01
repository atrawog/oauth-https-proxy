#!/bin/bash

# Token for authentication
TOKEN="acm_bp_z9wqu9GC3X65y9Ow4HXuUzo76bCvWEt4JvUxlkp0"

# Routes to delete (all except /.well-known/ routes)
ROUTES_TO_DELETE=(
    "-74671644"
    "oauth-introspect"
    "oauth-token"
    "oauth-callback"
    "oauth-verify"
    "token-47f737ca"
    "jwks-af10910e"
    "register-d273cfe4"
    "oauth-register"
    "callback-d0308d89"
    "authorize-d03d47c6"
    "oauth-revoke"
    "verify-47dc55f9"
    "revoke-0e7b0823"
    "introspect-e2b76092"
    "oauth-jwks"
    "oauth-error"
    "oauth-sessions"
    "oauth-success"
    "oauth-clients"
    "oauth-resources"
    "^-api-v[0-9]+-.*-9eac93d0"
    "health"
    "webhook-71b31c8c"
)

# Delete each route
for route_id in "${ROUTES_TO_DELETE[@]}"; do
    echo "Deleting route: $route_id"
    just route-delete "$route_id" "$TOKEN"
done

echo "Route cleanup completed!"