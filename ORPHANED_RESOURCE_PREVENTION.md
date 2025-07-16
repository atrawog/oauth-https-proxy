# Orphaned Resource Prevention

## Overview

The system now includes comprehensive safeguards to prevent orphaned certificates and proxy targets when tokens are deleted. All token deletion operations automatically cascade delete all owned resources.

## Changes Implemented

### 1. Enhanced Token Deletion Script (`delete_token.py`)
- Now deletes certificates AND proxy targets owned by the token
- Shows all resources that will be deleted before confirmation
- Reports deletion statistics after completion

### 2. Storage Layer Cascade Deletion (`storage.py`)
- Added `delete_api_token_cascade()` method
- Added `delete_api_token_cascade_by_name()` method
- Returns detailed deletion statistics including errors
- Ensures atomic deletion of token and all owned resources

### 3. Updated Cleanup Script (`cleanup_all.py`)
- Uses cascade deletion for each token
- Reports orphaned resources found after cascade deletion
- Cleans up any remaining orphaned resources as a safety net

### 4. Health Check Integration
- Health endpoint now reports orphaned resource count
- Status becomes "degraded" if orphaned resources exist
- `orphaned_resources` field added to health response

### 5. Monitoring Tools
- `just check-orphaned-resources` - Check for orphaned resources
- `just cleanup-orphaned-certs [delete]` - Clean up orphaned resources
- `just debug-cert-ownership` - Debug certificate ownership

## How It Works

### Token Deletion Flow
1. User runs `just token-delete <name>`
2. Script shows all resources owned by the token
3. User confirms deletion
4. Storage layer cascade deletion:
   - Scans for all certificates with matching `owner_token_hash`
   - Scans for all proxy targets with matching `owner_token_hash`
   - Deletes all owned resources
   - Finally deletes the token itself

### Safeguards
1. **No API deletion endpoint** - Tokens can only be deleted via CLI
2. **Cascade deletion in storage layer** - Ensures consistency
3. **Health check monitoring** - Reports orphaned resources
4. **Cleanup tools** - For handling legacy orphaned resources

## Usage Examples

### Check for Orphaned Resources
```bash
# Quick check
just check-orphaned-resources

# Via health endpoint
curl http://localhost:80/health | jq .orphaned_resources
```

### Delete Token with Resources
```bash
just token-delete mytoken
# Output shows:
# - Token details
# - Owned certificates
# - Owned proxy targets
# - Confirmation prompt
# - Deletion results
```

### Clean Up Legacy Orphaned Resources
```bash
# Dry run (check what would be deleted)
just cleanup-orphaned-certs

# Actually delete orphaned resources
just cleanup-orphaned-certs delete
```

## Prevention Guarantees

1. **Token deletion always cascades** - The storage layer ensures all owned resources are deleted
2. **Health monitoring** - Orphaned resources are detected and reported
3. **No silent failures** - Deletion operations report all errors
4. **Audit trail** - All deletions are logged with statistics

## Legacy Data

Orphaned resources found in the system are from previous versions that didn't have cascade deletion. These can be safely cleaned up using the cleanup tools.