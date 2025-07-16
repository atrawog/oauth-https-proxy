# Certificate List Discrepancy Resolution

## Issue Identified
`just token-list` and `just cert-list` were showing contradicting information:
- **token-list**: Showed 1 token with 0 certificates
- **cert-list**: Showed 4 certificates in the system

## Root Cause Analysis
Using the `just debug-cert-ownership` command, we discovered:

1. **Orphaned Certificates**: All 4 certificates belonged to tokens that no longer exist
   - Each certificate had an `owner_token_hash` that didn't match any existing token
   - These were left over from previous testing sessions

2. **Command Behavior**:
   - `just token-list`: Correctly counts only certificates owned by each token
   - `just cert-list` (without auth): Shows ALL certificates in the system, including orphaned ones
   - `just cert-list <token>`: Shows only certificates owned by that specific token

## Solution Implemented

### 1. Created Debug Tools
- **`just debug-cert-ownership`**: Shows certificate ownership details
- **`just cleanup-orphaned-certs`**: Finds and removes orphaned certificates/proxies

### 2. Cleanup Process
```bash
# Check for orphaned certificates (dry run)
just cleanup-orphaned-certs

# Actually delete orphaned certificates
just cleanup-orphaned-certs delete
```

### 3. Results
- Deleted 4 orphaned certificates
- Deleted 1 orphaned proxy target
- Both commands now show consistent results (0 certificates)

## Prevention Recommendations

1. **Token Deletion**: When deleting tokens, ensure cascade deletion of owned resources
2. **Regular Cleanup**: Run `just cleanup-orphaned-certs` periodically
3. **Monitoring**: Use `just debug-cert-ownership` to verify certificate ownership

## Key Commands Summary
```bash
# Debug certificate ownership
just debug-cert-ownership

# Check for orphaned certificates
just cleanup-orphaned-certs

# Clean up orphaned certificates
just cleanup-orphaned-certs delete

# List certificates for specific token only
just cert-list <token-name>
```

## Conclusion
The discrepancy was not a bug but rather orphaned data from deleted tokens. The cleanup tools now make it easy to identify and resolve such issues.