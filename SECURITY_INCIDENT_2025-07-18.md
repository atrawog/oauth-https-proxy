# Security Incident Report - 2025-07-18

## Executive Summary
On July 18, 2025 at 16:57 UTC, the Redis database was compromised by an external attacker who exploited an exposed, unauthenticated Redis port. All data including certificates, proxy configurations, and routes were exfiltrated and deleted.

## Incident Timeline
- **16:57:43 UTC** - Attacker from IP `106.12.35.113` (China) connected to exposed Redis port 6379
- **16:57:43 UTC** - Executed `SLAVEOF 39.105.136.204:60120` making Redis replicate to attacker's server
- **16:57:43-49 UTC** - Multiple replication attempts, each flushing all local data
- **16:57:49 UTC** - Attacker executed `SLAVEOF NO ONE` to restore master mode and cover tracks
- **18:00:00 UTC** - Incident discovered during routine testing

## Root Cause Analysis
1. **Why did it fail?** - Redis was compromised and all data deleted
2. **Why did that condition exist?** - Redis port 6379 was exposed to the internet
3. **Why was it allowed?** - docker-compose.yml had `ports: - "0.0.0.0:6379->6379/tcp"`
4. **Why wasn't it caught?** - No authentication was configured on Redis
5. **Why will it never happen again?** - Redis is now internal-only with strong authentication

## Impact
- **Data Lost**: All certificates, proxy configurations, routes, tokens
- **Services Affected**: Certificate manager functionality reset to blank state
- **Security**: Attacker had full Redis access for ~6 seconds
- **Recovery**: Manual recreation of all configurations required

## Remediation Actions Taken
1. **Immediate** (18:05 UTC)
   - Removed public port exposure from docker-compose.yml
   - Added Redis authentication with strong password
   - Created redis.conf with security hardening
   - Disabled dangerous Redis commands (FLUSHDB, SLAVEOF, etc.)
   - Restarted all containers with secure configuration

2. **Security Improvements**
   - Redis now only accessible within Docker network
   - Authentication required for all Redis operations
   - Protected mode enabled
   - Dangerous commands disabled

## Lessons Learned
1. **NEVER** expose database ports to the internet
2. **ALWAYS** use authentication on all services
3. **DEFAULT** to internal-only networking
4. Monitor for suspicious connections
5. Regular security audits of docker-compose configurations

## Recommendations
1. Implement Redis ACLs for fine-grained access control
2. Set up fail2ban or similar intrusion detection
3. Enable Redis command logging
4. Regular backups of Redis data
5. Network segmentation with firewall rules
6. Consider Redis Enterprise with built-in security features

## Configuration Changes

### Before (INSECURE)
```yaml
redis:
  ports:
    - "0.0.0.0:6379->6379/tcp"  # EXPOSED TO INTERNET!
  command: redis-server --appendonly yes
```

### After (SECURE)
```yaml
redis:
  # ports: REMOVED - Internal only
  volumes:
    - ./redis.conf:/usr/local/etc/redis/redis.conf:ro
  command: redis-server /usr/local/etc/redis/redis.conf --requirepass ${REDIS_PASSWORD}
```

## Attacker Information
- **Primary IP**: 106.12.35.113 (Alibaba Cloud, China)
- **Secondary IP**: 39.105.136.204 (Alibaba Cloud, China)
- **Method**: Redis replication attack (SLAVEOF command)
- **Duration**: ~6 seconds of active compromise

## Status
- **Incident**: Resolved
- **Security**: Hardened
- **Data**: Lost (requires manual recreation)
- **Monitoring**: To be implemented

---
Generated: 2025-07-18 18:10 UTC