# Certificate Manager Documentation

## Overview

The Certificate Manager provides automated SSL/TLS certificate management using the ACME protocol (Let's Encrypt) with fully async operations.

## ACME Implementation

- **Protocol**: ACME v2 with HTTP-01 challenges
- **Storage**: Redis-exclusive (no filesystem)
- **Multi-domain**: Up to 100 domains per certificate
- **Keys**: RSA 2048-bit, new key per certificate

## Configuration

### ACME Configuration
- `ACME_DIRECTORY_URL` - Production ACME directory URL (default: https://acme-v02.api.letsencrypt.org/directory)
- `ACME_STAGING_URL` - Staging ACME directory URL for testing (default: https://acme-staging-v02.api.letsencrypt.org/directory)
- `ACME_POLL_MAX_ATTEMPTS` - Maximum polling attempts for ACME challenges (default: 60)
- `ACME_POLL_INTERVAL_SECONDS` - Seconds between ACME polling attempts (default: 2)
- `ACME_POLL_INITIAL_WAIT` - Initial wait before polling starts (default: 0)

### Certificate Management Configuration
- `RENEWAL_CHECK_INTERVAL` - Seconds between certificate renewal checks (default: 86400 = 24 hours)
- `RENEWAL_THRESHOLD_DAYS` - Days before expiry to trigger renewal (default: 30)
- `CERT_STATUS_RETENTION_SECONDS` - How long to retain certificate generation status (default: 300)
- `CERT_GEN_MAX_WORKERS` - Maximum concurrent certificate generation workers (default: 5)
- `RSA_KEY_SIZE` - RSA key size for certificates (default: 2048)
- `SELF_SIGNED_DAYS` - Validity period for self-signed certificates (default: 365)

## Certificate Object Schema

```json
{
  "cert_name": "services-cert",
  "domains": ["api.example.com", "app.example.com"],
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "status": "active",
  "expires_at": "2024-03-15T00:00:00Z",
  "fullchain_pem": "-----BEGIN CERTIFICATE-----",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----",
  "owner_token_hash": "sha256:..."
}
```

## Auto-Renewal

- Check interval: 24 hours
- Renewal threshold: 30 days before expiry
- Automatic SSL context updates
- No downtime during renewal

## ACME Challenge Flow

1. **Challenge Request**: Certificate manager requests HTTP-01 challenge from ACME server
2. **Token Storage**: Challenge token stored in Redis
3. **Validation**: ACME server validates via `/.well-known/acme-challenge/{token}`
4. **Certificate Issuance**: Upon successful validation, certificate is issued
5. **Storage**: Certificate and key stored in Redis
6. **SSL Context Update**: New SSL context created and applied

## API Endpoints

- `POST /certificates/` - Single domain (async)
- `POST /certificates/multi-domain` - Multiple domains (async)
- `GET /certificates/` - List all certificates (requires trailing slash)
- `GET /certificates/{cert_name}` - Get certificate details
- `GET /certificates/{cert_name}/status` - Generation status
- `POST /certificates/{cert_name}/renew` - Manual renewal
- `DELETE /certificates/{cert_name}` - Delete certificate
- `GET /.well-known/acme-challenge/{token}` - ACME validation (root level)
- `GET /health` - Service health status (root level)

## Certificate Commands

```bash
# Certificate operations
just cert create <name> <domain> [staging] [email] [token]
just cert delete <name> [force] [token]
just cert list [token]
just cert show <name> [pem] [token]
```

## Key Features

### Async Operations
- Non-blocking certificate generation
- Concurrent certificate requests
- Background renewal tasks
- Async ACME client operations

### Multi-Domain Support
Certificates can cover multiple domains:
```bash
just cert create services-cert "api.example.com,app.example.com,www.example.com"
```

### Staging vs Production
Use staging for testing to avoid rate limits:
```bash
just cert create test-cert example.com true  # Uses staging
just cert create prod-cert example.com false # Uses production
```

### Certificate Ownership
- Certificates are owned by the token that creates them
- Only the owner token can delete or modify certificates
- Ownership is tracked via `owner_token_hash`

## Dynamic SSL Provider

The `DynamicSSLProvider` class manages SSL contexts dynamically:
- Loads certificates from Redis on demand
- Caches SSL contexts for performance
- Automatically updates when certificates renew
- Supports SNI (Server Name Indication)

## Certificate Status Tracking

Generation status is tracked for async operations:
```json
{
  "status": "pending|generating|completed|failed",
  "message": "Status message",
  "created_at": "2024-01-15T10:00:00Z"
}
```

## Integration with Proxy

Certificates are automatically used by proxies:
1. Proxy references certificate by name
2. Certificate manager provides SSL context
3. Dispatcher uses SSL context for HTTPS
4. Automatic updates on renewal

## Best Practices

1. **Use Staging First**: Always test with staging certificates before production
2. **Monitor Expiry**: Check certificate expiry dates regularly
3. **Plan for Rate Limits**: Let's Encrypt has rate limits - plan accordingly
4. **Multi-Domain Certificates**: Group related domains to reduce certificate count
5. **Email Configuration**: Set valid email for important notifications

## Troubleshooting

### Common Issues

1. **Challenge Validation Fails**: Ensure domain points to proxy and port 80 is accessible
2. **Rate Limits**: Use staging for testing, production has strict limits
3. **DNS Propagation**: Wait for DNS changes to propagate before requesting certificates
4. **Certificate Not Applied**: Check proxy configuration references correct cert name

### Debug Commands

```bash
# Check certificate status
just cert show <name> | jq .status

# View certificate details
just cert show <name> true  # Shows PEM data

# Check ACME challenge endpoint
curl http://yourdomain/.well-known/acme-challenge/test
```

## Related Documentation

- [Proxy Manager](../proxy/CLAUDE.md) - How proxies use certificates
- [Dispatcher](../dispatcher/CLAUDE.md) - SSL context management
- [Storage](../storage/CLAUDE.md) - Certificate storage schema