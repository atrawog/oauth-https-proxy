# Multi-Domain Certificate Implementation Plan

## Overview
Enable creation of single certificates covering multiple hostnames to improve efficiency and management.

## Benefits
- **Efficiency**: Fewer certificates to manage and renew
- **Rate Limits**: Avoid Let's Encrypt rate limits by grouping domains
- **Cost**: Reduced computational overhead for certificate operations
- **Management**: Simpler certificate lifecycle management

## Architecture Changes

### 1. New API Endpoint
```python
POST /certificates/multi-domain
{
  "cert_name": "echo-services",
  "domains": [
    "echo-stateful.atradev.org",
    "echo-stateless.atradev.org"
  ],
  "email": "admin@atradev.org",
  "acme_directory_url": "..."
}
```

### 2. New Models
```python
class MultiDomainCertificateRequest(BaseModel):
    cert_name: str
    domains: List[str]  # Multiple domains
    email: str
    acme_directory_url: str
    
    @validator('domains')
    def validate_domains(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one domain required")
        if len(v) > 100:  # Let's Encrypt limit
            raise ValueError("Maximum 100 domains per certificate")
        return [d.strip().lower() for d in v]
```

### 3. Proxy Certificate Validation
When attaching a multi-domain certificate to a proxy:
- Check if proxy hostname matches any domain in the certificate
- Support wildcard matching (*.example.com matches sub.example.com)
- Show which domains are covered by the certificate

### 4. New Commands

#### Create Multi-Domain Certificate
```bash
just cert create-multi <cert-name> <domain1,domain2,domain3> <email> <token> [staging]
# Example:
just cert create-multi echo-services "echo-stateful.atradev.org,echo-stateless.atradev.org" admin@example.com admin
```

#### Create Wildcard Certificate
```bash
just cert create-wildcard <cert-name> <base-domain> <email> <token> [staging]
# Example:
just cert create-wildcard atradev-wildcard atradev.org admin@example.com admin
# Creates cert for: *.atradev.org and atradev.org
```

#### List Certificate Coverage
```bash
just cert coverage <cert-name>
# Shows which proxies could use this certificate
```

### 5. Certificate Sharing Strategy

#### Automatic Detection
When creating a new proxy, check existing certificates:
1. Look for exact domain match
2. Check wildcard certificates that cover the domain
3. Suggest compatible certificates

#### Manual Grouping
Allow users to specify certificate groups:
```bash
just proxy create-group <group-name> <hostnames...> <target-url> <token>
# Creates multiple proxies sharing one certificate
```

### 6. Migration Path

1. **Phase 1**: Add multi-domain support without breaking existing single-domain flow
2. **Phase 2**: Add commands and UI for multi-domain certificates
3. **Phase 3**: Add automatic grouping suggestions
4. **Phase 4**: Migration tool to consolidate existing certificates

## Implementation Priority

1. **Core API** (High Priority)
   - MultiDomainCertificateRequest model
   - POST /certificates/multi-domain endpoint
   - Update manager to handle domain lists

2. **CLI Commands** (High Priority)
   - cert create-multi command
   - cert create-wildcard command
   - Update proxy cert-attach to show domain coverage

3. **Validation & Safety** (High Priority)
   - Domain validation in proxy attachment
   - Wildcard matching logic
   - Certificate compatibility checks

4. **User Experience** (Medium Priority)
   - cert coverage command
   - Suggestions for certificate consolidation
   - Enhanced proxy list showing certificate efficiency

5. **Advanced Features** (Low Priority)
   - Automatic certificate grouping
   - proxy create-group command
   - Certificate consolidation tool

## Challenges & Solutions

### Challenge 1: DNS Validation
**Problem**: All domains must pass ACME validation
**Solution**: Pre-validate DNS before attempting certificate generation

### Challenge 2: Proxy Updates
**Problem**: Multiple proxies may reference the same certificate
**Solution**: Track certificate usage and update all affected proxies

### Challenge 3: Domain Changes
**Problem**: Adding/removing domains requires new certificate
**Solution**: Provide cert add-domain and cert remove-domain commands

### Challenge 4: Wildcard DNS
**Problem**: Wildcard certificates require DNS-01 challenge
**Solution**: Start with HTTP-01 for specific domains, add DNS-01 support later

## Example Workflows

### Consolidate Services
```bash
# Current: 3 certificates
proxy-echo-stateful.atradev.org -> cert1
proxy-echo-stateless.atradev.org -> cert2
proxy-fetcher.atradev.org -> cert3

# New: 1 certificate
just cert create-multi services "echo-stateful.atradev.org,echo-stateless.atradev.org,fetcher.atradev.org" admin@example.com admin
just proxy cert-attach echo-stateful.atradev.org services
just proxy cert-attach echo-stateless.atradev.org services
just proxy cert-attach fetcher.atradev.org services
```

### Wildcard Setup
```bash
# Create wildcard certificate
just cert create-wildcard myapp-wildcard myapp.com admin@example.com admin
# Covers: *.myapp.com and myapp.com

# Use for any subdomain
just proxy create api.myapp.com http://api:3000 admin
just proxy cert-attach api.myapp.com myapp-wildcard

just proxy create app.myapp.com http://app:3000 admin
just proxy cert-attach app.myapp.com myapp-wildcard
```

## Success Metrics
- Reduce total certificates by 50%+
- Simplify certificate renewal process
- Support wildcard certificates
- Maintain backwards compatibility
- Clear user feedback on certificate coverage