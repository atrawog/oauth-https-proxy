# Architecture

Deep dive into the ACME Certificate Manager architecture and design decisions.

## System Overview

```mermaid
graph TB
    Client[Client]
    
    subgraph "ACME Certificate Manager"
        API[FastAPI Server]
        HTTPS[HTTPS Server]
        CM[Certificate Manager]
        ACME[ACME Client]
        Scheduler[Auto-Renewal Scheduler]
        Storage[Redis Storage]
    end
    
    subgraph "External Services"
        Redis[(Redis)]
        ACMEProvider[ACME Provider<br/>Let's Encrypt]
    end
    
    Client -->|HTTP/HTTPS| API
    Client -->|HTTPS| HTTPS
    API --> CM
    HTTPS --> CM
    CM --> ACME
    CM --> Storage
    ACME -->|ACME Protocol| ACMEProvider
    Storage -->|Store/Retrieve| Redis
    Scheduler --> CM
    Scheduler -->|Check Expiry| Storage
```

## Core Components

### Certificate Manager

The central orchestrator that coordinates all certificate operations.

**Responsibilities:**
- Certificate lifecycle management
- API request handling
- Storage coordination
- SSL context updates

**Key Methods:**
- `create_certificate()` - Generate new certificates
- `renew_certificate()` - Renew existing certificates
- `get_certificate()` - Retrieve certificate data
- `auto_renew_certificates()` - Batch renewal process

### ACME Client

Implements the ACME v2 protocol for certificate generation.

**Features:**
- Account key management (RSA 2048-bit)
- Certificate key generation (RSA 2048-bit)
- HTTP-01 challenge support
- CSR generation with SAN support

**ACME Flow:**
1. Get/create account key
2. Register/login to ACME provider
3. Create order for domains
4. Complete HTTP-01 challenges
5. Finalize order and download certificate

### HTTPS Server

FastAPI application with dynamic SSL context loading.

**Features:**
- Dual HTTP/HTTPS operation
- SNI (Server Name Indication) support
- Hot-reload certificates without downtime
- Self-signed fallback certificate

**SSL Context Management:**
```python
# Per-domain SSL contexts
ssl_contexts = {
    "example.com": SSLContext,
    "www.example.com": SSLContext,
    "*.example.com": SSLContext  # Wildcard support
}
```

### Redis Storage

Exclusive storage backend for all persistent data.

**Data Schema:**

```
# Certificates
cert:{cert_name} -> Certificate JSON
{
    "domains": ["example.com"],
    "email": "admin@example.com",
    "fullchain_pem": "...",
    "private_key_pem": "...",
    ...
}

# ACME Challenges (TTL: 3600s)
challenge:{token} -> Challenge JSON
{
    "token": "abc123",
    "authorization": "abc123.def456",
    "expires_at": "2024-01-15T12:00:00Z"
}

# Account Keys
account:{provider}:{email} -> Private Key PEM
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

### Auto-Renewal Scheduler

Background scheduler for automatic certificate renewal.

**Configuration:**
- Check interval: 24 hours (configurable)
- Renewal threshold: 30 days before expiry
- Per-certificate job tracking

**Renewal Logic:**
```python
for cert in expiring_certificates:
    if days_until_expiry <= threshold:
        schedule_renewal(cert)
```

## Design Decisions

### Why Redis?

1. **Atomic Operations**: Certificate updates are atomic
2. **Persistence**: AOF ensures data survives restarts
3. **Scalability**: Multiple instances can share storage
4. **Simplicity**: No filesystem permissions or mounts
5. **Performance**: In-memory speed with persistence

### Why No Filesystem Storage?

1. **Container-friendly**: No volume mounts needed
2. **Security**: No file permission issues
3. **Portability**: Works identically everywhere
4. **Simplicity**: Single storage interface

### Why Hot-Reload?

1. **Zero downtime**: Update certificates without restarts
2. **User experience**: No connection drops
3. **Automation**: Seamless renewal process
4. **Scalability**: Update multiple certificates independently

## Security Considerations

### Key Generation

- **Account Keys**: RSA 2048-bit, unique per email/provider
- **Certificate Keys**: RSA 2048-bit, new key per generation
- **Storage**: All keys stored in Redis (ensure Redis security)

### ACME Challenges

- **HTTP-01 only**: Simplest, most compatible
- **Automatic cleanup**: Challenges deleted after use
- **TTL enforcement**: 1-hour expiry on challenges

### Network Security

```
Internet -> Firewall -> Load Balancer -> ACME Manager -> Redis
                                |
                                v
                          ACME Provider
```

**Recommendations:**
1. Use Redis AUTH password
2. Enable Redis TLS
3. Firewall Redis port
4. Use private network for Redis
5. Regular security updates

## Deployment Patterns

### Single Instance

Simple deployment for small scale:

```yaml
services:
  certmanager:
    image: acme-certmanager
    ports:
      - "80:80"
      - "443:443"
  redis:
    image: redis:7-alpine
```

### High Availability

Multi-instance with shared Redis:

```yaml
services:
  certmanager1:
    image: acme-certmanager
    environment:
      REDIS_URL: redis://redis-cluster:6379
  
  certmanager2:
    image: acme-certmanager
    environment:
      REDIS_URL: redis://redis-cluster:6379
  
  haproxy:
    image: haproxy
    ports:
      - "80:80"
      - "443:443"
```

### Behind Reverse Proxy

Common production pattern:

```
Internet -> Nginx/Traefik -> ACME Manager (high ports)
                          -> Application Servers
```

Benefits:
- Additional security layer
- Load balancing
- Request routing
- Authentication

## Performance Considerations

### Certificate Loading

- **Startup**: Load all certificates into memory
- **Updates**: Hot-reload only changed certificates
- **Memory**: ~10KB per certificate in SSL context

### Redis Operations

- **Reads**: O(1) key lookups
- **Writes**: Atomic operations
- **Scanning**: Efficient pattern matching

### Scaling Limits

| Component | Limit | Notes |
|-----------|-------|-------|
| Certificates | 10,000+ | Memory dependent |
| Domains/cert | 100 | ACME provider limit |
| Requests/sec | 1000+ | FastAPI performance |
| Redis storage | 1GB | Holds ~100k certificates |

## Extension Points

### Custom Storage Backend

```python
class StorageBackend(ABC):
    @abstractmethod
    def store_certificate(self, name: str, cert: Certificate) -> bool:
        pass
    
    @abstractmethod
    def get_certificate(self, name: str) -> Optional[Certificate]:
        pass
```

### Custom ACME Providers

Add new providers by configuring directory URL:

```python
PROVIDERS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "custom": "https://your-acme-provider.com/directory"
}
```

### Plugin System

Future enhancement for:
- DNS-01 challenges
- Custom validators
- Certificate processors
- Event webhooks