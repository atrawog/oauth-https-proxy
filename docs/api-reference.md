# API Reference

Complete API documentation for ACME Certificate Manager.

## Base URL

```
http://localhost:80
https://localhost:443
```

## Authentication

Currently, the API does not require authentication. In production, place behind a reverse proxy with authentication.

## Endpoints

### Certificate Management

#### Create Certificate

```http
POST /certificates
```

Request a new certificate via ACME protocol.

**Request Body:**

```json
{
  "domain": "example.com",
  "email": "admin@example.com",
  "cert_name": "production",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
}
```

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| domain | string | Yes | Domain name for certificate |
| email | string | Yes | Contact email for ACME account |
| cert_name | string | Yes | Unique name for certificate |
| acme_directory_url | string | Yes | ACME provider directory URL |

**Response:**

```json
{
  "domains": ["example.com"],
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "status": "active",
  "expires_at": "2024-04-15T00:00:00Z",
  "issued_at": "2024-01-15T00:00:00Z",
  "fingerprint": "sha256:abcd1234...",
  "fullchain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Status Codes:**

- `200 OK` - Certificate created successfully
- `400 Bad Request` - Invalid request data
- `500 Internal Server Error` - Certificate generation failed

---

#### List Certificates

```http
GET /certificates
```

Get all certificates.

**Response:**

```json
[
  {
    "production": {
      "domains": ["example.com"],
      "email": "admin@example.com",
      "status": "active",
      "expires_at": "2024-04-15T00:00:00Z"
    }
  },
  {
    "staging": {
      "domains": ["test.example.com"],
      "email": "admin@example.com",
      "status": "active",
      "expires_at": "2024-04-15T00:00:00Z"
    }
  }
]
```

---

#### Get Certificate

```http
GET /certificates/{cert_name}
```

Get specific certificate details.

**Path Parameters:**

| Name | Type | Description |
|------|------|-------------|
| cert_name | string | Certificate name |

**Response:**

```json
{
  "domains": ["example.com"],
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "status": "active",
  "expires_at": "2024-04-15T00:00:00Z",
  "issued_at": "2024-01-15T00:00:00Z",
  "fingerprint": "sha256:abcd1234...",
  "fullchain_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Status Codes:**

- `200 OK` - Certificate found
- `404 Not Found` - Certificate not found

---

#### Renew Certificate

```http
POST /certificates/{cert_name}/renew
```

Manually trigger certificate renewal.

**Path Parameters:**

| Name | Type | Description |
|------|------|-------------|
| cert_name | string | Certificate name |

**Response:**

Same as Create Certificate response.

**Status Codes:**

- `200 OK` - Certificate renewed successfully
- `404 Not Found` - Certificate not found
- `500 Internal Server Error` - Renewal failed

---

#### Remove Domain

```http
DELETE /certificates/{cert_name}/domains/{domain}
```

Remove domain from certificate (regenerates certificate).

**Path Parameters:**

| Name | Type | Description |
|------|------|-------------|
| cert_name | string | Certificate name |
| domain | string | Domain to remove |

**Response:**

Updated certificate object or deletion confirmation.

**Status Codes:**

- `200 OK` - Domain removed
- `404 Not Found` - Certificate or domain not found

### ACME Challenge

#### Challenge Response

```http
GET /.well-known/acme-challenge/{token}
```

ACME HTTP-01 challenge validation endpoint.

**Path Parameters:**

| Name | Type | Description |
|------|------|-------------|
| token | string | Challenge token |

**Response:**

Plain text challenge authorization string.

**Status Codes:**

- `200 OK` - Challenge found
- `404 Not Found` - Challenge not found

### System

#### Health Check

```http
GET /health
```

System health status.

**Response:**

```json
{
  "status": "healthy",
  "scheduler": true,
  "redis": "healthy",
  "certificates_loaded": 5,
  "https_enabled": true
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| status | string | Overall health status |
| scheduler | boolean | Renewal scheduler running |
| redis | string | Redis connection status |
| certificates_loaded | integer | Number of loaded certificates |
| https_enabled | boolean | HTTPS server enabled |

## Examples

### cURL Examples

```bash
# Create certificate
curl -X POST http://localhost/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",
    "cert_name": "prod",
    "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
  }'

# List certificates
curl http://localhost/certificates

# Get specific certificate
curl http://localhost/certificates/prod

# Renew certificate
curl -X POST http://localhost/certificates/prod/renew

# Check health
curl http://localhost/health
```

### Python Examples

```python
import httpx

# Create client
client = httpx.Client(base_url="http://localhost")

# Create certificate
response = client.post("/certificates", json={
    "domain": "example.com",
    "email": "admin@example.com",
    "cert_name": "prod",
    "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
})
certificate = response.json()

# List certificates
response = client.get("/certificates")
certificates = response.json()

# Renew certificate
response = client.post(f"/certificates/prod/renew")
renewed_cert = response.json()
```

### JavaScript Examples

```javascript
// Create certificate
const response = await fetch('http://localhost/certificates', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    domain: 'example.com',
    email: 'admin@example.com',
    cert_name: 'prod',
    acme_directory_url: 'https://acme-v02.api.letsencrypt.org/directory'
  })
});
const certificate = await response.json();

// List certificates
const certificates = await fetch('http://localhost/certificates')
  .then(res => res.json());

// Renew certificate
const renewed = await fetch('http://localhost/certificates/prod/renew', {
  method: 'POST'
}).then(res => res.json());
```

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

Common error scenarios:

- **Invalid domain**: Domain format validation failed
- **ACME challenge failed**: Could not validate domain ownership
- **Rate limited**: ACME provider rate limit exceeded
- **Redis error**: Storage backend unavailable

## Rate Limits

Be aware of ACME provider rate limits:

| Provider | Limit Type | Limit |
|----------|------------|-------|
| Let's Encrypt | Certificates per domain | 50/week |
| Let's Encrypt | Duplicate certificates | 5/week |
| Let's Encrypt | Failed validations | 5/hour |
| Let's Encrypt | Accounts per IP | 10/3 hours |

Always test with staging environments first!