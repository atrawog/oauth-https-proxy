# Troubleshooting

Common issues and solutions for ACME Certificate Manager.

## Certificate Generation Issues

### Error: "Failed to create certificate"

**Symptoms:**
- API returns 500 error
- Certificate status remains "pending"
- Logs show ACME errors

**Common Causes:**

1. **Domain not pointing to server**
   ```bash
   # Check DNS resolution
   dig +short yourdomain.com
   
   # Verify it matches your server IP
   curl ifconfig.me
   ```

2. **Ports 80/443 blocked**
   ```bash
   # Check port accessibility
   sudo netstat -tlnp | grep -E "80|443"
   
   # Test from external
   curl -I http://yourdomain.com
   ```

3. **Firewall blocking ACME**
   ```bash
   # Check firewall rules
   sudo iptables -L -n
   sudo ufw status
   
   # Allow ports
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```

**Solutions:**

1. Update DNS records
2. Open firewall ports
3. Use staging environment first
4. Check ACME provider status

### Error: "Challenge validation failed"

**Symptoms:**
- ACME challenge returns 404
- Timeout during validation
- "Invalid response" errors

**Diagnosis:**
```bash
# Test challenge endpoint
curl http://yourdomain.com/.well-known/acme-challenge/test

# Check Redis for challenges
redis-cli KEYS "challenge:*"

# View certmanager logs
docker-compose logs certmanager | grep challenge
```

**Solutions:**

1. **Ensure HTTP routing works**
   ```nginx
   location /.well-known/acme-challenge/ {
       proxy_pass http://certmanager;
   }
   ```

2. **Check Redis connectivity**
   ```bash
   docker-compose exec certmanager redis-cli -u $REDIS_URL ping
   ```

3. **Verify challenge storage**
   ```python
   # Debug challenge storage
   redis-cli GET "challenge:token123"
   ```

### Error: "Rate limit exceeded"

**Symptoms:**
- "Too many certificates" error
- "Rate limit" in error message
- HTTP 429 responses

**Let's Encrypt Limits:**
- 50 certificates per domain per week
- 5 duplicate certificates per week
- 5 failed validations per hour
- 300 new orders per 3 hours

**Solutions:**

1. **Use staging environment**
   ```json
   {
     "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"
   }
   ```

2. **Check rate limit status**
   ```bash
   curl -I https://acme-v02.api.letsencrypt.org/directory
   ```

3. **Wait for reset**
   - Most limits reset weekly
   - Failed validation: 1 hour
   - Check exact reset time in headers

## Connection Issues

### Error: "Redis connection refused"

**Symptoms:**
- Health check shows Redis unhealthy
- "Connection refused" in logs
- Service won't start

**Diagnosis:**
```bash
# Check Redis is running
docker-compose ps redis

# Test connection
redis-cli -u $REDIS_URL ping

# Check Redis logs
docker-compose logs redis
```

**Solutions:**

1. **Start Redis**
   ```bash
   docker-compose up -d redis
   ```

2. **Fix connection string**
   ```env
   # Correct format
   REDIS_URL=redis://localhost:6379/0
   
   # With auth
   REDIS_URL=redis://:password@localhost:6379/0
   ```

3. **Check network**
   ```bash
   # Verify Redis is listening
   netstat -tlnp | grep 6379
   
   # Test from container
   docker-compose exec certmanager ping redis
   ```

### Error: "Address already in use"

**Symptoms:**
- Port 80/443 binding fails
- "Address already in use" error
- Service won't start

**Diagnosis:**
```bash
# Find process using ports
sudo lsof -i :80
sudo lsof -i :443

# Or using netstat
sudo netstat -tlnp | grep -E "80|443"
```

**Solutions:**

1. **Stop conflicting service**
   ```bash
   # Common conflicts
   sudo systemctl stop nginx
   sudo systemctl stop apache2
   ```

2. **Use different ports**
   ```env
   HTTP_PORT=8080
   HTTPS_PORT=8443
   ```

3. **Use reverse proxy**
   - Run certmanager on high ports
   - Proxy through nginx/traefik

## SSL/TLS Issues

### Error: "SSL handshake failed"

**Symptoms:**
- HTTPS connections fail
- "No cipher suites in common"
- Certificate warnings

**Diagnosis:**
```bash
# Test SSL connection
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certificate
curl -vI https://yourdomain.com

# View loaded certificates
curl http://localhost/certificates
```

**Solutions:**

1. **Verify certificate loaded**
   ```bash
   # Check health endpoint
   curl http://localhost/health | jq .https_enabled
   ```

2. **Check certificate validity**
   ```bash
   # Decode certificate
   echo "$CERT_PEM" | openssl x509 -text -noout
   ```

3. **Restart with fresh certificates**
   ```bash
   docker-compose restart certmanager
   ```

### Error: "Certificate expired"

**Symptoms:**
- Browser warnings
- "Certificate has expired" errors
- Auto-renewal not working

**Diagnosis:**
```bash
# Check certificate expiry
curl http://localhost/certificates/production | jq .expires_at

# Check scheduler status
curl http://localhost/health | jq .scheduler

# View renewal logs
docker-compose logs certmanager | grep renewal
```

**Solutions:**

1. **Manual renewal**
   ```bash
   curl -X POST http://localhost/certificates/production/renew
   ```

2. **Fix auto-renewal**
   ```env
   # Ensure scheduler is enabled
   RENEWAL_CHECK_INTERVAL=86400
   RENEWAL_THRESHOLD_DAYS=30
   ```

3. **Check scheduler health**
   ```python
   # Verify scheduler is running
   scheduler.is_running()
   ```

## Performance Issues

### High Memory Usage

**Symptoms:**
- Container using excessive memory
- OOM kills
- Slow responses

**Diagnosis:**
```bash
# Check memory usage
docker stats certmanager

# View process details
docker-compose exec certmanager ps aux

# Check certificate count
curl http://localhost/certificates | jq length
```

**Solutions:**

1. **Limit certificate count**
   - Archive old certificates
   - Remove unused domains

2. **Set memory limits**
   ```yaml
   services:
     certmanager:
       deploy:
         resources:
           limits:
             memory: 512M
   ```

3. **Optimize SSL contexts**
   - Share contexts for wildcards
   - Lazy loading implementation

### Slow API Responses

**Symptoms:**
- API timeouts
- Slow certificate generation
- High latency

**Diagnosis:**
```bash
# Time API calls
time curl http://localhost/health

# Check Redis performance
redis-cli --latency

# Monitor slow queries
redis-cli SLOWLOG GET 10
```

**Solutions:**

1. **Optimize Redis**
   ```bash
   # Enable Redis persistence optimization
   redis-cli CONFIG SET save ""
   ```

2. **Add connection pooling**
   ```python
   # Use connection pool
   pool = redis.ConnectionPool(...)
   redis_client = redis.Redis(connection_pool=pool)
   ```

3. **Enable caching**
   - Cache ACME directory
   - Cache account keys

## Docker Issues

### Container Keeps Restarting

**Symptoms:**
- Container in restart loop
- Exit code non-zero
- Service unavailable

**Diagnosis:**
```bash
# Check container status
docker-compose ps

# View recent logs
docker-compose logs --tail=50 certmanager

# Check exit code
docker-compose ps -q certmanager | xargs docker inspect -f '{{.State.ExitCode}}'
```

**Solutions:**

1. **Check configuration**
   ```bash
   # Validate .env file
   docker-compose config
   ```

2. **Fix permissions**
   ```bash
   # For low ports
   sysctl net.ipv4.ip_unprivileged_port_start=80
   ```

3. **Increase health check timeout**
   ```yaml
   healthcheck:
     timeout: 30s
     start_period: 60s
   ```

### Build Failures

**Symptoms:**
- Docker build errors
- Package installation failures
- Image not created

**Solutions:**

1. **Clear cache**
   ```bash
   docker-compose build --no-cache
   ```

2. **Update base image**
   ```dockerfile
   FROM python:3.11-slim-latest
   ```

3. **Check network**
   ```bash
   # Test package downloads
   docker run --rm python:3.11-slim pip install fastapi
   ```

## Debugging Tools

### Enable Debug Logging

```env
LOG_LEVEL=DEBUG
```

### Interactive Debugging

```bash
# Connect to running container
docker-compose exec certmanager /bin/sh

# Run Python shell
docker-compose exec certmanager pixi run python

# Test imports
>>> from acme_certmanager import CertificateManager
>>> manager = CertificateManager()
```

### Redis Debugging

```bash
# Monitor Redis commands
redis-cli MONITOR

# Check all keys
redis-cli KEYS "*"

# Inspect certificate
redis-cli GET "cert:production" | jq
```

### Network Debugging

```bash
# Trace HTTP requests
tcpdump -i any -w trace.pcap port 80

# Monitor connections
watch 'netstat -an | grep -E "80|443"'
```

## Getting Help

### Collect Diagnostics

```bash
#!/bin/bash
# collect-diagnostics.sh

echo "=== System Info ==="
uname -a
docker --version
docker-compose --version

echo "=== Service Status ==="
docker-compose ps

echo "=== Recent Logs ==="
docker-compose logs --tail=100

echo "=== Configuration ==="
docker-compose config

echo "=== Health Check ==="
curl -s http://localhost/health | jq

echo "=== Redis Info ==="
redis-cli INFO server
```

### Report Issues

Include:
1. Error messages
2. Steps to reproduce
3. Diagnostic output
4. Environment details
5. Configuration (sanitized)