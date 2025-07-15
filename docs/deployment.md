# Deployment Guide

Production deployment guide for ACME Certificate Manager.

## Deployment Options

### Option 1: Docker Compose (Recommended)

Best for single-server deployments.

#### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Domain pointing to server
- Ports 80/443 available

#### Steps

1. **Clone repository**
   ```bash
   git clone https://github.com/acme-certmanager/acme-certmanager
   cd acme-certmanager
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   nano .env
   ```

   Production settings:
   ```env
   REDIS_URL=redis://redis:6379/0
   HTTP_PORT=80
   HTTPS_PORT=443
   ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
   LOG_LEVEL=INFO
   RENEWAL_CHECK_INTERVAL=86400
   RENEWAL_THRESHOLD_DAYS=30
   ```

3. **Start services**
   ```bash
   docker-compose up -d
   ```

4. **Verify deployment**
   ```bash
   docker-compose ps
   docker-compose logs -f
   curl http://localhost/health
   ```

### Option 2: Kubernetes

For cloud-native deployments.

#### Manifests

**ConfigMap:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: certmanager-config
data:
  REDIS_URL: "redis://redis-service:6379/0"
  HTTP_PORT: "80"
  HTTPS_PORT: "443"
  LOG_LEVEL: "INFO"
```

**Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: certmanager
spec:
  replicas: 2
  selector:
    matchLabels:
      app: certmanager
  template:
    metadata:
      labels:
        app: certmanager
    spec:
      containers:
      - name: certmanager
        image: acme-certmanager:latest
        ports:
        - containerPort: 80
        - containerPort: 443
        envFrom:
        - configMapRef:
            name: certmanager-config
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 80
          periodSeconds: 10
```

**Service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: certmanager-service
spec:
  type: LoadBalancer
  ports:
  - name: http
    port: 80
    targetPort: 80
  - name: https
    port: 443
    targetPort: 443
  selector:
    app: certmanager
```

### Option 3: Systemd Service

For traditional Linux deployments.

1. **Install Python package**
   ```bash
   pip install acme-certmanager
   ```

2. **Create systemd service**
   ```bash
   sudo nano /etc/systemd/system/certmanager.service
   ```

   ```ini
   [Unit]
   Description=ACME Certificate Manager
   After=network.target redis.service
   Requires=redis.service

   [Service]
   Type=exec
   User=certmanager
   Group=certmanager
   WorkingDirectory=/opt/certmanager
   Environment="REDIS_URL=redis://localhost:6379/0"
   Environment="HTTP_PORT=80"
   Environment="HTTPS_PORT=443"
   ExecStart=/usr/local/bin/acme-certmanager
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable and start**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable certmanager
   sudo systemctl start certmanager
   ```

## Production Configuration

### Redis Security

1. **Enable AUTH**
   ```bash
   # redis.conf
   requirepass your-strong-password
   ```

   Update REDIS_URL:
   ```
   REDIS_URL=redis://:your-strong-password@localhost:6379/0
   ```

2. **Enable TLS**
   ```bash
   # redis.conf
   tls-port 6380
   tls-cert-file /path/to/cert.pem
   tls-key-file /path/to/key.pem
   ```

3. **Persistence**
   ```bash
   # redis.conf
   appendonly yes
   appendfsync everysec
   ```

### Reverse Proxy Setup

#### Nginx

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location /.well-known/acme-challenge/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # Let certmanager handle SSL
    proxy_ssl_server_name on;
    
    location / {
        proxy_pass https://localhost:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Traefik

```yaml
http:
  routers:
    certmanager:
      rule: "Host(`yourdomain.com`)"
      service: certmanager
      tls:
        passthrough: true

  services:
    certmanager:
      loadBalancer:
        servers:
          - url: "https://certmanager:443"
```

### High Availability

#### Redis Sentinel

```yaml
version: '3.8'
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    
  redis-slave:
    image: redis:7-alpine
    command: redis-server --slaveof redis-master 6379
    
  sentinel:
    image: redis:7-alpine
    command: redis-sentinel /etc/sentinel.conf
    volumes:
      - ./sentinel.conf:/etc/sentinel.conf
```

#### Multiple Instances

```yaml
version: '3.8'
services:
  certmanager1:
    image: acme-certmanager
    environment:
      REDIS_URL: redis://redis-ha:6379
      
  certmanager2:
    image: acme-certmanager
    environment:
      REDIS_URL: redis://redis-ha:6379
      
  haproxy:
    image: haproxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg
```

## Monitoring

### Prometheus Metrics

Future feature - export metrics:
- Certificate count
- Renewal success/failure
- API request rates
- Redis connection status

### Health Checks

Monitor `/health` endpoint:

```bash
# Simple check
curl -f http://localhost/health || alert

# Detailed monitoring
response=$(curl -s http://localhost/health)
status=$(echo $response | jq -r .status)
if [ "$status" != "healthy" ]; then
    send_alert "Certificate Manager unhealthy"
fi
```

### Logging

Configure log aggregation:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    labels: "service=certmanager"
```

## Security Hardening

### Network Isolation

```yaml
networks:
  frontend:
    external: true
  backend:
    internal: true
    
services:
  certmanager:
    networks:
      - frontend
      - backend
      
  redis:
    networks:
      - backend
```

### Resource Limits

```yaml
services:
  certmanager:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
```

### Read-Only Filesystem

```yaml
services:
  certmanager:
    read_only: true
    tmpfs:
      - /tmp
```

## Backup and Recovery

### Redis Backup

```bash
#!/bin/bash
# backup-redis.sh
BACKUP_DIR="/backups/redis"
DATE=$(date +%Y%m%d_%H%M%S)

# Save Redis data
docker exec redis redis-cli BGSAVE
sleep 5

# Copy backup files
docker cp redis:/data/dump.rdb $BACKUP_DIR/dump_$DATE.rdb
docker cp redis:/data/appendonly.aof $BACKUP_DIR/appendonly_$DATE.aof

# Keep last 7 days
find $BACKUP_DIR -name "*.rdb" -mtime +7 -delete
find $BACKUP_DIR -name "*.aof" -mtime +7 -delete
```

### Certificate Export

```python
import httpx
import json

# Export all certificates
client = httpx.Client(base_url="http://localhost")
certificates = client.get("/certificates").json()

with open("certificates_backup.json", "w") as f:
    json.dump(certificates, f, indent=2)
```

## Troubleshooting Production Issues

### Certificate Generation Failures

1. **Check connectivity**
   ```bash
   curl -I http://yourdomain.com/.well-known/acme-challenge/test
   ```

2. **Verify firewall**
   ```bash
   sudo iptables -L -n | grep -E "80|443"
   ```

3. **Check rate limits**
   ```bash
   docker-compose logs certmanager | grep -i "rate"
   ```

### Performance Issues

1. **Monitor Redis**
   ```bash
   redis-cli INFO stats
   redis-cli SLOWLOG GET 10
   ```

2. **Check connections**
   ```bash
   ss -tunlp | grep -E "80|443"
   netstat -an | grep ESTABLISHED | wc -l
   ```

3. **Resource usage**
   ```bash
   docker stats certmanager
   ```

## Migration Guide

### From Other Certificate Managers

1. **Export existing certificates**
2. **Convert to PEM format**
3. **Import via API**
   ```bash
   curl -X POST http://localhost/certificates/import \
     -F "cert=@fullchain.pem" \
     -F "key=@privkey.pem" \
     -F "name=imported"
   ```

### Version Upgrades

1. **Backup Redis data**
2. **Pull new image**
3. **Rolling update**
   ```bash
   docker-compose pull
   docker-compose up -d --no-deps --scale certmanager=2
   docker-compose up -d --no-deps certmanager
   ```