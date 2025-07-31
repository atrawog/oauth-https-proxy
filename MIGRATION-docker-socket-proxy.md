# Migration Guide: Removing docker-socket-proxy

This guide helps you migrate from the docker-socket-proxy setup to direct Docker socket access.

## What Changed

We removed the `docker-socket-proxy` service because:
- It provided no meaningful security with the permissions we needed
- Added complexity without benefit
- The required permissions (CONTAINERS=1, IMAGES=1, etc.) essentially granted full Docker access anyway

## Migration Steps

### 1. Stop Current Services
```bash
docker-compose down
```

### 2. Update Your Configuration

#### Find your Docker GID:
```bash
# Run this on your host system:
getent group docker | cut -d: -f3
# Note the number (e.g., 999)
```

#### Update .env file:
```bash
# Add or update this line with your Docker GID:
DOCKER_GID=999

# Remove or comment out this line if present:
# DOCKER_HOST=tcp://docker-socket-proxy:2375
```

### 3. Pull Latest Changes
```bash
git pull
```

### 4. Rebuild and Start
```bash
# Rebuild the proxy image with new Dockerfile
docker-compose build proxy

# Start services
docker-compose up -d
```

### 5. Verify Migration
```bash
# Check that docker-socket-proxy is NOT running
docker ps | grep docker-socket-proxy
# Should return nothing

# Verify proxy can access Docker
docker exec proxy docker version
# Should show Docker version info

# Check that services are healthy
docker-compose ps
```

## What This Means for Security

⚠️ **IMPORTANT SECURITY CHANGE**:
- The proxy container now has direct Docker socket access
- This is equivalent to root access on the host
- Security now relies entirely on API authentication

### Before (with docker-socket-proxy):
```
API → Proxy Container → docker-socket-proxy → Docker Socket
                          ↑
                    (false sense of security)
```

### After (direct access):
```
API → Proxy Container → Docker Socket
         ↑
   (has docker group permissions)
```

## Rollback (if needed)

If you need to rollback to the previous setup:

1. Restore the old docker-compose.yml
2. Set `DOCKER_HOST=tcp://docker-socket-proxy:2375` in .env
3. Rebuild and restart services

However, we recommend accepting the new setup as it's more honest about the security model.

## Questions?

The fundamental security hasn't changed - if someone can create Docker containers, they effectively have root access. The new setup just makes this reality more transparent.