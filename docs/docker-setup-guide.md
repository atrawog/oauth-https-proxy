# Docker Service Setup Guide

This guide helps you set up the Docker service management feature correctly.

## Prerequisites

1. Docker installed on the host system
2. Docker Compose installed
3. The user running docker-compose must be in the docker group

## Finding Your Docker Group GID

The proxy container needs to be added to the same group that owns the Docker socket. This varies by Linux distribution.

### Find your Docker GID:
```bash
# Method 1: Using getent
getent group docker | cut -d: -f3

# Method 2: Check the socket directly
stat -c '%g' /var/run/docker.sock

# Method 3: Look at ls output
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 Jan 15 10:00 /var/run/docker.sock
#                  ^^^^^^ (group name)
```

### Common Docker GIDs by Distribution:
- **Debian/Ubuntu**: 999
- **Arch Linux**: 994
- **Fedora/RHEL**: 989
- **Alpine Linux**: 101
- **Custom installations**: May vary

## Configuration Steps

1. **Create your .env file**:
```bash
cp .env.example .env
```

2. **Set the DOCKER_GID**:
```bash
# Edit .env and set DOCKER_GID to match your system
DOCKER_GID=999  # Replace with your actual GID
```

3. **Start the services**:
```bash
docker-compose up -d
```

4. **Verify Docker access**:
```bash
# Check if the proxy container can access Docker
docker exec proxy docker version

# Check group membership
docker exec proxy id
# Should show: groups=1000(proxyuser),999(docker)
```

## Troubleshooting

### Permission Denied Errors

If you get "permission denied" when the proxy tries to access Docker:

1. **Wrong GID**: The DOCKER_GID doesn't match your system
   ```bash
   # Find correct GID
   stat -c '%g' /var/run/docker.sock
   
   # Update .env
   DOCKER_GID=<correct-value>
   
   # Restart container
   docker-compose restart proxy
   ```

2. **SELinux/AppArmor**: Security modules may block access
   ```bash
   # For SELinux (Red Hat/Fedora)
   sudo setsebool -P container_manage_cgroup on
   
   # For AppArmor (Ubuntu/Debian)
   # May need to add apparmor profile exceptions
   ```

3. **Docker Desktop**: Uses different socket location
   ```bash
   # Docker Desktop for Mac/Windows often uses:
   DOCKER_HOST=unix://${HOME}/.docker/run/docker.sock
   ```

### Container Can't Start

If the proxy container fails to start:

```bash
# Check logs
docker-compose logs proxy

# Common issues:
# - Port 80/443 already in use
# - Redis connection failed
# - Invalid environment variables
```

## Security Warning

⚠️ **IMPORTANT**: Granting Docker socket access is equivalent to giving root access to the host system.

By mounting the Docker socket into the proxy container, you're giving that container the ability to:
- Create privileged containers
- Mount host filesystems
- Access all host resources
- Essentially do anything root can do

Only enable this feature if you:
1. Trust all users who have API access
2. Understand the security implications
3. Have proper authentication in place
4. Monitor and audit all activities

## Alternative Approaches

If the security risk is too high, consider:

1. **Remote Docker Host**: Connect to a separate Docker host
   ```bash
   DOCKER_HOST=tcp://docker-host.internal:2375
   ```

2. **Limited Permissions**: Use Docker rootless mode
   ```bash
   # Install rootless Docker
   curl -fsSL https://get.docker.com/rootless | sh
   ```

3. **Template-Only**: Only allow pre-defined service templates

4. **Disable Feature**: Remove Docker service endpoints entirely