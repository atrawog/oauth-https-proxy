# Docker Service Security Example

This example demonstrates the security implications of direct Docker socket access.

## Direct Docker Socket Access

With the Docker socket mounted and proper group permissions, the proxy container has full Docker access:

```bash
# Exec into proxy container as the non-root user
docker exec -it proxy bash

# Docker socket is accessible via group permissions
proxyuser@proxy:~$ ls -la /var/run/docker.sock
srw-rw---- 1 root 999 0 Jan 15 10:00 /var/run/docker.sock

# User is in docker group (via group_add in docker-compose.yml)
proxyuser@proxy:~$ id
uid=1000(proxyuser) gid=1000(proxyuser) groups=1000(proxyuser),999(docker)

# Full Docker access is available
proxyuser@proxy:~$ docker ps
CONTAINER ID   IMAGE           COMMAND                  CREATED       STATUS       PORTS     NAMES
abc123...      nginx:alpine    "/docker-entrypoint.…"   1 hour ago    Up 1 hour              test-nginx
def456...      redis:alpine    "redis-server"           2 hours ago   Up 2 hours             redis

# ALL Docker operations work - including dangerous ones
proxyuser@proxy:~$ docker run --rm -v /:/host alpine cat /host/etc/shadow
# This would show the host's shadow file!
```

## What Happens When Creating a Service

1. **API Request**:
```bash
curl -X POST http://localhost/api/v1/services \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"service_name": "test", "image": "nginx:alpine"}'
```

2. **Python Code Execution**:
```python
# In DockerManager
self.client.run(
    image="nginx:alpine",
    name="test",
    detach=True,
    # ... other options
)
```

3. **Python-on-whales Translation**:
```bash
# python-on-whales executes this command internally
docker run -d --name test nginx:alpine
```

4. **Docker CLI Unix Socket Call**:
```
# Communicates directly with Docker daemon
/var/run/docker.sock → Docker daemon API
```

5. **Docker Daemon Execution**:
- Creates and starts the container
- Returns success response
- No filtering or validation at Docker level

## Security Boundaries

### What an Attacker CAN Do (if they compromise the proxy container):
⚠️ **EVERYTHING** - Full Docker access means effective root on the host:
- Create privileged containers with `--privileged`
- Mount ANY host directory into containers (`-v /:/host`)
- Access host network namespace (`--network host`)
- Read/write any file on the host system
- Install backdoors or malware on the host
- Access secrets from other containers
- Modify or stop any running container
- Pull and run any Docker image
- Execute commands as root on the host

### The Only Protection:
- **API Authentication**: Who can access the service creation endpoints
- **Token Permissions**: Which tokens have `docker:create` permission
- **Audit Logging**: Track who does what
- **Resource Limits**: Prevent complete resource exhaustion (but not privilege escalation)

## Recommendations

Given the security implications:

1. **Treat Service Creation as Root Access**: Only grant to fully trusted users
2. **Strong Authentication**: Use strong, unique tokens for API access
3. **Audit Everything**: Log all service creation/modification operations
4. **Regular Reviews**: Periodically review who has service creation access
5. **Consider Alternatives**:
   - Run on a dedicated Docker host with nothing sensitive
   - Use a proper orchestration platform (Kubernetes) with RBAC
   - Limit to pre-approved container templates only
   - Remove this feature if the security risk is too high

## The Honest Truth

Docker socket access = root access. There's no way around this fundamental truth. The decision to enable dynamic Docker service management should be made with full understanding that:

- Anyone with API access to create services can compromise the entire host
- No amount of application-level security can prevent privilege escalation
- This feature should only be used in trusted environments
- Consider it equivalent to giving users SSH root access