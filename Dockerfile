# Use official pixi image as base - Ubuntu-based with pixi pre-installed
FROM ghcr.io/prefix-dev/pixi:latest

# Switch to root for system setup
USER root

# Install system dependencies required by docker-compose.yml and app
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    libcap2-bin \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Docker buildx plugin for advanced build features
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    wget -O /usr/local/lib/docker/cli-plugins/docker-buildx \
    https://github.com/docker/buildx/releases/download/v0.14.1/buildx-v0.14.1.linux-amd64 && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx

# The pixi base image already has user 'ubuntu' with UID/GID 1000
# We'll use this existing user instead of creating a new one
# This maintains consistency with the original UID/GID requirement

# Set working directory
WORKDIR /app

# Create necessary directories with proper ownership
RUN mkdir -p /app/logs /app/dockerfiles /app/contexts && \
    chown -R ubuntu:ubuntu /app

# Copy project configuration files (as ubuntu for proper ownership)
COPY --chown=ubuntu:ubuntu pixi.toml pyproject.toml ./

# Copy local dependency referenced in pixi.toml
COPY --chown=ubuntu:ubuntu oauth-https-proxy-client/ ./oauth-https-proxy-client/

# Switch to ubuntu user for pixi operations
USER ubuntu

# Install dependencies using pixi (creates .pixi directory)
RUN pixi install

# Copy application code (will be overridden by volume mounts in dev)
COPY --chown=ubuntu:ubuntu src/ ./src/
COPY --chown=ubuntu:ubuntu run.py ./
COPY --chown=ubuntu:ubuntu scripts/ ./scripts/

# Switch back to root for capability setting
USER root

# Find Python executable in pixi environment and grant port binding capability
# This allows the app to bind to ports 80/443 without running as root
# Need to resolve symlinks as setcap doesn't work on symlinks
RUN PIXI_PYTHON=$(pixi run which python) && \
    if [ -n "$PIXI_PYTHON" ]; then \
        REAL_PYTHON=$(readlink -f "$PIXI_PYTHON") && \
        setcap 'cap_net_bind_service=+ep' "$REAL_PYTHON" && \
        echo "Capabilities set on: $REAL_PYTHON"; \
    else \
        echo "Warning: Could not find pixi Python executable"; \
        exit 1; \
    fi

# Ensure pixi is in PATH for all users
RUN echo 'export PATH="/usr/local/bin:$PATH"' >> /etc/profile.d/pixi.sh && \
    chmod +x /etc/profile.d/pixi.sh

# Switch back to ubuntu user for runtime
USER ubuntu

# Environment variables
ENV RUNNING_IN_DOCKER=1
# Ensure pixi is in PATH
ENV PATH="/usr/local/bin:$PATH"

# Health check using curl (as defined in docker-compose.yml)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

# Expose ports
EXPOSE 80 443

# Run using pixi (matching justfile commands)
CMD ["pixi", "run", "python", "run.py"]