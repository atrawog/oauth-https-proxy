FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    libcap2-bin \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Docker buildx plugin manually (newer version with --format support)
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    wget -O /usr/local/lib/docker/cli-plugins/docker-buildx \
    https://github.com/docker/buildx/releases/download/v0.14.1/buildx-v0.14.1.linux-amd64 && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx

# Create non-root user with specific UID/GID
RUN groupadd -g 1000 proxyuser && \
    useradd -u 1000 -g 1000 -m -s /bin/bash proxyuser

# Set working directory
WORKDIR /app

# Create necessary directories with proper ownership
RUN mkdir -p /app/logs /app/dockerfiles /app/contexts && \
    chown -R proxyuser:proxyuser /app

# Copy requirements first for better caching
COPY --chown=proxyuser:proxyuser pixi.toml .
COPY --chown=proxyuser:proxyuser pyproject.toml .

# Copy local dependencies referenced in pixi.toml
COPY --chown=proxyuser:proxyuser mcp-echo-streamablehttp-server-stateful/ ./mcp-echo-streamablehttp-server-stateful/
COPY --chown=proxyuser:proxyuser mcp-echo-streamablehttp-server-stateless/ ./mcp-echo-streamablehttp-server-stateless/
COPY --chown=proxyuser:proxyuser mcp-http-validator/ ./mcp-http-validator/
COPY --chown=proxyuser:proxyuser oauth-https-proxy-client/ ./oauth-https-proxy-client/

# Switch to non-root user for pixi installation
USER proxyuser

# Install pixi as proxyuser
RUN curl -fsSL https://pixi.sh/install.sh | bash && \
    echo 'export PATH="/home/proxyuser/.pixi/bin:$PATH"' >> ~/.bashrc

# Install dependencies using pixi
ENV PATH="/home/proxyuser/.pixi/bin:$PATH"
RUN pixi install

# Copy application code
COPY --chown=proxyuser:proxyuser src/ ./src/
COPY --chown=proxyuser:proxyuser run.py ./
COPY --chown=proxyuser:proxyuser scripts/ ./scripts/

# Switch back to root to set capabilities
USER root

# Grant capability to bind to privileged ports
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/python3.11

# Switch to non-root user for runtime
USER proxyuser

# Set environment variable to indicate we're running in Docker
ENV RUNNING_IN_DOCKER=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:80/health || exit 1

# Expose ports
EXPOSE 80 443

# Run the server
CMD ["pixi", "run", "python", "run.py"]