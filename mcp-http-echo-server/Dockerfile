# Multi-stage build for optimal image size
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy package files
COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/

# Install the package and dependencies
# Force rebuild by adding timestamp v3 for middleware fix
RUN echo "Build timestamp v3 middleware fix: $(date +%s)" && \
    pip install --no-cache-dir --user .

# Runtime stage
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash mcp && \
    mkdir -p /app && \
    chown -R mcp:mcp /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/mcp/.local

# Set working directory (no need to copy source since package is installed)
WORKDIR /app

# Set environment variables
ENV PATH=/home/mcp/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    MCP_ECHO_HOST=0.0.0.0 \
    MCP_ECHO_PORT=3000 \
    MCP_MODE=stateless \
    MCP_ECHO_DEBUG=false

# Switch to non-root user
USER mcp

# Expose the port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:3000/health')" || exit 1

# Run the server
ENTRYPOINT ["python", "-m", "mcp_http_echo_server"]

# Default arguments (can be overridden)
CMD ["--host", "0.0.0.0", "--port", "3000", "--mode", "stateless"]