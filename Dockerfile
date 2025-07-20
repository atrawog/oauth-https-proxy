FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY pixi.toml .
COPY pyproject.toml .

# Copy local dependencies referenced in pixi.toml
COPY mcp-streamablehttp-client/ ./mcp-streamablehttp-client/
COPY mcp-echo-streamablehttp-server-stateful/ ./mcp-echo-streamablehttp-server-stateful/
COPY mcp-echo-streamablehttp-server-stateless/ ./mcp-echo-streamablehttp-server-stateless/

# Install pixi
RUN curl -fsSL https://pixi.sh/install.sh | bash && \
    echo 'export PATH="/root/.pixi/bin:$PATH"' >> ~/.bashrc

# Install dependencies using pixi
ENV PATH="/root/.pixi/bin:$PATH"
RUN pixi install

# Copy application code
COPY acme_certmanager/ ./acme_certmanager/
COPY scripts/ ./scripts/

# Create log directory
RUN mkdir -p /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:80/health || exit 1

# Expose ports
EXPOSE 80 443

# Run the server
CMD ["pixi", "run", "python", "scripts/run_server.py"]