# Multi-stage build for mcp-simple-streamablehttp server
FROM python:3.12-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy the application source
COPY mcp_simple_streamablehttp/ ./mcp_simple_streamablehttp/
COPY pyproject.toml ./
COPY README.md ./

# Install pip-tools and build dependencies
RUN pip install --upgrade pip setuptools wheel hatch

# Build the wheel
RUN hatch build -t wheel

# Runtime stage
FROM python:3.12-slim

# Set environment variables
ENV NODE_ENV=production \
    PORT=3000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Set working directory
WORKDIR /app

# Copy wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install the application
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm /tmp/*.whl

# Expose the default port
EXPOSE 3000

# Run the application using the installed command
CMD ["mcp-simple-streamablehttp", "--port", "3000"]