# Multi-stage build for FastMCP Echo Server
FROM python:3.12-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy the application source
COPY server.py ./
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

# Copy server file directly (FastMCP needs the source)
COPY server.py ./

# Install FastMCP and dependencies
RUN pip install --no-cache-dir fastmcp uvicorn

# Expose the default port
EXPOSE 3000

# Run the FastMCP application directly
CMD ["python", "server.py"]