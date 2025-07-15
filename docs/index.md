# ACME Certificate Manager

Welcome to the ACME Certificate Manager documentation!

## Overview

ACME Certificate Manager is a pure Python HTTPS server that automatically obtains and renews TLS certificates via the ACME protocol. It provides a complete solution for certificate management with these key features:

- **Zero-downtime certificate updates** through hot-reloading
- **Redis-exclusive storage** - no filesystem persistence
- **Multi-domain certificates** with SNI support
- **Automatic renewal** before expiry
- **RESTful API** for management
- **Docker-ready** deployment

## Quick Links

::::{grid} 2
:::{grid-item-card} Getting Started
:link: getting-started
:link-type: doc

Learn how to install and configure ACME Certificate Manager
:::

:::{grid-item-card} API Reference
:link: api-reference
:link-type: doc

Complete API documentation with examples
:::

:::{grid-item-card} Architecture
:link: architecture
:link-type: doc

Understand the system design and components
:::

:::{grid-item-card} Deployment
:link: deployment
:link-type: doc

Deploy to production with Docker or manually
:::
::::

## Why ACME Certificate Manager?

### Problem

Managing HTTPS certificates is complex:
- Manual certificate generation and renewal
- Service restarts cause downtime
- Certificate files scattered across filesystem
- Complex nginx/Apache configuration
- No centralized management

### Solution

ACME Certificate Manager solves these problems:
- **Automatic**: Certificates generated and renewed automatically
- **Zero-downtime**: Hot-reload certificates without restarts
- **Centralized**: All data in Redis, manageable via API
- **Simple**: Just point your domains and go
- **Scalable**: Horizontal scaling with shared Redis

## Key Features

### 🔐 ACME Protocol Integration
Full implementation of ACME v2 protocol for Let's Encrypt and other providers.

### 🔄 Auto-Renewal
Certificates automatically renewed 30 days before expiry.

### 🚀 Hot Reload
Update certificates without restarting the server or dropping connections.

### 📦 Redis Storage
All data stored in Redis - certificates, keys, and configuration.

### 🌐 Multi-Domain Support
Single certificate for multiple domains with SNI routing.

### 🏥 Health Monitoring
Built-in health checks for monitoring and orchestration.

## Next Steps

- [Get Started](getting-started) with installation and configuration
- Review the [API Reference](api-reference) for integration
- Understand the [Architecture](architecture) for customization
- Follow the [Deployment Guide](deployment) for production