# Development Guide

Guide for contributing to ACME Certificate Manager development.

## Development Setup

### Prerequisites

- Python 3.10+
- Docker and Docker Compose
- pixi (Python environment manager)
- Redis (via Docker)

### Environment Setup

1. **Install pixi**
   ```bash
   curl -fsSL https://pixi.sh/install.sh | bash
   ```

2. **Clone repository**
   ```bash
   git clone https://github.com/acme-certmanager/acme-certmanager
   cd acme-certmanager
   ```

3. **Install dependencies**
   ```bash
   just setup
   ```

4. **Start Redis**
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

5. **Run development server**
   ```bash
   just dev
   ```

## Project Structure

```
acme-certmanager/
├── acme_certmanager/       # Main package
│   ├── __init__.py        # Package initialization
│   ├── server.py          # FastAPI application
│   ├── manager.py         # Certificate manager
│   ├── acme_client.py     # ACME protocol client
│   ├── storage.py         # Redis storage backend
│   ├── scheduler.py       # Auto-renewal scheduler
│   └── models.py          # Pydantic models
├── tests/                 # Test suite
│   ├── conftest.py       # Pytest configuration
│   └── test_*.py         # Test files
├── scripts/              # Utility scripts
├── docs/                 # JupyterBook documentation
├── docker-compose.yml    # Service orchestration
├── Dockerfile           # Container image
├── justfile            # Task automation
├── pixi.toml          # Python environment
└── pyproject.toml     # Package metadata
```

## Code Style

### Python Style Guide

Follow PEP 8 with these additions:

- Line length: 120 characters
- Use type hints for all functions
- Docstrings for all public functions
- No trailing whitespace

### Linting and Formatting

```bash
# Run linting
just lint

# Format code
pixi run ruff format .

# Type checking (future)
pixi run mypy acme_certmanager
```

### Example Code Style

```python
from typing import Optional, List
from datetime import datetime

from pydantic import BaseModel


class Certificate(BaseModel):
    """Certificate data model.
    
    Attributes:
        domains: List of domain names
        expires_at: Certificate expiration date
    """
    domains: List[str]
    expires_at: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        """Check if certificate is expired.
        
        Returns:
            True if expired, False otherwise
        """
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
```

## Testing

### Test Philosophy

- **No mocks**: Test against real services
- **Integration focus**: Test complete workflows
- **Docker-based**: Consistent test environment
- **Fast feedback**: Quick test execution

### Running Tests

```bash
# Run all tests
just test-all

# Run specific test
pixi run pytest tests/test_integration.py::TestHealthCheck

# Run with coverage
pixi run pytest --cov=acme_certmanager tests/

# Run against Docker services
just test tests/test_docker.py
```

### Writing Tests

```python
import pytest
import httpx


class TestCertificateAPI:
    """Test certificate management API."""
    
    def test_create_certificate(
        self, 
        http_client: httpx.Client,
        cert_request_data: dict
    ):
        """Test certificate creation."""
        response = http_client.post(
            "/certificates",
            json=cert_request_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["domains"] == [cert_request_data["domain"]]
        assert data["status"] == "active"
```

### Test Environment

Tests use Docker Compose:

```yaml
# docker-compose.test.yml
services:
  test-runner:
    build: .
    command: pixi run pytest tests/ -v
    environment:
      TEST_API_URL: http://certmanager:80
      TEST_REDIS_URL: redis://redis:6379/1
```

## Adding Features

### 1. Plan the Feature

- Create issue describing the feature
- Discuss design in issue comments
- Get approval before implementation

### 2. Implement Feature

Example: Adding DNS-01 challenge support

```python
# acme_certmanager/challenges.py
from abc import ABC, abstractmethod


class ChallengeHandler(ABC):
    """Base class for ACME challenges."""
    
    @abstractmethod
    async def setup(self, domain: str, token: str, auth: str):
        """Setup challenge validation."""
        pass
    
    @abstractmethod
    async def cleanup(self, domain: str, token: str):
        """Cleanup after validation."""
        pass


class DNS01Handler(ChallengeHandler):
    """DNS-01 challenge handler."""
    
    async def setup(self, domain: str, token: str, auth: str):
        """Create DNS TXT record."""
        record_name = f"_acme-challenge.{domain}"
        record_value = auth
        # Implementation here
    
    async def cleanup(self, domain: str, token: str):
        """Remove DNS TXT record."""
        # Implementation here
```

### 3. Add Tests

```python
def test_dns01_challenge(challenge_handler):
    """Test DNS-01 challenge implementation."""
    handler = DNS01Handler()
    
    # Test setup
    await handler.setup("example.com", "token123", "auth456")
    
    # Verify DNS record created
    # ...
    
    # Test cleanup
    await handler.cleanup("example.com", "token123")
```

### 4. Update Documentation

- Add feature to README
- Update API documentation
- Add configuration examples
- Include in architecture docs

### 5. Submit Pull Request

```bash
# Create feature branch
git checkout -b feature/dns01-support

# Make changes and commit
git add .
git commit -m "Add DNS-01 challenge support"

# Push and create PR
git push origin feature/dns01-support
```

## Debugging

### Local Debugging

1. **Enable debug logging**
   ```bash
   LOG_LEVEL=DEBUG just dev
   ```

2. **Use debugger**
   ```python
   import pdb; pdb.set_trace()
   ```

3. **Check Redis data**
   ```bash
   redis-cli
   > KEYS *
   > GET cert:production
   ```

### Docker Debugging

1. **View logs**
   ```bash
   docker-compose logs -f certmanager
   ```

2. **Execute commands**
   ```bash
   docker-compose exec certmanager /bin/sh
   ```

3. **Debug build**
   ```bash
   docker-compose build --no-cache certmanager
   ```

## Performance Optimization

### Profiling

```python
import cProfile
import pstats

def profile_function():
    """Profile certificate generation."""
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Code to profile
    manager.create_certificate(request)
    
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats()
```

### Load Testing

```bash
# Using locust
pixi run locust -f tests/load_test.py \
    --host http://localhost \
    --users 100 \
    --spawn-rate 10
```

### Optimization Tips

1. **Batch operations**: Process multiple certificates together
2. **Connection pooling**: Reuse Redis connections
3. **Async operations**: Use async/await properly
4. **Caching**: Cache ACME directory metadata

## Release Process

### Version Numbering

Follow semantic versioning:
- MAJOR: Breaking changes
- MINOR: New features
- PATCH: Bug fixes

### Release Steps

1. **Update version**
   ```bash
   # pyproject.toml
   version = "1.2.0"
   
   # acme_certmanager/__init__.py
   __version__ = "1.2.0"
   ```

2. **Update changelog**
   ```markdown
   ## [1.2.0] - 2024-01-15
   ### Added
   - DNS-01 challenge support
   ### Fixed
   - Rate limit handling
   ```

3. **Create release**
   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```

4. **Build and publish**
   ```bash
   just build
   just upload
   ```

## Contributing Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- No harassment or discrimination

### Pull Request Process

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Ensure all tests pass
5. Update documentation
6. Submit pull request
7. Address review feedback
8. Merge after approval

### Commit Messages

Format:
```
type(scope): subject

body

footer
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- test: Tests
- refactor: Code refactoring
- style: Formatting
- chore: Maintenance

Example:
```
feat(acme): add DNS-01 challenge support

- Implement DNS01Handler class
- Add route53 and cloudflare providers
- Include configuration examples

Fixes #123
```