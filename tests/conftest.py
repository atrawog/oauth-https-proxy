"""Pytest configuration for integration tests."""

import os
import time
import pytest
import httpx
import redis
from typing import Generator

# Test configuration - NO DEFAULTS!
TEST_BASE_URL = os.getenv("TEST_BASE_URL")  # From .env via just
REDIS_URL = os.getenv("REDIS_URL")  # From .env via just - use same Redis as app!
ACME_STAGING_URL = os.getenv("ACME_STAGING_URL")  # From .env via just


@pytest.fixture(scope="session")
def redis_client() -> Generator[redis.Redis, None, None]:
    """Provide Redis client for tests."""
    client = redis.from_url(REDIS_URL, decode_responses=True)
    
    # Wait for Redis to be ready
    max_retries = 30
    for i in range(max_retries):
        try:
            if client.ping():
                break
        except redis.ConnectionError:
            if i == max_retries - 1:
                raise
            time.sleep(1)
    
    # WARNING: Not flushing database since we're using production Redis!
    # This means tests must clean up after themselves
    
    yield client
    
    # Don't flush on cleanup - we're using production Redis!
    client.close()


@pytest.fixture(scope="session")
def http_client() -> Generator[httpx.Client, None, None]:
    """Provide HTTP client for API tests."""
    with httpx.Client(base_url=TEST_BASE_URL, timeout=30.0) as client:
        # Wait for service to be ready
        max_retries = 30
        for i in range(max_retries):
            try:
                response = client.get("/health")
                if response.status_code == 200:
                    break
            except httpx.ConnectError:
                if i == max_retries - 1:
                    raise
                time.sleep(1)
        
        yield client


@pytest.fixture
def test_domain():
    """Provide test domain for ACME staging."""
    # NO DEFAULTS! Must come from .env
    base_domain = os.getenv("TEST_DOMAIN_BASE")
    assert base_domain, "TEST_DOMAIN_BASE not set - must be loaded from .env via just"
    import uuid
    return f"test-{uuid.uuid4().hex[:8]}.{base_domain}"


@pytest.fixture
def test_email():
    """Provide test email for ACME."""
    email = os.getenv("TEST_EMAIL")
    assert email, "TEST_EMAIL not set - must be loaded from .env via just"
    return email


@pytest.fixture
def cert_request_data(test_domain, test_email):
    """Provide certificate request data."""
    return {
        "domain": test_domain,
        "email": test_email,
        "cert_name": "test-cert",
        "acme_directory_url": ACME_STAGING_URL
    }


@pytest.fixture
def auth_token():
    """Provide authentication token for API requests."""
    token = os.getenv("ADMIN_TOKEN")
    assert token, "ADMIN_TOKEN not set - must be loaded from .env via just"
    return token