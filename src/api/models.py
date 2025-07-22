"""API-specific models and data structures."""

from pydantic import BaseModel


class HealthStatus(BaseModel):
    """Health check response model."""
    status: str
    scheduler: bool
    redis: str
    certificates_loaded: int
    https_enabled: bool
    orphaned_resources: int = 0