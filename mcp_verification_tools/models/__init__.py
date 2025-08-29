"""Data models for MCP verification tools."""

from .test_results import TestResult, TestStatus
from .config import TestConfig

__all__ = ["TestResult", "TestStatus", "TestConfig"]