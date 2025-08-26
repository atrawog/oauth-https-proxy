"""Python logging configuration for the OAuth HTTPS Proxy.

This module sets up the Python logging system for console output and
optional file logging. It's used alongside the Redis-based logging for
components that need immediate console visibility (dispatcher, main).

Environment Variables:
    LOG_LEVEL: Logging level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)
    PYTHON_LOG_ENABLED: Enable Python logging (default: true)
    PYTHON_LOG_FORMAT: Log message format (default: see below)
    DUAL_LOG_COMPONENTS: Comma-separated list of components using dual logging
"""

import os
import sys
import logging
from typing import Optional, List, Set

from .log_levels import TRACE, setup_trace_logging

# Ensure TRACE level is set up
setup_trace_logging()

# Default components that should use dual logging
DEFAULT_DUAL_LOG_COMPONENTS = {'dispatcher', 'main', 'redis_stream_consumer'}


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output."""
    
    # ANSI color codes
    COLORS = {
        'TRACE': '\033[90m',     # Dark gray
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        """Format the log record with colors if supported."""
        # Get the base formatted message
        msg = super().format(record)
        
        # Add color if we're in a TTY
        if sys.stdout.isatty():
            levelname = record.levelname
            color = self.COLORS.get(levelname, '')
            if color:
                # Color the entire log line
                msg = f"{color}{msg}{self.RESET}"
        
        return msg


def setup_python_logging(
    log_level: Optional[str] = None,
    use_colors: bool = True,
    log_format: Optional[str] = None
) -> logging.Logger:
    """Configure Python logging with console output.
    
    Args:
        log_level: Logging level (if None, reads from env)
        use_colors: Whether to use colored output for TTY
        log_format: Custom log format (if None, uses default)
        
    Returns:
        Configured root logger
    """
    # Get configuration from environment
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    if log_format is None:
        log_format = os.getenv(
            'PYTHON_LOG_FORMAT',
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Convert string level to logging constant
    if log_level == 'TRACE':
        level = TRACE
    else:
        level = getattr(logging, log_level, logging.INFO)
    
    # Remove any existing handlers to avoid duplicates
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Create formatter (colored or plain)
    if use_colors and sys.stdout.isatty():
        formatter = ColoredFormatter(log_format)
    else:
        formatter = logging.Formatter(log_format)
    
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # Also configure the oauth_proxy namespace
    oauth_logger = logging.getLogger('oauth_proxy')
    oauth_logger.setLevel(level)
    
    # Log the configuration
    root_logger.info(f"Python logging configured: level={log_level}, colors={use_colors and sys.stdout.isatty()}")
    
    return root_logger


def get_dual_logging_components() -> Set[str]:
    """Get the list of components that should use dual logging.
    
    Returns:
        Set of component names
    """
    env_components = os.getenv('DUAL_LOG_COMPONENTS', '')
    
    if env_components:
        # Parse comma-separated list from environment
        components = {c.strip() for c in env_components.split(',') if c.strip()}
    else:
        # Use defaults
        components = DEFAULT_DUAL_LOG_COMPONENTS.copy()
    
    return components


def should_use_dual_logging(component: str) -> bool:
    """Check if a component should use dual logging.
    
    Args:
        component: Component name to check
        
    Returns:
        True if component should use dual logging
    """
    components = get_dual_logging_components()
    return component in components


def configure_component_logger(component: str, level: Optional[str] = None) -> logging.Logger:
    """Configure a logger for a specific component.
    
    Args:
        component: Component name
        level: Optional log level override
        
    Returns:
        Configured logger for the component
    """
    logger_name = f"oauth_proxy.{component}"
    logger = logging.getLogger(logger_name)
    
    if level:
        if level == 'TRACE':
            logger.setLevel(TRACE)
        else:
            logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    return logger


def silence_noisy_loggers():
    """Silence or reduce verbosity of noisy third-party loggers."""
    # Silence or reduce common noisy loggers
    noisy_loggers = [
        'asyncio',
        'aioredis',
        'redis',
        'httpx',
        'httpcore',
        'hpack',
        'hypercorn.access',
        'hypercorn.error',
        'python_multipart',  # Silence verbose multipart parsing debug logs
        'python_multipart.multipart',  # Also silence the specific submodule
    ]
    
    for logger_name in noisy_loggers:
        logger = logging.getLogger(logger_name)
        # Set to WARNING to reduce noise but still see errors
        logger.setLevel(logging.WARNING)


# Initialize Python logging when module is imported if enabled
if os.getenv('PYTHON_LOG_ENABLED', 'true').lower() == 'true':
    setup_python_logging()
    silence_noisy_loggers()