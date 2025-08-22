"""Custom logging levels for the application.

This module defines additional logging levels like TRACE for very verbose debugging.
"""

import logging

# Define TRACE level (below DEBUG)
TRACE = 5

def setup_trace_logging():
    """Set up the TRACE logging level in Python's logging system."""
    # Add TRACE level to logging module
    logging.addLevelName(TRACE, "TRACE")
    
    # Add trace method to Logger class
    def trace(self, message, *args, **kwargs):
        if self.isEnabledFor(TRACE):
            self._log(TRACE, message, args, **kwargs)
    
    logging.Logger.trace = trace
    
    # Add trace method to LoggerAdapter class  
    def adapter_trace(self, message, *args, **kwargs):
        self.log(TRACE, message, *args, **kwargs)
    
    logging.LoggerAdapter.trace = adapter_trace
    
    # Set up level name mapping
    logging.TRACE = TRACE
    
    return TRACE

# Initialize TRACE level when module is imported
TRACE_LEVEL = setup_trace_logging()