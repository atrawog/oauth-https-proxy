"""Base formatter classes and registry."""

import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union


class OutputFormatter(ABC):
    """Abstract base class for output formatters."""
    
    @abstractmethod
    def format(self, data: Any, **kwargs) -> str:
        """Format data for output.
        
        Args:
            data: Data to format
            **kwargs: Formatter-specific options
        
        Returns:
            Formatted string
        """
        pass
    
    def supports_type(self, data: Any) -> bool:
        """Check if formatter supports the data type.
        
        Args:
            data: Data to check
        
        Returns:
            True if formatter can handle this data type
        """
        return True
    
    def is_suitable_for_terminal(self) -> bool:
        """Check if formatter is suitable for terminal output.
        
        Returns:
            True if suitable for terminal display
        """
        return True


class FormatterRegistry:
    """Registry for output formatters."""
    
    def __init__(self):
        """Initialize formatter registry."""
        self.formatters: Dict[str, OutputFormatter] = {}
        self.default_format = 'table'
    
    def register(self, name: str, formatter: OutputFormatter):
        """Register a formatter.
        
        Args:
            name: Formatter name
            formatter: Formatter instance
        """
        self.formatters[name] = formatter
    
    def unregister(self, name: str):
        """Unregister a formatter.
        
        Args:
            name: Formatter name to remove
        """
        if name in self.formatters:
            del self.formatters[name]
    
    def get(self, name: str) -> Optional[OutputFormatter]:
        """Get a formatter by name.
        
        Args:
            name: Formatter name
        
        Returns:
            Formatter instance or None
        """
        return self.formatters.get(name)
    
    def format(self, data: Any, format_type: str = 'auto', **kwargs) -> str:
        """Format data using specified formatter.
        
        Args:
            data: Data to format
            format_type: Formatter to use ('auto' for automatic selection)
            **kwargs: Formatter-specific options
        
        Returns:
            Formatted string
        
        Raises:
            ValueError: If formatter not found or data type not supported
        """
        # Handle auto format selection
        if format_type == 'auto':
            format_type = self._auto_select_format(data)
        
        # Get formatter
        formatter = self.get(format_type)
        if not formatter:
            raise ValueError(f"Unknown format type: {format_type}")
        
        # Check if formatter supports data type
        if not formatter.supports_type(data):
            raise ValueError(f"Formatter '{format_type}' does not support this data type")
        
        # Format and return
        return formatter.format(data, **kwargs)
    
    def _auto_select_format(self, data: Any) -> str:
        """Automatically select format based on context.
        
        Args:
            data: Data to format
        
        Returns:
            Selected format type
        """
        # Check if output is to terminal
        if sys.stdout.isatty():
            # Terminal output - prefer table for lists/dicts
            if isinstance(data, (list, dict)):
                return 'table'
            else:
                return 'json'
        else:
            # Pipe or redirect - prefer JSON
            return 'json'
    
    def list_formats(self) -> List[str]:
        """Get list of available formats.
        
        Returns:
            List of format names
        """
        return list(self.formatters.keys())