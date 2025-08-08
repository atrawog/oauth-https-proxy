"""JSON output formatter."""

import json
from typing import Any
from datetime import datetime, date
from .base import OutputFormatter


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""
    
    def default(self, obj):
        """Encode datetime objects as ISO format strings."""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


class JSONFormatter(OutputFormatter):
    """Format output as JSON."""
    
    def format(self, data: Any, **kwargs) -> str:
        """Format data as JSON.
        
        Args:
            data: Data to format
            **kwargs: Options including:
                - indent: Indentation level (default: 2)
                - sort_keys: Sort dictionary keys (default: False)
                - compact: Compact output without indentation (default: False)
        
        Returns:
            JSON formatted string
        """
        indent = None if kwargs.get('compact', False) else kwargs.get('indent', 2)
        sort_keys = kwargs.get('sort_keys', False)
        
        return json.dumps(
            data,
            cls=DateTimeEncoder,
            indent=indent,
            sort_keys=sort_keys,
            ensure_ascii=False
        )