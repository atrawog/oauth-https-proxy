"""CSV output formatter."""

import csv
import io
from typing import Any, List, Dict, Union
from .base import OutputFormatter


class CSVFormatter(OutputFormatter):
    """Format output as CSV."""
    
    def format(self, data: Any, **kwargs) -> str:
        """Format data as CSV.
        
        Args:
            data: Data to format (list of dicts or single dict)
            **kwargs: Options including:
                - delimiter: Field delimiter (default: ',')
                - quoting: Quoting style (default: csv.QUOTE_MINIMAL)
                - headers: Include headers (default: True)
        
        Returns:
            CSV formatted string
        """
        # Convert single dict to list
        if isinstance(data, dict) and not any(isinstance(v, (list, dict)) for v in data.values()):
            data = [data]
        elif isinstance(data, dict):
            # Dictionary with nested data - format as key-value pairs
            data = [{'key': k, 'value': self._format_value(v)} for k, v in data.items()]
        
        if not isinstance(data, list):
            # For non-list data, create a simple single-column CSV
            data = [{'value': str(data)}]
        
        # Handle empty data
        if not data:
            return ""
        
        # Handle list of dictionaries
        if data and isinstance(data[0], dict):
            output = io.StringIO()
            
            # Get all unique keys maintaining order
            keys = []
            seen = set()
            for item in data:
                for key in item.keys():
                    if key not in seen:
                        keys.append(key)
                        seen.add(key)
            
            writer = csv.DictWriter(
                output,
                fieldnames=keys,
                delimiter=kwargs.get('delimiter', ','),
                quoting=kwargs.get('quoting', csv.QUOTE_MINIMAL)
            )
            
            # Write headers if requested
            if kwargs.get('headers', True):
                writer.writeheader()
            
            # Write rows
            for item in data:
                # Format values
                formatted_item = {}
                for key in keys:
                    value = item.get(key, '')
                    formatted_item[key] = self._format_value(value)
                writer.writerow(formatted_item)
            
            return output.getvalue()
        
        # Handle list of simple values
        elif data and not isinstance(data[0], dict):
            output = io.StringIO()
            writer = csv.writer(
                output,
                delimiter=kwargs.get('delimiter', ','),
                quoting=kwargs.get('quoting', csv.QUOTE_MINIMAL)
            )
            
            # Write header if requested
            if kwargs.get('headers', True):
                writer.writerow(['value'])
            
            # Write values
            for item in data:
                writer.writerow([self._format_value(item)])
            
            return output.getvalue()
        
        return ""
    
    def _format_value(self, value: Any) -> str:
        """Format value for CSV output.
        
        Args:
            value: Value to format
        
        Returns:
            Formatted string
        """
        if value is None:
            return ''
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        elif isinstance(value, (list, tuple)):
            # Join list items with semicolon
            return ';'.join(str(item) for item in value)
        elif isinstance(value, dict):
            # Format dict as JSON-like string
            items = [f"{k}={v}" for k, v in value.items()]
            return ';'.join(items)
        else:
            return str(value)
    
    def supports_type(self, data: Any) -> bool:
        """Check if formatter supports the data type.
        
        Args:
            data: Data to check
        
        Returns:
            True if data can be formatted as CSV
        """
        return isinstance(data, (list, dict)) or hasattr(data, '__iter__')
    
    def is_suitable_for_terminal(self) -> bool:
        """CSV is better for files than terminal display.
        
        Returns:
            False - not ideal for terminal
        """
        return False