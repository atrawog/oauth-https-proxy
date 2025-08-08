"""Output formatters for displaying data in various formats."""

from .base import OutputFormatter, FormatterRegistry
from .json_formatter import JSONFormatter
from .table_formatter import TableFormatter
from .yaml_formatter import YAMLFormatter
from .csv_formatter import CSVFormatter

# Register default formatters
registry = FormatterRegistry()
registry.register('json', JSONFormatter())
registry.register('table', TableFormatter())
registry.register('yaml', YAMLFormatter())
registry.register('csv', CSVFormatter())

# Convenience function
def format_output(data, format_type='auto', **kwargs):
    """Format data for output.
    
    Args:
        data: Data to format
        format_type: Output format ('json', 'table', 'yaml', 'csv', 'auto')
        **kwargs: Additional formatter options
    
    Returns:
        Formatted string
    """
    return registry.format(data, format_type, **kwargs)

__all__ = [
    'OutputFormatter',
    'FormatterRegistry',
    'JSONFormatter',
    'TableFormatter',
    'YAMLFormatter',
    'CSVFormatter',
    'format_output',
    'registry',
]