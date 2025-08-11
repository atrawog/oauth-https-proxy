"""Table output formatter using rich."""

from typing import Any, Dict, List, Union
from rich.console import Console
from rich.table import Table
from rich.text import Text
from io import StringIO
from .base import OutputFormatter
from .enhanced_table import EnhancedTableFormatter


class TableFormatter(OutputFormatter):
    """Format output as a rich table."""
    
    def __init__(self):
        """Initialize formatter with enhanced capabilities."""
        self.enhanced = EnhancedTableFormatter()
    
    def format(self, data: Any, **kwargs) -> str:
        """Format data as a table.
        
        Args:
            data: Data to format (list of dicts or single dict)
            **kwargs: Options including:
                - title: Table title
                - show_header: Show column headers (default: True)
                - show_lines: Show row lines (default: False)
                - max_width: Maximum column width (default: None)
                - style: Table style (default: 'bold cyan')
                - highlight: Highlight rows (default: True)
                - data_type: Hint for data type ('tokens', 'proxies', etc.)
                - enhanced: Use enhanced formatting (default: True)
        
        Returns:
            Table formatted string
        """
        # Use enhanced formatter if available and not explicitly disabled
        if kwargs.get('enhanced', True):
            try:
                return self.enhanced.format(data, **kwargs)
            except Exception:
                # Fall back to basic formatter on any error
                pass
        # Convert single dict to list
        if isinstance(data, dict) and not any(isinstance(v, (list, dict)) for v in data.values()):
            data = [data]
        elif isinstance(data, dict):
            # Dictionary with nested data - format as key-value pairs
            data = [{'Key': k, 'Value': self._format_value(v)} for k, v in data.items()]
        
        if not isinstance(data, list):
            # For non-list data, create a simple single-cell table
            data = [{'Value': str(data)}]
        
        # Handle empty data
        if not data:
            return "No data to display"
        
        # Create table
        table = Table(
            title=kwargs.get('title'),
            show_header=kwargs.get('show_header', True),
            show_lines=kwargs.get('show_lines', False),
            style=kwargs.get('style', 'bold cyan'),
            highlight=kwargs.get('highlight', True),
        )
        
        # Handle list of dictionaries
        if data and isinstance(data[0], dict):
            # Get all unique keys maintaining order
            keys = []
            seen = set()
            for item in data:
                for key in item.keys():
                    if key not in seen:
                        keys.append(key)
                        seen.add(key)
            
            # Add columns
            for key in keys:
                # Format column headers
                header = self._format_header(key)
                table.add_column(
                    header,
                    max_width=kwargs.get('max_width'),
                    overflow='fold'
                )
            
            # Add rows
            for item in data:
                row = []
                for key in keys:
                    value = item.get(key, '')
                    row.append(self._format_value(value))
                table.add_row(*row)
        
        # Handle list of simple values
        elif data and not isinstance(data[0], dict):
            table.add_column('Value', max_width=kwargs.get('max_width'))
            for item in data:
                table.add_row(self._format_value(item))
        
        # Render to string
        console = Console(file=StringIO(), force_terminal=True)
        console.print(table)
        return console.file.getvalue()
    
    def _format_header(self, key: str) -> str:
        """Format column header.
        
        Args:
            key: Raw column key
        
        Returns:
            Formatted header string
        """
        # Convert snake_case to Title Case
        return key.replace('_', ' ').title()
    
    def _format_value(self, value: Any) -> str:
        """Format cell value.
        
        Args:
            value: Value to format
        
        Returns:
            Formatted string
        """
        if value is None:
            return Text("—", style="dim")
        elif isinstance(value, bool):
            return Text("✓" if value else "✗", style="green" if value else "red")
        elif isinstance(value, (list, tuple)):
            if not value:
                return Text("[]", style="dim")
            # Format list items
            items = [str(item) for item in value[:3]]  # Show first 3 items
            if len(value) > 3:
                items.append(f"... ({len(value) - 3} more)")
            return Text(", ".join(items))
        elif isinstance(value, dict):
            if not value:
                return Text("{}", style="dim")
            # Show dict summary
            return Text(f"<{len(value)} items>", style="dim")
        else:
            # Convert to string and truncate if too long
            text = str(value)
            if len(text) > 100:
                text = text[:97] + "..."
            return Text(text)
    
    def supports_type(self, data: Any) -> bool:
        """Check if formatter supports the data type.
        
        Args:
            data: Data to check
        
        Returns:
            True if data can be formatted as table
        """
        return isinstance(data, (list, dict)) or hasattr(data, '__iter__')