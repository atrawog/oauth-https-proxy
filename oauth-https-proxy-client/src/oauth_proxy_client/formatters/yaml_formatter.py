"""YAML output formatter."""

import yaml
from typing import Any
from datetime import datetime, date
from .base import OutputFormatter


def datetime_representer(dumper, data):
    """Represent datetime objects in YAML."""
    return dumper.represent_scalar('tag:yaml.org,2002:str', data.isoformat())


# Register datetime representer
yaml.add_representer(datetime, datetime_representer)
yaml.add_representer(date, datetime_representer)


class YAMLFormatter(OutputFormatter):
    """Format output as YAML."""
    
    def format(self, data: Any, **kwargs) -> str:
        """Format data as YAML.
        
        Args:
            data: Data to format
            **kwargs: Options including:
                - default_flow_style: Use flow style (default: False)
                - indent: Indentation spaces (default: 2)
                - width: Line width limit (default: 80)
                - sort_keys: Sort dictionary keys (default: False)
        
        Returns:
            YAML formatted string
        """
        return yaml.dump(
            data,
            default_flow_style=kwargs.get('default_flow_style', False),
            indent=kwargs.get('indent', 2),
            width=kwargs.get('width', 80),
            sort_keys=kwargs.get('sort_keys', False),
            allow_unicode=True
        )