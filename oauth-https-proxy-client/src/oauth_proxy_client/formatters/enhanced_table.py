"""Enhanced table formatter with context-aware formatting."""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED, MINIMAL, SIMPLE
from io import StringIO
import json


class EnhancedTableFormatter:
    """Smart table formatter with type-specific layouts."""
    
    # Column configurations for different data types
    COLUMN_CONFIGS = {
        'tokens': {
            'columns': ['name', 'cert_email', 'created_at', 'owner'],
            'headers': ['Token Name', 'Certificate Email', 'Created', 'Owner'],
            'styles': ['bold cyan', 'yellow', 'dim', 'dim'],
            'box': ROUNDED,
        },
        'certificates': {
            'columns': ['cert_name', 'domains', 'status', 'expires_at', 'email'],
            'headers': ['Certificate', 'Domains', 'Status', 'Expires', 'Email'],
            'styles': ['bold cyan', 'white', 'status', 'date', 'dim'],
            'box': ROUNDED,
        },
        'proxies': {
            'columns': ['hostname', 'target_url', 'status_summary', 'auth_enabled', 'cert_name'],
            'headers': ['Hostname', 'Target', 'Status', 'Auth', 'Certificate'],
            'styles': ['bold cyan', 'blue', 'status', 'bool', 'yellow'],
            'box': ROUNDED,
        },
        'services': {
            'columns': ['service_name', 'service_type', 'status_info', 'ports_summary', 'memory_cpu'],
            'headers': ['Service', 'Type', 'Status', 'Ports', 'Resources'],
            'styles': ['bold cyan', 'yellow', 'status', 'dim', 'dim'],
            'box': ROUNDED,
        },
        'routes': {
            'columns': ['route_id', 'path_pattern', 'target_summary', 'priority', 'scope_display', 'enabled'],
            'headers': ['ID', 'Path', 'Target', 'Priority', 'Proxy/Scope', 'Status'],
            'styles': ['dim', 'bold cyan', 'blue', 'number', 'yellow', 'bool'],
            'box': SIMPLE,
        },
        'oauth_clients': {
            'columns': ['client_id', 'client_name', 'active_tokens', 'created_at', 'last_used'],
            'headers': ['Client ID', 'Name', 'Active Tokens', 'Created', 'Last Used'],
            'styles': ['mono', 'bold cyan', 'number', 'date', 'date'],
            'box': ROUNDED,
        },
        'logs': {
            'columns': ['timestamp', 'client_ip', 'method_path', 'status_code', 'response_time'],
            'headers': ['Time', 'Client IP', 'Request', 'Status', 'Time (ms)'],
            'styles': ['dim', 'yellow', 'cyan', 'status_code', 'number'],
            'box': MINIMAL,
        }
    }
    
    def __init__(self):
        """Initialize the formatter."""
        self.console = Console(file=StringIO(), force_terminal=True)
    
    def format(self, data: Any, data_type: Optional[str] = None, **kwargs) -> str:
        """Format data with smart type detection and layout.
        
        Args:
            data: Data to format
            data_type: Type hint for data ('tokens', 'certificates', etc.)
            **kwargs: Additional formatting options
            
        Returns:
            Formatted table string
        """
        # Handle empty data
        if not data:
            return self._empty_message(data_type)
        
        # Convert single item to list
        if isinstance(data, dict) and not self._is_key_value_dict(data):
            data = [data]
        
        # Auto-detect data type if not provided
        if not data_type and isinstance(data, list) and data:
            data_type = self._detect_data_type(data[0])
        
        # Prepare data for display
        prepared_data = self._prepare_data(data, data_type)
        
        # Get configuration
        config = self.COLUMN_CONFIGS.get(data_type, self._default_config())
        
        # Create and populate table
        table = self._create_table(prepared_data, config, **kwargs)
        
        # Render to string
        self.console.file = StringIO()
        self.console.print(table)
        output = self.console.file.getvalue()
        
        # Add summary if applicable
        if data_type and len(data) > 5:
            summary = self._generate_summary(data, data_type)
            if summary:
                output += f"\n{summary}"
        
        return output
    
    def _detect_data_type(self, sample: Dict) -> Optional[str]:
        """Auto-detect data type from sample record."""
        if 'token' in sample or 'cert_email' in sample:
            return 'tokens'
        elif 'cert_name' in sample or 'fullchain_pem' in sample:
            return 'certificates'
        elif 'hostname' in sample and 'target_url' in sample:
            return 'proxies'
        elif 'service_name' in sample or 'image' in sample:
            return 'services'
        elif 'route_id' in sample or 'path_pattern' in sample:
            return 'routes'
        elif 'client_id' in sample and 'client_secret' in sample:
            return 'oauth_clients'
        elif 'client_ip' in sample or 'request_path' in sample:
            return 'logs'
        return None
    
    def _prepare_data(self, data: List[Dict], data_type: Optional[str]) -> List[Dict]:
        """Prepare and enhance data for display."""
        if not data_type:
            return data
        
        prepared = []
        for item in data:
            enhanced = item.copy()
            
            # Add computed fields based on type
            if data_type == 'proxies':
                enhanced['status_summary'] = self._proxy_status(item)
            elif data_type == 'services':
                enhanced['status_info'] = self._service_status(item)
                enhanced['ports_summary'] = self._ports_summary(item)
                enhanced['memory_cpu'] = self._resource_summary(item)
            elif data_type == 'routes':
                enhanced['target_summary'] = self._route_target(item)
                enhanced['scope_display'] = self._route_scope(item)
            elif data_type == 'logs':
                enhanced['method_path'] = f"{item.get('method', 'GET')} {item.get('path', '/')}"
                enhanced['response_time'] = item.get('response_time_ms', 0)
            elif data_type == 'oauth_clients':
                enhanced['active_tokens'] = len(item.get('tokens', []))
            
            prepared.append(enhanced)
        
        return prepared
    
    def _create_table(self, data: List[Dict], config: Dict, **kwargs) -> Table:
        """Create and populate a rich table."""
        # Create table with configuration
        table = Table(
            title=kwargs.get('title'),
            box=config.get('box', ROUNDED),
            show_header=kwargs.get('show_header', True),
            highlight=True,
            row_styles=["none", "dim"],  # Alternating row colors
        )
        
        # Add columns
        columns = config.get('columns', [])
        headers = config.get('headers', columns)
        styles = config.get('styles', [])
        
        for i, (col, header) in enumerate(zip(columns, headers)):
            style = styles[i] if i < len(styles) else None
            table.add_column(header, style=style if style not in ['status', 'bool', 'date', 'number', 'status_code', 'mono'] else None)
        
        # Add rows
        for item in data:
            row = []
            for i, col in enumerate(columns):
                value = item.get(col, '')
                style = styles[i] if i < len(styles) else None
                formatted = self._format_cell(value, style)
                row.append(formatted)
            table.add_row(*row)
        
        return table
    
    def _format_cell(self, value: Any, style: Optional[str]) -> str:
        """Format individual cell based on style hint."""
        if value is None or value == '':
            return Text("—", style="dim")
        
        # Handle style-specific formatting
        if style == 'status':
            return self._format_status(value)
        elif style == 'bool':
            return Text("✓", style="green") if value else Text("✗", style="dim red")
        elif style == 'date':
            return self._format_date(value)
        elif style == 'number':
            return self._format_number(value)
        elif style == 'status_code':
            return self._format_status_code(value)
        elif style == 'mono':
            return Text(str(value), style="bold mono")
        
        # Handle complex types
        if isinstance(value, list):
            if not value:
                return Text("[]", style="dim")
            if len(value) == 1:
                return str(value[0])
            return f"{value[0]} (+{len(value)-1})"
        elif isinstance(value, dict):
            return Text(f"{{{len(value)} fields}}", style="dim")
        
        # Default string formatting
        text = str(value)
        if len(text) > 50:
            text = text[:47] + "..."
        return text
    
    def _format_status(self, status: str) -> Text:
        """Format status with color coding."""
        status_lower = str(status).lower()
        if 'active' in status_lower or 'running' in status_lower or 'ready' in status_lower:
            return Text(f"● {status}", style="green")
        elif 'pending' in status_lower or 'starting' in status_lower:
            return Text(f"◌ {status}", style="yellow")
        elif 'error' in status_lower or 'failed' in status_lower:
            return Text(f"✗ {status}", style="red")
        elif 'stopped' in status_lower or 'disabled' in status_lower:
            return Text(f"○ {status}", style="dim")
        else:
            return Text(status)
    
    def _format_date(self, value: Any) -> Text:
        """Format date/time values."""
        if not value:
            return Text("—", style="dim")
        
        try:
            # Parse ISO format
            if isinstance(value, str):
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                # Format as relative time if recent
                now = datetime.now(dt.tzinfo)
                diff = now - dt
                if diff.days == 0 and diff.seconds < 3600:
                    mins = diff.seconds // 60
                    return Text(f"{mins}m ago", style="yellow")
                elif diff.days == 0:
                    hours = diff.seconds // 3600
                    return Text(f"{hours}h ago", style="yellow")
                elif diff.days < 7:
                    return Text(f"{diff.days}d ago", style="dim")
                else:
                    return Text(dt.strftime("%Y-%m-%d"), style="dim")
        except:
            pass
        
        return Text(str(value)[:10], style="dim")
    
    def _format_number(self, value: Any) -> Text:
        """Format numeric values."""
        try:
            num = float(value)
            if num >= 1000000:
                return Text(f"{num/1000000:.1f}M", style="bold")
            elif num >= 1000:
                return Text(f"{num/1000:.1f}K", style="bold")
            else:
                return Text(str(int(num)), style="cyan")
        except:
            return Text(str(value))
    
    def _format_status_code(self, code: Any) -> Text:
        """Format HTTP status codes with color."""
        try:
            code = int(code)
            if 200 <= code < 300:
                return Text(str(code), style="green")
            elif 300 <= code < 400:
                return Text(str(code), style="yellow")
            elif 400 <= code < 500:
                return Text(str(code), style="red")
            elif code >= 500:
                return Text(str(code), style="bold red")
            else:
                return Text(str(code))
        except:
            return Text(str(code))
    
    def _proxy_status(self, proxy: Dict) -> str:
        """Generate proxy status summary."""
        statuses = []
        if proxy.get('enable_http'):
            statuses.append('HTTP')
        if proxy.get('enable_https'):
            if proxy.get('cert_name'):
                statuses.append('HTTPS✓')
            else:
                statuses.append('HTTPS⚠')
        if proxy.get('auth_enabled'):
            statuses.append('Auth')
        return ' | '.join(statuses) if statuses else 'Disabled'
    
    def _service_status(self, service: Dict) -> str:
        """Generate service status summary."""
        status = service.get('status', 'unknown')
        if service.get('service_type') == 'docker':
            container_status = service.get('container_status', '')
            if container_status:
                return container_status
        return status
    
    def _ports_summary(self, service: Dict) -> str:
        """Generate ports summary for service."""
        ports = service.get('port_configs', [])
        if not ports:
            if service.get('internal_port'):
                return str(service['internal_port'])
            return '—'
        
        port_strs = []
        for p in ports[:2]:  # Show max 2 ports
            host = p.get('host', p.get('external_port'))
            container = p.get('container', p.get('internal_port'))
            if host and container:
                port_strs.append(f"{host}→{container}")
        
        if len(ports) > 2:
            port_strs.append(f"+{len(ports)-2}")
        
        return ', '.join(port_strs) if port_strs else '—'
    
    def _resource_summary(self, service: Dict) -> str:
        """Generate resource summary for service."""
        parts = []
        if service.get('memory_limit'):
            parts.append(service['memory_limit'])
        if service.get('cpu_limit'):
            parts.append(f"{service['cpu_limit']}cpu")
        return ' / '.join(parts) if parts else '—'
    
    def _route_target(self, route: Dict) -> str:
        """Generate route target summary."""
        target_type = route.get('target_type', '')
        target_value = route.get('target_value', '')
        
        if target_type == 'port':
            return f":{target_value}"
        elif target_type == 'service':
            return f"→{target_value}"
        elif target_type == 'hostname':
            return f"@{target_value}"
        elif target_type == 'url':
            return f"↗{target_value[:30]}"
        return target_value
    
    def _route_scope(self, route: Dict) -> str:
        """Generate route scope display with proxy hostnames."""
        scope = route.get('scope', 'global')
        if scope == 'global':
            return 'global'
        elif scope == 'proxy':
            proxies = route.get('proxy_hostnames', [])
            if not proxies:
                return 'proxy (none)'
            elif len(proxies) == 1:
                return f"{proxies[0]}"
            elif len(proxies) <= 2:
                return f"{proxies[0]}, {proxies[1]}"
            else:
                return f"{proxies[0]} (+{len(proxies)-1})"
        return scope
    
    def _generate_summary(self, data: List[Dict], data_type: str) -> str:
        """Generate summary statistics for data."""
        if data_type == 'proxies':
            https_count = sum(1 for p in data if p.get('enable_https'))
            auth_count = sum(1 for p in data if p.get('auth_enabled'))
            return f"Summary: {len(data)} proxies | {https_count} HTTPS | {auth_count} with auth"
        
        elif data_type == 'services':
            docker_count = sum(1 for s in data if s.get('service_type') == 'docker')
            external_count = sum(1 for s in data if s.get('service_type') == 'external')
            return f"Summary: {docker_count} Docker | {external_count} External"
        
        elif data_type == 'routes':
            global_count = sum(1 for r in data if r.get('scope') == 'global')
            proxy_count = sum(1 for r in data if r.get('scope') == 'proxy')
            return f"Summary: {global_count} global | {proxy_count} proxy-specific"
        
        return ""
    
    def _empty_message(self, data_type: Optional[str]) -> str:
        """Generate empty data message."""
        if data_type == 'tokens':
            return "No tokens found. Create one with: proxy-client token create <name>"
        elif data_type == 'certificates':
            return "No certificates found. Create one with: proxy-client cert create <name> <domain>"
        elif data_type == 'proxies':
            return "No proxies configured. Create one with: proxy-client proxy create <hostname> <target>"
        elif data_type == 'services':
            return "No services running. Create one with: proxy-client service create <name> <image>"
        elif data_type == 'routes':
            return "No routes configured. Create one with: proxy-client route create <path> <type> <target>"
        return "No data to display"
    
    def _default_config(self) -> Dict:
        """Default configuration for unknown data types."""
        return {
            'columns': [],
            'headers': [],
            'styles': [],
            'box': SIMPLE,
        }
    
    def _is_key_value_dict(self, data: Dict) -> bool:
        """Check if dict should be displayed as key-value pairs."""
        # If all values are simple types, treat as key-value
        for value in data.values():
            if isinstance(value, (list, dict)) and value:
                return False
        return True