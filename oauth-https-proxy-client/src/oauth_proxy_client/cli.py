"""Main CLI entry point for OAuth HTTPS Proxy Client."""

import sys
import asyncio
from pathlib import Path
from typing import Optional
import click
from rich.console import Console

from .core.config import Config
from .core.client import ProxyClient
from .core.exceptions import (
    ProxyClientError,
    AuthenticationError,
    ConfigurationError,
)
from .formatters import format_output

# Import command groups
from .commands.tokens import token_group
from .commands.certificates import cert_group
from .commands.proxies import proxy_group
from .commands.routes import route_group
from .commands.services import service_group
from .commands.oauth import oauth_group
from .commands.resources import resource_group
from .commands.logs import log_group
from .commands.system import system_group
from .commands.workflows import workflow_group

# Console for error output
console = Console(stderr=True)


class Context:
    """Click context object for sharing state between commands."""
    
    def __init__(self):
        """Initialize context."""
        self.config: Optional[Config] = None
        self.client: Optional[ProxyClient] = None
        self.output_format: str = 'auto'
        self.debug: bool = False
        self.dry_run: bool = False
    
    def ensure_client(self) -> ProxyClient:
        """Ensure client is initialized.
        
        Returns:
            Initialized ProxyClient
        
        Raises:
            ConfigurationError: If client cannot be initialized
        """
        if not self.client:
            if not self.config:
                raise ConfigurationError("Configuration not initialized")
            self.client = ProxyClient(self.config, dry_run=self.dry_run)
        return self.client
    
    def output(self, data, **kwargs):
        """Output data in configured format.
        
        Args:
            data: Data to output
            **kwargs: Additional formatter options
        """
        try:
            formatted = format_output(data, self.output_format, **kwargs)
            click.echo(formatted)
        except Exception as e:
            if self.debug:
                console.print_exception()
            else:
                console.print(f"[red]Error formatting output: {e}[/red]")
            sys.exit(1)
    
    def handle_error(self, error: Exception):
        """Handle and display errors.
        
        Args:
            error: Exception to handle
        """
        if self.debug:
            console.print_exception()
        else:
            if isinstance(error, AuthenticationError):
                console.print(f"[red]Authentication failed: {error.message}[/red]")
                console.print("[yellow]Check your token with: export ADMIN_TOKEN=your_token[/yellow]")
            elif isinstance(error, ConfigurationError):
                console.print(f"[red]Configuration error: {error.message}[/red]")
            elif isinstance(error, ProxyClientError):
                console.print(f"[red]Error: {error.message}[/red]")
                if error.details:
                    for key, value in error.details.items():
                        console.print(f"  [dim]{key}:[/dim] {value}")
            else:
                console.print(f"[red]Unexpected error: {str(error)}[/red]")
        
        # Set appropriate exit code
        if isinstance(error, AuthenticationError):
            sys.exit(3)
        elif isinstance(error, ConfigurationError):
            sys.exit(2)
        else:
            sys.exit(1)


@click.group()
@click.option(
    '--base-url',
    envvar='API_URL',
    default='http://localhost:80',
    help='API base URL'
)
@click.option(
    '--token',
    envvar=['TOKEN', 'ADMIN_TOKEN'],
    help='Authentication token'
)
@click.option(
    '--format',
    'output_format',
    type=click.Choice(['json', 'table', 'yaml', 'csv', 'auto']),
    default='auto',
    help='Output format'
)
@click.option(
    '--profile',
    default='default',
    help='Configuration profile to use'
)
@click.option(
    '--config',
    'config_file',
    type=click.Path(exists=False, path_type=Path),
    help='Configuration file path'
)
@click.option(
    '--timeout',
    type=int,
    envvar='PROXY_REQUEST_TIMEOUT',
    default=120,
    help='Request timeout in seconds'
)
@click.option(
    '--debug/--no-debug',
    envvar='DEBUG',
    default=False,
    help='Enable debug output'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Show what would be done without making changes'
)
@click.version_option(version='0.1.0', prog_name='oauth-https-proxy-client')
@click.pass_context
def cli(ctx, base_url, token, output_format, profile, config_file, timeout, debug, dry_run):
    """OAuth HTTPS Proxy Client - Manage your proxy infrastructure.
    
    This CLI provides comprehensive management of OAuth HTTPS proxy services,
    including certificates, routing, services, and authentication.
    
    Environment variables:
        API_URL: API endpoint (default: http://localhost:80)
        ADMIN_TOKEN or TOKEN: Authentication token
        LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    
    Examples:
        proxy-client token list
        proxy-client proxy create api.example.com http://backend:8080
        proxy-client cert create my-cert example.com --email admin@example.com
    """
    # Initialize context
    context = Context()
    context.output_format = output_format
    context.debug = debug
    context.dry_run = dry_run
    
    # Show dry-run warning if enabled
    if dry_run:
        console.print("[yellow]DRY RUN MODE - No changes will be made[/yellow]\n")
    
    # Load configuration
    if config_file:
        # Load from specified file
        try:
            context.config = Config.from_file(config_file, profile)
        except Exception as e:
            context.handle_error(ConfigurationError(f"Failed to load config file: {e}"))
    else:
        # Check for default config file
        default_config = Path.home() / '.oauth-proxy-client.yml'
        if default_config.exists():
            try:
                context.config = Config.from_file(default_config, profile)
            except Exception:
                # Silently ignore config file errors and use env
                context.config = Config.from_env()
        else:
            # Load from environment
            context.config = Config.from_env()
    
    # Override with command-line options
    if base_url:
        context.config.api_url = base_url
    if token:
        context.config.token = token
    if timeout:
        context.config.request_timeout = timeout
        context.config.connect_timeout = min(timeout, 30)
    
    # Validate configuration
    warnings = context.config.validate()
    if warnings and debug:
        for warning in warnings:
            console.print(f"[yellow]Warning: {warning}[/yellow]")
    
    # Store context
    ctx.obj = context


# Add command groups
cli.add_command(token_group)
cli.add_command(cert_group)
cli.add_command(proxy_group)
cli.add_command(route_group)
cli.add_command(service_group)
cli.add_command(oauth_group)
cli.add_command(resource_group)
cli.add_command(log_group)
cli.add_command(system_group)
cli.add_command(workflow_group)


def main():
    """Main entry point for the CLI."""
    try:
        # Handle async properly
        if sys.platform == 'win32':
            # Windows requires special event loop policy
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        cli(obj=None)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if '--debug' in sys.argv or '-d' in sys.argv:
            console.print_exception()
        sys.exit(1)


if __name__ == '__main__':
    main()