"""System health and management commands."""

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group('system')
def system_group():
    """System health and management."""
    pass


@system_group.command('health')
@click.pass_obj
def health_check(ctx):
    """Check system health status."""
    try:
        client = ctx.ensure_client()
        health = client.health_check_sync()
        
        if health:
            console.print("[green]✓ System is healthy[/green]")
        else:
            console.print("[red]✗ System is not responding[/red]")
            
        # Try to get detailed health info
        try:
            response = client.get_sync('/health')
            ctx.output(response)
        except Exception:
            pass
            
    except Exception as e:
        console.print(f"[red]✗ System is not healthy: {e}[/red]")
        ctx.handle_error(e)


@system_group.command('info')
@click.pass_obj
def system_info(ctx):
    """Show system information."""
    try:
        # Gather system information from various endpoints
        info = {
            'api_url': ctx.config.api_url,
            'authenticated': bool(ctx.config.token),
            'profile': ctx.config.profile,
        }
        
        client = ctx.ensure_client()
        
        # Try to get various system info
        try:
            # Get OAuth server metadata
            metadata = client.get_sync('/.well-known/oauth-authorization-server')
            info['oauth_server'] = {
                'issuer': metadata.get('issuer'),
                'authorization_endpoint': metadata.get('authorization_endpoint'),
                'token_endpoint': metadata.get('token_endpoint'),
            }
        except Exception:
            info['oauth_server'] = 'Not available'
        
        # Get current token info if authenticated
        if ctx.config.token:
            try:
                token_info = client.get_sync('/api/v1/tokens/info')
                info['current_token'] = {
                    'name': token_info.get('name'),
                    'cert_email': token_info.get('cert_email'),
                }
            except Exception:
                info['current_token'] = 'Not available'
        
        ctx.output(info, title="System Information")
    except Exception as e:
        ctx.handle_error(e)


@system_group.command('stats')
@click.pass_obj
def system_stats(ctx):
    """Show system statistics."""
    try:
        client = ctx.ensure_client()
        
        stats = {}
        
        # Get counts from various endpoints
        try:
            tokens = client.get_sync('/api/v1/tokens/')
            stats['tokens'] = len(tokens)
        except Exception:
            stats['tokens'] = 'N/A'
        
        try:
            certs = client.get_sync('/api/v1/certificates/')
            stats['certificates'] = len(certs)
        except Exception:
            stats['certificates'] = 'N/A'
        
        try:
            proxies = client.get_sync('/api/v1/proxy/targets/')
            stats['proxies'] = len(proxies)
        except Exception:
            stats['proxies'] = 'N/A'
        
        try:
            routes = client.get_sync('/api/v1/routes/')
            stats['routes'] = len(routes)
        except Exception:
            stats['routes'] = 'N/A'
        
        try:
            services = client.get_sync('/api/v1/services/')
            stats['docker_services'] = len(services)
        except Exception:
            stats['docker_services'] = 'N/A'
        
        try:
            resources = client.get_sync('/api/v1/resources/')
            stats['mcp_resources'] = len(resources)
        except Exception:
            stats['mcp_resources'] = 'N/A'
        
        # Display as table
        if ctx.output_format == 'table' or ctx.output_format == 'auto':
            table = Table(title="System Statistics")
            table.add_column("Resource", style="cyan")
            table.add_column("Count", style="yellow")
            
            for resource, count in stats.items():
                table.add_row(resource.replace('_', ' ').title(), str(count))
            
            console.print(table)
        else:
            ctx.output(stats)
    except Exception as e:
        ctx.handle_error(e)


@system_group.command('validate')
@click.pass_obj
def validate_config(ctx):
    """Validate system configuration."""
    try:
        console.print("[bold]Validating configuration...[/bold]\n")
        
        # Check configuration
        warnings = ctx.config.validate()
        
        if not warnings:
            console.print("[green]✓ Configuration is valid[/green]")
        else:
            console.print("[yellow]Configuration warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  [yellow]⚠ {warning}[/yellow]")
        
        # Test connectivity
        console.print("\n[bold]Testing connectivity...[/bold]")
        
        client = ctx.ensure_client()
        
        # Test health endpoint
        if client.health_check_sync():
            console.print(f"[green]✓ Connected to {ctx.config.api_url}[/green]")
        else:
            console.print(f"[red]✗ Cannot connect to {ctx.config.api_url}[/red]")
            return
        
        # Test authentication
        if ctx.config.token:
            try:
                token_info = client.get_sync('/api/v1/tokens/info')
                console.print(f"[green]✓ Authenticated as: {token_info.get('name', 'unknown')}[/green]")
            except Exception as e:
                console.print(f"[red]✗ Authentication failed: {e}[/red]")
        else:
            console.print("[yellow]⚠ No authentication token configured[/yellow]")
        
        console.print("\n[green]Validation complete![/green]")
    except Exception as e:
        ctx.handle_error(e)


@system_group.command('version')
@click.pass_obj
def show_version(ctx):
    """Show client and server versions."""
    try:
        from .. import __version__
        
        console.print(f"[bold]Client Version:[/bold] {__version__}")
        
        # Try to get server version
        client = ctx.ensure_client()
        try:
            # Server might have version endpoint
            server_info = client.get_sync('/version')
            console.print(f"[bold]Server Version:[/bold] {server_info.get('version', 'Unknown')}")
        except Exception:
            # Try from health endpoint
            try:
                health = client.get_sync('/health')
                if 'version' in health:
                    console.print(f"[bold]Server Version:[/bold] {health['version']}")
                else:
                    console.print("[dim]Server version not available[/dim]")
            except Exception:
                console.print("[dim]Server version not available[/dim]")
    except Exception as e:
        ctx.handle_error(e)