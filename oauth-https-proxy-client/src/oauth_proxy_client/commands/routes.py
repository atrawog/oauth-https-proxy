"""Route management commands."""

import click
from rich.console import Console

console = Console()


@click.group('route')
def route_group():
    """Manage routing rules."""
    pass


@route_group.command('list')
@click.option('--scope', type=click.Choice(['all', 'global', 'proxy']), default='all')
@click.option('--formatted', is_flag=True, help='Show formatted output')
@click.pass_obj
def list_routes(ctx, scope, formatted):
    """List all routing rules."""
    try:
        client = ctx.ensure_client()
        
        if formatted:
            routes = client.get_sync('/api/v1/routes/formatted')
            # Formatted endpoint returns text, not JSON
            console.print(routes)
        else:
            routes = client.get_sync('/api/v1/routes/')
            
            # Filter by scope if specified
            if scope != 'all':
                routes = [r for r in routes if r.get('scope') == scope]
            
            ctx.output(routes, title=f"Routes ({scope})")
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('create')
@click.argument('path')
@click.argument('target-type', type=click.Choice(['port', 'service', 'hostname', 'url']))
@click.argument('target-value')
@click.option('--priority', type=int, default=50, help='Route priority (higher = checked first)')
@click.option('--methods', help='Comma-separated HTTP methods')
@click.option('--scope', type=click.Choice(['global', 'proxy']), default='global')
@click.option('--proxies', help='Comma-separated proxy hostnames (for proxy scope)')
@click.pass_obj
def create_route(ctx, path, target_type, target_value, priority, methods, scope, proxies):
    """Create a new routing rule."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'path_pattern': path,
            'target_type': target_type,
            'target_value': target_value,
            'priority': priority,
            'scope': scope,
            'enabled': True,
        }
        
        if methods:
            data['methods'] = methods.upper().split(',')
        
        if scope == 'proxy' and proxies:
            data['proxy_hostnames'] = proxies.split(',')
        
        result = client.post_sync('/api/v1/routes/', data)
        
        console.print(f"[green]Route created successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('delete')
@click.argument('route-id')
@click.pass_obj
def delete_route(ctx, route_id):
    """Delete a routing rule."""
    try:
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/routes/{route_id}')
        
        console.print(f"[green]Route '{route_id}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)