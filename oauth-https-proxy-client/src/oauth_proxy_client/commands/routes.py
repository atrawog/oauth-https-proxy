"""Route management commands."""

import click
from rich.console import Console
from rich.prompt import Confirm

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
            
            ctx.output(routes, title=f"Routes ({scope})", data_type='routes')
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


@route_group.command('show')
@click.argument('route-id')
@click.pass_obj
def show_route(ctx, route_id):
    """Show detailed route information."""
    try:
        client = ctx.ensure_client()
        route = client.get_sync(f'/api/v1/routes/{route_id}')
        ctx.output(route, title=f"Route: {route_id}")
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('delete')
@click.argument('route-id')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def delete_route(ctx, route_id, force):
    """Delete a routing rule."""
    try:
        if not force:
            if not Confirm.ask(f"Delete route '{route_id}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/routes/{route_id}')
        
        console.print(f"[green]Route '{route_id}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('create-global')
@click.argument('path')
@click.argument('target-type', type=click.Choice(['port', 'service', 'hostname', 'url']))
@click.argument('target-value')
@click.option('--priority', type=int, default=50, help='Route priority (higher = checked first)')
@click.option('--methods', help='Comma-separated HTTP methods')
@click.option('--is-regex', is_flag=True, help='Path is a regex pattern')
@click.option('--description', help='Route description')
@click.pass_obj
def create_global_route(ctx, path, target_type, target_value, priority, methods, is_regex, description):
    """Create a global routing rule that applies to all proxies."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'path_pattern': path,
            'target_type': target_type,
            'target_value': target_value,
            'priority': priority,
            'scope': 'global',
            'enabled': True,
            'is_regex': is_regex,
        }
        
        if methods:
            data['methods'] = methods.upper().split(',')
        else:
            data['methods'] = ['*']
        
        if description:
            data['description'] = description
        
        result = client.post_sync('/api/v1/routes/', data)
        
        console.print(f"[green]Global route created successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('create-proxy')
@click.argument('path')
@click.argument('target-type', type=click.Choice(['port', 'service', 'hostname', 'url']))
@click.argument('target-value')
@click.argument('proxies')  # Comma-separated proxy hostnames
@click.option('--priority', type=int, default=500, help='Route priority (default 500 for proxy-specific)')
@click.option('--methods', help='Comma-separated HTTP methods')
@click.option('--is-regex', is_flag=True, help='Path is a regex pattern')
@click.option('--description', help='Route description')
@click.pass_obj
def create_proxy_route(ctx, path, target_type, target_value, proxies, priority, methods, is_regex, description):
    """Create a proxy-specific routing rule.
    
    PROXIES: Comma-separated list of proxy hostnames to apply this route to.
    """
    try:
        client = ctx.ensure_client()
        
        proxy_list = [p.strip() for p in proxies.split(',')]
        
        data = {
            'path_pattern': path,
            'target_type': target_type,
            'target_value': target_value,
            'priority': priority,
            'scope': 'proxy',
            'proxy_hostnames': proxy_list,
            'enabled': True,
            'is_regex': is_regex,
        }
        
        if methods:
            data['methods'] = methods.upper().split(',')
        else:
            data['methods'] = ['*']
        
        if description:
            data['description'] = description
        
        result = client.post_sync('/api/v1/routes/', data)
        
        console.print(f"[green]Proxy-specific route created for {', '.join(proxy_list)}![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('list-by-scope')
@click.argument('scope', type=click.Choice(['all', 'global', 'proxy']), default='all')
@click.option('--proxy', help='Filter by specific proxy hostname (for proxy scope)')
@click.option('--formatted', is_flag=True, help='Show formatted output')
@click.pass_obj
def list_routes_by_scope(ctx, scope, proxy, formatted):
    """List routes filtered by scope."""
    try:
        client = ctx.ensure_client()
        
        # Get all routes
        if formatted:
            routes = client.get_sync('/api/v1/routes/formatted')
            console.print(routes)
            return
        
        # Use API parameters if available, otherwise filter client-side
        params = {}
        if scope != 'all':
            params['scope'] = scope
        if proxy:
            params['proxy_hostname'] = proxy
        
        try:
            # Try with parameters first
            routes = client.get_sync('/api/v1/routes/', params)
        except Exception:
            # Fall back to client-side filtering
            routes = client.get_sync('/api/v1/routes/')
            
            if scope != 'all':
                routes = [r for r in routes if r.get('scope') == scope]
            
            if proxy and scope == 'proxy':
                routes = [r for r in routes if proxy in r.get('proxy_hostnames', [])]
        
        # Sort by priority (higher first)
        routes = sorted(routes, key=lambda r: r.get('priority', 0), reverse=True)
        
        title = f"Routes ({scope})"
        if proxy:
            title += f" for {proxy}"
        
        ctx.output(routes, title=title)
    except Exception as e:
        ctx.handle_error(e)


@route_group.command('update')
@click.argument('route-id')
@click.option('--priority', type=int, help='Update route priority')
@click.option('--enabled/--disabled', default=None, help='Enable or disable route')
@click.option('--methods', help='Update HTTP methods (comma-separated)')
@click.option('--description', help='Update route description')
@click.pass_obj
def update_route(ctx, route_id, priority, enabled, methods, description):
    """Update an existing route."""
    try:
        client = ctx.ensure_client()
        
        # Get current route
        current = client.get_sync(f'/api/v1/routes/{route_id}')
        
        # Build update data
        data = dict(current)
        
        if priority is not None:
            data['priority'] = priority
        
        if enabled is not None:
            data['enabled'] = enabled
        
        if methods:
            data['methods'] = methods.upper().split(',')
        
        if description is not None:
            data['description'] = description
        
        result = client.put_sync(f'/api/v1/routes/{route_id}', data)
        
        console.print(f"[green]Route '{route_id}' updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


# Additional route commands for missing endpoints

@route_group.command('list-formatted')
@click.pass_obj
def list_routes_formatted(ctx):
    """List all routing rules in formatted display."""
    try:
        client = ctx.ensure_client()
        formatted = client.get_sync('/api/v1/routes/formatted')
        
        # Formatted endpoint returns text, not JSON
        console.print(formatted)
    except Exception as e:
        ctx.handle_error(e)