"""Protected resource management commands."""

import click
from rich.console import Console

console = Console()


@click.group('resource')
def resource_group():
    """Manage protected resources."""
    pass


@resource_group.command('list')
@click.pass_obj
def list_resources(ctx):
    """List all protected resources."""
    try:
        client = ctx.ensure_client()
        resources = client.get_sync('/api/v1/resources/')
        ctx.output(resources, title="Protected Resources")
    except Exception as e:
        ctx.handle_error(e)


@resource_group.command('register')
@click.argument('uri')
@click.argument('proxy-hostname')
@click.argument('name')
@click.option('--scopes', default='mcp:read,mcp:write', help='Comma-separated scopes')
@click.pass_obj
def register_resource(ctx, uri, proxy_hostname, name, scopes):
    """Register a new protected resource."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'uri': uri,
            'name': name,
            'proxy_target': proxy_hostname,
            'scopes': scopes.split(','),
        }
        
        result = client.post_sync('/api/v1/resources/', data)
        
        console.print(f"[green]Protected resource registered successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@resource_group.command('show')
@click.argument('uri')
@click.pass_obj
def show_resource(ctx, uri):
    """Show protected resource details."""
    try:
        client = ctx.ensure_client()
        
        # URL encode the URI
        from urllib.parse import quote
        encoded_uri = quote(uri, safe='')
        
        resource = client.get_sync(f'/api/v1/resources/{encoded_uri}')
        ctx.output(resource, title=f"Protected Resource: {uri}")
    except Exception as e:
        ctx.handle_error(e)


@resource_group.command('validate-token')
@click.argument('uri')
@click.argument('token')
@click.pass_obj
def validate_token(ctx, uri, token):
    """Validate a token for a specific resource."""
    try:
        client = ctx.ensure_client()
        
        from urllib.parse import quote
        encoded_uri = quote(uri, safe='')
        
        data = {'token': token}
        result = client.post_sync(f'/api/v1/resources/{encoded_uri}/validate-token', data)
        
        if result.get('valid'):
            console.print(f"[green]✓ Token is valid for resource: {uri}[/green]")
        else:
            console.print(f"[red]✗ Token is invalid for resource: {uri}[/red]")
        
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@resource_group.command('auto-register')
@click.pass_obj
def auto_register_resources(ctx):
    """Auto-discover and register protected resources from proxy configurations."""
    try:
        client = ctx.ensure_client()
        result = client.post_sync('/api/v1/resources/auto-register')
        
        console.print(f"[green]Auto-registration complete![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@resource_group.command('update')
@click.argument('uri')
@click.option('--name', help='Resource name')
@click.option('--proxy-target', help='Proxy hostname')
@click.option('--scopes', help='Comma-separated scopes')
@click.option('--metadata-url', help='Metadata URL')
@click.pass_obj
def update_resource(ctx, uri, name, proxy_target, scopes, metadata_url):
    """Update protected resource configuration."""
    try:
        client = ctx.ensure_client()
        
        from urllib.parse import quote
        encoded_uri = quote(uri, safe='')
        
        # Get current configuration
        current = client.get_sync(f'/api/v1/resources/{encoded_uri}')
        
        # Build update data
        data = dict(current)
        
        if name:
            data['name'] = name
        if proxy_target:
            data['proxy_target'] = proxy_target
        if scopes:
            data['scopes'] = scopes.split(',')
        if metadata_url:
            data['metadata_url'] = metadata_url
        
        result = client.put_sync(f'/api/v1/resources/{encoded_uri}', data)
        
        console.print(f"[green]Protected resource '{uri}' updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@resource_group.command('delete')
@click.argument('uri')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def delete_resource(ctx, uri, force):
    """Delete a protected resource."""
    try:
        from rich.prompt import Confirm
        
        if not force:
            if not Confirm.ask(f"Delete protected resource '{uri}'?", default=False):
                return
        
        client = ctx.ensure_client()
        
        from urllib.parse import quote
        encoded_uri = quote(uri, safe='')
        
        client.delete_sync(f'/api/v1/resources/{encoded_uri}')
        
        console.print(f"[green]Protected resource '{uri}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)