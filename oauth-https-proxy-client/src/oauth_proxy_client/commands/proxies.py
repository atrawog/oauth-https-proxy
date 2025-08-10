"""Proxy management commands."""

import click
from rich.console import Console
from rich.prompt import Confirm

console = Console()


@click.group('proxy')
def proxy_group():
    """Manage proxy targets."""
    pass


@proxy_group.command('list')
@click.pass_obj
def list_proxies(ctx):
    """List all proxy targets."""
    try:
        client = ctx.ensure_client()
        proxies = client.get_sync('/api/v1/proxy/targets/')
        ctx.output(proxies, title="Proxy Targets")
    except Exception as e:
        ctx.handle_error(e)


@proxy_group.command('create')
@click.argument('hostname')
@click.argument('target-url')
@click.option('--cert-name', help='Certificate to use')
@click.option('--email', envvar='ADMIN_EMAIL', help='Email for auto-generated certificate')
@click.option('--staging/--production', default=False, help='Use staging certificates')
@click.option('--preserve-host/--no-preserve-host', default=True, help='Preserve host header')
@click.option('--enable-http/--no-enable-http', default=True, help='Enable HTTP')
@click.option('--enable-https/--no-enable-https', default=True, help='Enable HTTPS')
@click.pass_obj
def create_proxy(ctx, hostname, target_url, cert_name, email, staging, preserve_host, enable_http, enable_https):
    """Create a new proxy target."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'hostname': hostname,
            'target_url': target_url,
            'preserve_host_header': preserve_host,
            'enable_http': enable_http,
            'enable_https': enable_https,
        }
        
        if cert_name:
            data['cert_name'] = cert_name
        
        result = client.post_sync('/api/v1/proxy/targets/', data)
        
        console.print(f"[green]Proxy created successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@proxy_group.command('show')
@click.argument('hostname')
@click.pass_obj
def show_proxy(ctx, hostname):
    """Show proxy details."""
    try:
        client = ctx.ensure_client()
        proxy = client.get_sync(f'/api/v1/proxy/targets/{hostname}')
        ctx.output(proxy, title=f"Proxy: {hostname}")
    except Exception as e:
        ctx.handle_error(e)


@proxy_group.command('delete')
@click.argument('hostname')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.option('--delete-cert', is_flag=True, help='Also delete associated certificate')
@click.pass_obj
def delete_proxy(ctx, hostname, force, delete_cert):
    """Delete a proxy target."""
    try:
        if not force:
            if not Confirm.ask(f"Delete proxy '{hostname}'?", default=False):
                return
        
        client = ctx.ensure_client()
        
        params = {}
        if delete_cert:
            params['delete_cert'] = 'true'
        
        client.delete_sync(f'/api/v1/proxy/targets/{hostname}')
        
        console.print(f"[green]Proxy '{hostname}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


# Auth subcommands
@proxy_group.group('auth')
def proxy_auth():
    """Manage proxy authentication."""
    pass


@proxy_auth.command('enable')
@click.argument('hostname')
@click.argument('auth-proxy')
@click.argument('mode', type=click.Choice(['forward', 'redirect', 'passthrough']))
@click.option('--users', help='Comma-separated list of allowed users')
@click.option('--scopes', help='Comma-separated list of allowed scopes')
@click.pass_obj
def enable_auth(ctx, hostname, auth_proxy, mode, users, scopes):
    """Enable OAuth authentication for a proxy."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'auth_enabled': True,
            'auth_proxy': auth_proxy,
            'auth_mode': mode,
        }
        
        if users:
            data['auth_required_users'] = users.split(',')
        if scopes:
            data['auth_allowed_scopes'] = scopes.split(',')
        
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/auth', data)
        
        console.print(f"[green]Authentication enabled for {hostname}![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@proxy_auth.command('disable')
@click.argument('hostname')
@click.pass_obj
def disable_auth(ctx, hostname):
    """Disable OAuth authentication for a proxy."""
    try:
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/proxy/targets/{hostname}/auth')
        
        console.print(f"[green]Authentication disabled for {hostname}![/green]")
    except Exception as e:
        ctx.handle_error(e)


@proxy_auth.command('config')
@click.argument('hostname')
@click.option('--users', help='Comma-separated list of allowed users (* for all)')
@click.option('--emails', help='Comma-separated list of allowed emails')
@click.option('--groups', help='Comma-separated list of allowed groups')
@click.option('--scopes', help='Comma-separated list of allowed scopes')
@click.option('--audiences', help='Comma-separated list of allowed audiences')
@click.pass_obj
def config_auth(ctx, hostname, users, emails, groups, scopes, audiences):
    """Update authentication configuration for a proxy."""
    try:
        client = ctx.ensure_client()
        
        # Get current auth configuration first
        current_config = client.get_sync(f'/api/v1/proxy/targets/{hostname}/auth')
        
        # Build update payload with current config as base
        data = {
            'auth_enabled': current_config.get('auth_enabled', True),
            'auth_proxy': current_config.get('auth_proxy'),
            'auth_mode': current_config.get('auth_mode', 'forward'),
            'auth_pass_headers': current_config.get('auth_pass_headers', True),
            'auth_cookie_name': current_config.get('auth_cookie_name', 'unified_auth_token'),
            'auth_header_prefix': current_config.get('auth_header_prefix', 'X-Auth-'),
            'auth_excluded_paths': current_config.get('auth_excluded_paths'),
        }
        
        # Add optional fields if provided
        if users is not None:
            if users == '*':
                data['auth_required_users'] = ['*']
            elif users:
                data['auth_required_users'] = [u.strip() for u in users.split(',')]
            else:
                data['auth_required_users'] = None
                
        if emails:
            data['auth_required_emails'] = [e.strip() for e in emails.split(',')]
            
        if groups:
            data['auth_required_groups'] = [g.strip() for g in groups.split(',')]
            
        if scopes:
            data['auth_allowed_scopes'] = [s.strip() for s in scopes.split(',')]
            
        if audiences:
            data['auth_allowed_audiences'] = [a.strip() for a in audiences.split(',')]
        
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/auth', data)
        
        console.print(f"[green]Authentication configuration updated for {hostname}![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@proxy_auth.command('show')
@click.argument('hostname')
@click.pass_obj
def show_auth(ctx, hostname):
    """Show authentication configuration for a proxy."""
    try:
        client = ctx.ensure_client()
        auth_config = client.get_sync(f'/api/v1/proxy/targets/{hostname}/auth')
        ctx.output(auth_config, title=f"Authentication Config: {hostname}")
    except Exception as e:
        ctx.handle_error(e)


# Resource (MCP) subcommands
@proxy_group.group('resource')
def proxy_resource():
    """Manage protected resource metadata."""
    pass


@proxy_resource.command('set')
@click.argument('hostname')
@click.option('--endpoint', default='/mcp', help='MCP endpoint path')
@click.option('--scopes', default='mcp:read,mcp:write', help='Comma-separated list of scopes')
@click.option('--stateful/--stateless', default=False, help='Whether server maintains session state')
@click.option('--override-backend/--no-override-backend', default=False, help='Override backend metadata endpoint')
@click.option('--bearer-methods', default='header', help='Bearer token methods (header,query,body)')
@click.option('--doc-suffix', default='/docs', help='Documentation URL suffix')
@click.option('--server-info', default='{}', help='Server info as JSON')
@click.option('--custom-metadata', default='{}', help='Custom metadata as JSON')
@click.pass_obj
def set_resource(ctx, hostname, endpoint, scopes, stateful, override_backend, bearer_methods, doc_suffix, server_info, custom_metadata):
    """Configure protected resource metadata for a proxy."""
    try:
        import json
        client = ctx.ensure_client()
        
        data = {
            'resource_endpoint': endpoint,
            'resource_scopes': [s.strip() for s in scopes.split(',')],
            'resource_stateful': stateful,
            'resource_override_backend': override_backend,
            'resource_bearer_methods': [m.strip() for m in bearer_methods.split(',')],
            'resource_documentation_suffix': doc_suffix,
        }
        
        # Parse JSON fields
        try:
            data['resource_server_info'] = json.loads(server_info) if server_info != '{}' else {}
        except json.JSONDecodeError:
            console.print(f"[red]Invalid JSON for server-info: {server_info}[/red]")
            return
            
        try:
            data['resource_custom_metadata'] = json.loads(custom_metadata) if custom_metadata != '{}' else {}
        except json.JSONDecodeError:
            console.print(f"[red]Invalid JSON for custom-metadata: {custom_metadata}[/red]")
            return
        
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/mcp', data)
        
        console.print(f"[green]Protected resource metadata configured for {hostname}![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@proxy_resource.command('show')
@click.argument('hostname')
@click.pass_obj
def show_resource(ctx, hostname):
    """Show protected resource metadata for a proxy."""
    try:
        client = ctx.ensure_client()
        resource_config = client.get_sync(f'/api/v1/proxy/targets/{hostname}/mcp')
        ctx.output(resource_config, title=f"Protected Resource Config: {hostname}")
    except Exception as e:
        ctx.handle_error(e)


@proxy_resource.command('clear')
@click.argument('hostname')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def clear_resource(ctx, hostname, force):
    """Remove protected resource metadata from a proxy."""
    try:
        if not force:
            if not Confirm.ask(f"Clear protected resource metadata for '{hostname}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/proxy/targets/{hostname}/mcp')
        
        console.print(f"[green]Protected resource metadata cleared for {hostname}![/green]")
    except Exception as e:
        ctx.handle_error(e)


@proxy_resource.command('list')
@click.pass_obj
def list_resources(ctx):
    """List all protected resources."""
    try:
        client = ctx.ensure_client()
        resources = client.get_sync('/api/v1/resources/')
        ctx.output(resources, title="Protected Resources")
    except Exception as e:
        ctx.handle_error(e)