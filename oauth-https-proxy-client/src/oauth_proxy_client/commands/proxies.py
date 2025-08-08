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