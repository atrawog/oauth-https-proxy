"""OAuth administration commands."""

import click
from rich.console import Console
from rich.prompt import Confirm

console = Console()


@click.group('oauth')
def oauth_group():
    """OAuth administration and management."""
    pass


# Client management
@oauth_group.group('client')
def oauth_client():
    """Manage OAuth clients."""
    pass


@oauth_client.command('list')
@click.option('--active-only', is_flag=True, help='Show only active clients')
@click.pass_obj
def list_clients(ctx, active_only):
    """List OAuth clients."""
    try:
        client = ctx.ensure_client()
        
        params = {}
        if active_only:
            params['active_only'] = 'true'
        
        clients = client.get_sync('/api/v1/oauth/clients', params)
        ctx.output(clients, title="OAuth Clients")
    except Exception as e:
        ctx.handle_error(e)


@oauth_client.command('show')
@click.argument('client-id')
@click.pass_obj
def show_client(ctx, client_id):
    """Show OAuth client details."""
    try:
        client = ctx.ensure_client()
        oauth_client = client.get_sync(f'/api/v1/oauth/clients/{client_id}')
        ctx.output(oauth_client, title=f"OAuth Client: {client_id}")
    except Exception as e:
        ctx.handle_error(e)


# Session management
@oauth_group.group('session')
def oauth_session():
    """Manage OAuth sessions."""
    pass


@oauth_session.command('list')
@click.pass_obj
def list_sessions(ctx):
    """List active OAuth sessions."""
    try:
        client = ctx.ensure_client()
        sessions = client.get_sync('/api/v1/oauth/sessions')
        ctx.output(sessions, title="Active OAuth Sessions")
    except Exception as e:
        ctx.handle_error(e)


@oauth_session.command('revoke')
@click.argument('session-id')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def revoke_session(ctx, session_id, force):
    """Revoke an OAuth session."""
    try:
        if not force:
            if not Confirm.ask(f"Revoke session '{session_id}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/oauth/sessions/{session_id}')
        
        console.print(f"[green]Session '{session_id}' revoked successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


# Metrics and health
@oauth_group.command('metrics')
@click.pass_obj
def oauth_metrics(ctx):
    """Show OAuth system metrics."""
    try:
        client = ctx.ensure_client()
        metrics = client.get_sync('/api/v1/oauth/metrics')
        ctx.output(metrics, title="OAuth Metrics")
    except Exception as e:
        ctx.handle_error(e)


@oauth_group.command('health')
@click.pass_obj
def oauth_health(ctx):
    """Check OAuth integration health."""
    try:
        client = ctx.ensure_client()
        health = client.get_sync('/api/v1/oauth/health')
        
        if ctx.output_format == 'json':
            ctx.output(health)
        else:
            # Format health status nicely
            status = health.get('status', 'unknown')
            if status == 'healthy':
                console.print("[green]✓ OAuth system is healthy[/green]")
            else:
                console.print(f"[red]✗ OAuth system status: {status}[/red]")
            
            if health.get('github_connected'):
                console.print("[green]✓ GitHub OAuth connected[/green]")
            else:
                console.print("[yellow]⚠ GitHub OAuth not configured[/yellow]")
            
            if health.get('jwks_available'):
                console.print("[green]✓ JWKS endpoint available[/green]")
            else:
                console.print("[red]✗ JWKS endpoint not available[/red]")
    except Exception as e:
        ctx.handle_error(e)


# Token operations
@oauth_group.command('register')
@click.argument('name')
@click.option('--redirect-uri', default='urn:ietf:wg:oauth:2.0:oob', help='OAuth redirect URI')
@click.option('--scope', default='mcp:read mcp:write', help='OAuth scopes')
@click.pass_obj
def register_client(ctx, name, redirect_uri, scope):
    """Register a new OAuth client."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'software_id': f'oauth-proxy-client-{name}',
            'software_version': '1.0.0',
            'client_name': name,
            'redirect_uris': [redirect_uri],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': scope,
        }
        
        result = client.post_sync('/register', data)
        
        console.print(f"[green]OAuth client registered successfully![/green]")
        console.print(f"Client ID: [bold yellow]{result['client_id']}[/bold yellow]")
        console.print(f"Client Secret: [bold yellow]{result['client_secret']}[/bold yellow]")
        console.print("[dim]Save these credentials - they cannot be retrieved again![/dim]")
        
        if 'registration_access_token' in result:
            console.print(f"Registration Token: {result['registration_access_token']}")
        if 'registration_client_uri' in result:
            console.print(f"Management URI: {result['registration_client_uri']}")
    except Exception as e:
        ctx.handle_error(e)