"""Token management commands."""

import asyncio
import click
from typing import Optional
from rich.console import Console
from rich.prompt import Confirm

console = Console()


@click.group('token')
def token_group():
    """Manage API tokens."""
    pass


@token_group.command('list')
@click.pass_obj
def list_tokens(ctx):
    """List all tokens."""
    try:
        client = ctx.ensure_client()
        tokens = client.get_sync('/api/v1/tokens/')
        
        # Remove sensitive data from display
        for token in tokens:
            if 'token' in token:
                token['token'] = token['token'][:20] + '...' if len(token['token']) > 20 else token['token']
        
        ctx.output(tokens, title="API Tokens", data_type='tokens')
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('create')
@click.argument('name')
@click.option('--cert-email', help='Email for certificate generation')
@click.pass_obj
def create_token(ctx, name, cert_email):
    """Create a new token."""
    try:
        client = ctx.ensure_client()
        
        data = {'name': name}
        if cert_email:
            data['cert_email'] = cert_email
        
        result = client.post_sync('/api/v1/tokens/', data)
        
        # Show full token on creation
        console.print(f"[green]Token created successfully![/green]")
        console.print(f"Name: {result['name']}")
        console.print(f"Token: [bold yellow]{result['token']}[/bold yellow]")
        console.print("[dim]Save this token - it cannot be retrieved again![/dim]")
        
        if cert_email:
            console.print(f"Certificate email: {cert_email}")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('generate')
@click.argument('name')
@click.option('--cert-email', help='Email for certificate generation')
@click.pass_obj
def generate_token(ctx, name, cert_email):
    """Generate and display a new token."""
    try:
        client = ctx.ensure_client()
        
        data = {'name': name}
        if cert_email:
            data['cert_email'] = cert_email
        
        result = client.post_sync('/api/v1/tokens/generate', data)
        
        # Output in requested format
        if ctx.output_format == 'json':
            ctx.output(result)
        else:
            console.print(f"[green]Token generated successfully![/green]")
            console.print(f"Name: {result['name']}")
            console.print(f"Token: [bold yellow]{result['token']}[/bold yellow]")
            console.print("[dim]Save this token - it cannot be retrieved again![/dim]")
            
            if 'cert_email' in result:
                console.print(f"Certificate email: {result['cert_email']}")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('show')
@click.argument('name')
@click.pass_obj
def show_token(ctx, name):
    """Show token details."""
    try:
        client = ctx.ensure_client()
        token = client.get_sync(f'/api/v1/tokens/{name}')
        
        # Mask token value in details
        if 'token' in token:
            token['token'] = token['token'][:20] + '...' if len(token['token']) > 20 else token['token']
        
        ctx.output(token, title=f"Token: {name}")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('reveal')
@click.argument('name')
@click.option('--confirm/--no-confirm', default=True, help='Confirm before revealing')
@click.pass_obj
def reveal_token(ctx, name, confirm):
    """Reveal full token value."""
    try:
        if confirm:
            if not Confirm.ask(f"Reveal token '{name}'?"):
                return
        
        client = ctx.ensure_client()
        result = client.get_sync(f'/api/v1/tokens/{name}/reveal')
        
        if ctx.output_format == 'json':
            ctx.output(result)
        else:
            console.print(f"[yellow]Token: {name}[/yellow]")
            console.print(f"[bold red]{result['token']}[/bold red]")
            console.print("[dim]Be careful with this token value![/dim]")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('info')
@click.pass_obj
def token_info(ctx):
    """Get current token information."""
    try:
        client = ctx.ensure_client()
        info = client.get_sync('/api/v1/tokens/info')
        ctx.output(info, title="Current Token Info")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('update-email')
@click.argument('email')
@click.pass_obj
def update_token_email(ctx, email):
    """Update certificate email for current token."""
    try:
        client = ctx.ensure_client()
        result = client.put_sync('/api/v1/tokens/email', {'email': email})
        
        console.print(f"[green]Email updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('delete')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def delete_token(ctx, name, force):
    """Delete a token and its owned resources."""
    try:
        if not force:
            if not Confirm.ask(f"Delete token '{name}' and all owned resources?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/tokens/{name}')
        
        console.print(f"[green]Token '{name}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('show-certs')
@click.argument('name', required=False)
@click.pass_obj
def show_token_certs(ctx, name):
    """Show certificates owned by a token."""
    try:
        client = ctx.ensure_client()
        
        # Get token details
        if name:
            token = client.get_sync(f'/api/v1/tokens/{name}')
            token_hash = token.get('hash')
        else:
            # Use current token
            info = client.get_sync('/api/v1/tokens/info')
            token_hash = info.get('hash')
            name = info.get('name', 'current')
        
        # Get all certificates and filter by owner
        certs = client.get_sync('/api/v1/certificates/')
        owned_certs = [c for c in certs if c.get('owner_token_hash') == token_hash]
        
        if owned_certs:
            ctx.output(owned_certs, title=f"Certificates owned by token: {name}")
        else:
            console.print(f"[yellow]No certificates owned by token: {name}[/yellow]")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('list-formatted')
@click.pass_obj
def list_tokens_formatted(ctx):
    """List all tokens in formatted display."""
    try:
        client = ctx.ensure_client()
        formatted = client.get_sync('/api/v1/tokens/formatted')
        
        # Formatted endpoint returns text, not JSON
        console.print(formatted)
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('certificates')
@click.argument('name')
@click.pass_obj
def token_certificates(ctx, name):
    """List certificates owned by a token."""
    try:
        client = ctx.ensure_client()
        certs = client.get_sync(f'/api/v1/tokens/{name}/certificates')
        
        if certs:
            ctx.output(certs, title=f"Certificates owned by token: {name}")
        else:
            console.print(f"[yellow]No certificates owned by token: {name}[/yellow]")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('proxies')
@click.argument('name')
@click.pass_obj
def token_proxies(ctx, name):
    """List proxies owned by a token."""
    try:
        client = ctx.ensure_client()
        proxies = client.get_sync(f'/api/v1/tokens/{name}/proxies')
        
        if proxies:
            ctx.output(proxies, title=f"Proxies owned by token: {name}")
        else:
            console.print(f"[yellow]No proxies owned by token: {name}[/yellow]")
    except Exception as e:
        ctx.handle_error(e)


@token_group.command('create-admin')
@click.option('--name', default='ADMIN', help='Admin token name')
@click.option('--cert-email', help='Email for certificate generation')
@click.pass_obj
def create_admin_token(ctx, name, cert_email):
    """Create an admin token."""
    try:
        client = ctx.ensure_client()
        
        data = {'name': name}
        if cert_email:
            data['cert_email'] = cert_email
        
        result = client.post_sync('/api/v1/tokens/admin', data)
        
        console.print(f"[green]Admin token created successfully![/green]")
        console.print(f"Name: {result['name']}")
        console.print(f"Token: [bold yellow]{result['token']}[/bold yellow]")
        console.print("[dim]Save this admin token - it cannot be retrieved again![/dim]")
        
        if cert_email:
            console.print(f"Certificate email: {cert_email}")
    except Exception as e:
        ctx.handle_error(e)