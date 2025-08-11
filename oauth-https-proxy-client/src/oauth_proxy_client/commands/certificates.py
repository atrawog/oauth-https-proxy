"""Certificate management commands."""

import asyncio
import time
from pathlib import Path
import click
from rich.console import Console
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group('cert')
def cert_group():
    """Manage TLS certificates."""
    pass


@cert_group.command('list')
@click.option('--token', help='Filter by owner token')
@click.pass_obj
def list_certificates(ctx, token):
    """List all certificates."""
    try:
        client = ctx.ensure_client()
        certs = client.get_sync('/api/v1/certificates/')
        
        # Filter by token if specified
        if token:
            token_info = client.get_sync(f'/api/v1/tokens/{token}')
            token_hash = token_info.get('hash')
            certs = [c for c in certs if c.get('owner_token_hash') == token_hash]
        
        ctx.output(certs, title="Certificates", data_type='certificates')
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('create')
@click.argument('name')
@click.argument('domain')
@click.option('--email', envvar='ADMIN_EMAIL', help='ACME account email')
@click.option('--staging/--production', default=False, help='Use ACME staging server')
@click.option('--wait/--no-wait', default=True, help='Wait for certificate generation')
@click.pass_obj
def create_certificate(ctx, name, domain, email, staging, wait):
    """Create a single-domain certificate."""
    try:
        if not email:
            email = ctx.config.admin_email
            if not email:
                click.echo("Email is required. Set ADMIN_EMAIL or use --email")
                return
        
        client = ctx.ensure_client()
        
        data = {
            'cert_name': name,
            'domain': domain,
            'email': email,
        }
        
        if staging:
            data['acme_directory_url'] = ctx.config.acme_staging_url
        
        result = client.post_sync('/api/v1/certificates/', data)
        
        console.print(f"[green]Certificate generation started for {domain}![/green]")
        
        if wait:
            _wait_for_certificate(client, name, ctx)
        else:
            console.print(f"Certificate name: {name}")
            console.print("Check status with: proxy-client cert status " + name)
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('create-multi')
@click.argument('name')
@click.argument('domains', nargs=-1, required=True)
@click.option('--email', envvar='ADMIN_EMAIL', help='ACME account email')
@click.option('--staging/--production', default=False, help='Use ACME staging server')
@click.option('--wait/--no-wait', default=True, help='Wait for certificate generation')
@click.pass_obj
def create_multi_domain(ctx, name, domains, email, staging, wait):
    """Create a multi-domain certificate."""
    try:
        if not email:
            email = ctx.config.admin_email
            if not email:
                click.echo("Email is required. Set ADMIN_EMAIL or use --email")
                return
        
        client = ctx.ensure_client()
        
        # Parse domains (handle comma-separated or space-separated)
        domain_list = []
        for domain in domains:
            if ',' in domain:
                domain_list.extend(d.strip() for d in domain.split(','))
            else:
                domain_list.append(domain.strip())
        
        data = {
            'cert_name': name,
            'domains': domain_list,
            'email': email,
        }
        
        if staging:
            data['acme_directory_url'] = ctx.config.acme_staging_url
        
        result = client.post_sync('/api/v1/certificates/multi-domain', data)
        
        console.print(f"[green]Multi-domain certificate generation started![/green]")
        console.print(f"Domains: {', '.join(domain_list)}")
        
        if wait:
            _wait_for_certificate(client, name, ctx)
        else:
            console.print(f"Certificate name: {name}")
            console.print("Check status with: proxy-client cert status " + name)
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('show')
@click.argument('name')
@click.option('--pem', is_flag=True, help='Show PEM content')
@click.pass_obj
def show_certificate(ctx, name, pem):
    """Show certificate details."""
    try:
        client = ctx.ensure_client()
        cert = client.get_sync(f'/api/v1/certificates/{name}')
        
        if pem:
            # Show raw PEM content
            console.print("[bold]Certificate (PEM):[/bold]")
            console.print(cert.get('fullchain_pem', 'N/A'))
            console.print("\n[bold]Private Key (PEM):[/bold]")
            console.print(cert.get('private_key_pem', 'N/A'))
        else:
            # Hide PEM content for normal display
            display_cert = cert.copy()
            if 'fullchain_pem' in display_cert:
                display_cert['fullchain_pem'] = f"<{len(display_cert['fullchain_pem'])} bytes>"
            if 'private_key_pem' in display_cert:
                display_cert['private_key_pem'] = f"<{len(display_cert['private_key_pem'])} bytes>"
            
            ctx.output(display_cert, title=f"Certificate: {name}")
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('status')
@click.argument('name')
@click.option('--wait/--no-wait', default=False, help='Wait for completion')
@click.pass_obj
def certificate_status(ctx, name, wait):
    """Check certificate generation status."""
    try:
        client = ctx.ensure_client()
        
        if wait:
            _wait_for_certificate(client, name, ctx)
        else:
            status = client.get_sync(f'/api/v1/certificates/{name}/status')
            ctx.output(status, title=f"Certificate Status: {name}")
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('renew')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Force renewal even if not expiring')
@click.option('--wait/--no-wait', default=True, help='Wait for renewal')
@click.pass_obj
def renew_certificate(ctx, name, force, wait):
    """Renew a certificate."""
    try:
        client = ctx.ensure_client()
        
        data = {}
        if force:
            data['force'] = True
        
        result = client.post_sync(f'/api/v1/certificates/{name}/renew', data)
        
        console.print(f"[green]Certificate renewal started for {name}![/green]")
        
        if wait:
            _wait_for_certificate(client, name, ctx)
        else:
            console.print("Check status with: proxy-client cert status " + name)
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('convert-to-production')
@click.argument('name')
@click.option('--wait/--no-wait', default=True, help='Wait for conversion to complete')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def convert_to_production(ctx, name, wait, force):
    """Convert a staging certificate to production."""
    try:
        client = ctx.ensure_client()
        
        # Get certificate details to confirm it's staging
        cert = client.get_sync(f'/api/v1/certificates/{name}')
        if not cert:
            console.print(f"[red]Certificate '{name}' not found[/red]")
            return
        
        # Check if it's a staging certificate
        acme_url = cert.get('acme_directory_url', '')
        if 'staging' not in acme_url.lower():
            console.print(f"[yellow]Certificate '{name}' is already a production certificate[/yellow]")
            return
        
        # Confirm with user
        if not force:
            if not Confirm.ask(f"Convert staging certificate '{name}' to production?", default=False):
                return
        
        # Trigger conversion
        result = client.post_sync(f'/api/v1/certificates/{name}/convert-to-production')
        
        console.print(f"[green]Certificate conversion to production started for {name}![/green]")
        
        if wait:
            _wait_for_certificate(client, name, ctx)
            console.print(f"[green]Certificate '{name}' has been converted to production![/green]")
        else:
            console.print("Check status with: proxy-client cert status " + name)
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('delete')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def delete_certificate(ctx, name, force):
    """Delete a certificate."""
    try:
        if not force:
            if not Confirm.ask(f"Delete certificate '{name}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/certificates/{name}')
        
        console.print(f"[green]Certificate '{name}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('export')
@click.argument('name')
@click.option('--output-dir', '-o', type=click.Path(exists=False, path_type=Path), default='.')
@click.option('--separate/--combined', default=True, help='Export as separate or combined files')
@click.pass_obj
def export_certificate(ctx, name, output_dir, separate):
    """Export certificate to files."""
    try:
        client = ctx.ensure_client()
        cert = client.get_sync(f'/api/v1/certificates/{name}')
        
        # Create output directory
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if separate:
            # Export as separate files
            cert_file = output_dir / f"{name}.crt"
            key_file = output_dir / f"{name}.key"
            
            cert_file.write_text(cert['fullchain_pem'])
            key_file.write_text(cert['private_key_pem'])
            key_file.chmod(0o600)  # Secure private key
            
            console.print(f"[green]Certificate exported to:[/green]")
            console.print(f"  Certificate: {cert_file}")
            console.print(f"  Private key: {key_file}")
        else:
            # Export as combined file
            combined_file = output_dir / f"{name}.pem"
            combined_content = cert['fullchain_pem'] + '\n' + cert['private_key_pem']
            combined_file.write_text(combined_content)
            combined_file.chmod(0o600)  # Secure file
            
            console.print(f"[green]Certificate exported to: {combined_file}[/green]")
    except Exception as e:
        ctx.handle_error(e)


@cert_group.command('to-production')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def convert_to_production(ctx, name, force):
    """Convert staging certificate to production."""
    try:
        if not force:
            if not Confirm.ask(f"Convert '{name}' from staging to production?", default=False):
                return
        
        client = ctx.ensure_client()
        
        # Get current certificate
        cert = client.get_sync(f'/api/v1/certificates/{name}')
        
        # Check if already production
        if 'staging' not in cert.get('acme_directory_url', '').lower():
            console.print(f"[yellow]Certificate '{name}' is already using production ACME.[/yellow]")
            return
        
        # Delete staging cert
        client.delete_sync(f'/api/v1/certificates/{name}')
        
        # Create production cert with same details
        data = {
            'cert_name': cert['cert_name'],
            'domains': cert['domains'],
            'email': cert['email'],
            'acme_directory_url': ctx.config.acme_directory_url,  # Production URL
        }
        
        if len(cert['domains']) == 1:
            data['domain'] = cert['domains'][0]
            result = client.post_sync('/api/v1/certificates/', data)
        else:
            result = client.post_sync('/api/v1/certificates/multi-domain', data)
        
        console.print(f"[green]Production certificate generation started![/green]")
        _wait_for_certificate(client, name, ctx)
    except Exception as e:
        ctx.handle_error(e)


def _wait_for_certificate(client, name, ctx):
    """Wait for certificate generation to complete."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Generating certificate '{name}'...", total=None)
        
        max_attempts = 60
        for attempt in range(max_attempts):
            try:
                status = client.get_sync(f'/api/v1/certificates/{name}/status')
                
                current_status = status.get('status', 'unknown')
                
                # Update progress message based on status
                if current_status == 'pending':
                    progress.update(task, description=f"Generating certificate '{name}'... (pending)")
                elif current_status == 'completed':
                    progress.remove_task(task)
                    console.print(f"[green]Certificate '{name}' generated successfully![/green]")
                    
                    # Show certificate details
                    cert = client.get_sync(f'/api/v1/certificates/{name}')
                    display_cert = {
                        'name': cert['cert_name'],
                        'domains': cert['domains'],
                        'expires_at': cert.get('expires_at'),
                        'status': cert.get('status'),
                    }
                    ctx.output(display_cert)
                    return
                elif current_status == 'failed':
                    progress.remove_task(task)
                    console.print(f"[red]Certificate generation failed: {status.get('error', 'Unknown error')}[/red]")
                    return
                
                time.sleep(2)
            except Exception:
                # Certificate might not exist yet
                time.sleep(2)
        
        progress.remove_task(task)
        console.print(f"[yellow]Certificate generation timed out. Check status with: proxy-client cert status {name}[/yellow]")