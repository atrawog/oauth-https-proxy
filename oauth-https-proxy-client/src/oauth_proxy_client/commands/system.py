"""System health and management commands."""

import json
from pathlib import Path
from datetime import datetime

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm

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


# Configuration management subcommands
@system_group.group('config')
def config_group():
    """Configuration backup and restore."""
    pass


@config_group.command('export')
@click.option('--output', '-o', type=click.Path(dir_okay=False, path_type=Path), 
              help='Output file path (default: config-export-TIMESTAMP.yaml)')
@click.option('--include-tokens/--no-include-tokens', default=False, 
              help='Include tokens in export (security sensitive)')
@click.option('--include-secrets/--no-include-secrets', default=False,
              help='Include secrets like private keys (security sensitive)')
@click.pass_obj
def export_config(ctx, output, include_tokens, include_secrets):
    """Export full system configuration to YAML file."""
    try:
        client = ctx.ensure_client()
        
        # Generate default filename if not provided
        if not output:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            output = Path(f'config-export-{timestamp}.yaml')
        
        config = {
            'version': '1.0',
            'metadata': {
                'exported_at': datetime.now().isoformat(),
                'exported_by': ctx.config.token[:20] + '...' if ctx.config.token else 'anonymous',
                'api_url': ctx.config.api_url,
            },
            'tokens': [],
            'certificates': [],
            'services': {
                'docker': [],
                'external': []
            },
            'proxies': [],
            'routes': [],
            'resources': [],
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Export tokens
            if include_tokens:
                task = progress.add_task("Exporting tokens...", total=None)
                try:
                    tokens = client.get_sync('/api/v1/tokens/')
                    for token in tokens:
                        token_data = {
                            'name': token.get('name'),
                            'cert_email': token.get('cert_email'),
                        }
                        if include_secrets:
                            # Try to reveal the actual token
                            try:
                                revealed = client.get_sync(f'/api/v1/tokens/{token["name"]}/reveal')
                                token_data['token'] = revealed.get('token')
                            except Exception:
                                pass
                        config['tokens'].append(token_data)
                    progress.update(task, description=f"Exported {len(tokens)} tokens")
                except Exception as e:
                    progress.update(task, description=f"[yellow]Failed to export tokens: {e}[/yellow]")
            
            # Export certificates
            task = progress.add_task("Exporting certificates...", total=None)
            try:
                certs = client.get_sync('/api/v1/certificates/')
                for cert in certs:
                    cert_data = {
                        'cert_name': cert.get('cert_name'),
                        'domains': cert.get('domains'),
                        'email': cert.get('email'),
                        'acme_directory_url': cert.get('acme_directory_url'),
                        'expires_at': cert.get('expires_at'),
                    }
                    if include_secrets:
                        cert_data['fullchain_pem'] = cert.get('fullchain_pem')
                        cert_data['private_key_pem'] = cert.get('private_key_pem')
                    config['certificates'].append(cert_data)
                progress.update(task, description=f"Exported {len(certs)} certificates")
            except Exception as e:
                progress.update(task, description=f"[yellow]Failed to export certificates: {e}[/yellow]")
            
            # Export Docker services
            task = progress.add_task("Exporting Docker services...", total=None)
            try:
                services = client.get_sync('/api/v1/services/')
                config['services']['docker'] = services
                progress.update(task, description=f"Exported {len(services)} Docker services")
            except Exception as e:
                progress.update(task, description=f"[yellow]Failed to export Docker services: {e}[/yellow]")
            
            # Export external services
            task = progress.add_task("Exporting external services...", total=None)
            try:
                external = client.get_sync('/api/v1/services/external')
                config['services']['external'] = external
                progress.update(task, description=f"Exported {len(external)} external services")
            except Exception as e:
                progress.update(task, description=f"[yellow]Failed to export external services: {e}[/yellow]")
            
            # Export proxies
            task = progress.add_task("Exporting proxies...", total=None)
            try:
                proxies = client.get_sync('/api/v1/proxy/targets/')
                for proxy in proxies:
                    # Get auth config if exists
                    try:
                        auth_config = client.get_sync(f'/api/v1/proxy/targets/{proxy["hostname"]}/auth')
                        proxy['auth'] = auth_config
                    except Exception:
                        pass
                    
                    # Get MCP config if exists
                    try:
                        mcp_config = client.get_sync(f'/api/v1/proxy/targets/{proxy["hostname"]}/mcp')
                        proxy['mcp'] = mcp_config
                    except Exception:
                        pass
                        
                config['proxies'] = proxies
                progress.update(task, description=f"Exported {len(proxies)} proxies")
            except Exception as e:
                progress.update(task, description=f"[yellow]Failed to export proxies: {e}[/yellow]")
            
            # Export routes
            task = progress.add_task("Exporting routes...", total=None)
            try:
                routes = client.get_sync('/api/v1/routes/')
                config['routes'] = routes
                progress.update(task, description=f"Exported {len(routes)} routes")
            except Exception as e:
                progress.update(task, description=f"[yellow]Failed to export routes: {e}[/yellow]")
            
            # Export resources
            task = progress.add_task("Exporting protected resources...", total=None)
            try:
                resources = client.get_sync('/api/v1/resources/')
                config['resources'] = resources
                progress.update(task, description=f"Exported {len(resources)} resources")
            except Exception as e:
                progress.update(task, description=f"[yellow]Failed to export resources: {e}[/yellow]")
        
        # Write to file
        with open(output, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        console.print(f"\n[green]✓ Configuration exported to {output}[/green]")
        
        # Show summary
        console.print("\n[bold]Export Summary:[/bold]")
        console.print(f"  Tokens: {len(config['tokens'])}")
        console.print(f"  Certificates: {len(config['certificates'])}")
        console.print(f"  Docker Services: {len(config['services']['docker'])}")
        console.print(f"  External Services: {len(config['services']['external'])}")
        console.print(f"  Proxies: {len(config['proxies'])}")
        console.print(f"  Routes: {len(config['routes'])}")
        console.print(f"  Protected Resources: {len(config['resources'])}")
        
    except Exception as e:
        ctx.handle_error(e)


@config_group.command('import')
@click.argument('config-file', type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option('--force', '-f', is_flag=True, help='Skip confirmation prompts')
@click.option('--dry-run', is_flag=True, help='Show what would be imported without applying')
@click.option('--skip-existing', is_flag=True, help='Skip resources that already exist')
@click.pass_obj
def import_config(ctx, config_file, force, dry_run, skip_existing):
    """Import configuration from YAML file."""
    try:
        # Load configuration file
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate version
        if config.get('version') != '1.0':
            console.print(f"[red]Unsupported config version: {config.get('version')}[/red]")
            return
        
        # Show what will be imported
        console.print("[bold]Configuration to import:[/bold]")
        console.print(f"  From: {config['metadata']['exported_at']}")
        console.print(f"  Tokens: {len(config.get('tokens', []))}")
        console.print(f"  Certificates: {len(config.get('certificates', []))}")
        console.print(f"  Docker Services: {len(config.get('services', {}).get('docker', []))}")
        console.print(f"  External Services: {len(config.get('services', {}).get('external', []))}")
        console.print(f"  Proxies: {len(config.get('proxies', []))}")
        console.print(f"  Routes: {len(config.get('routes', []))}")
        console.print(f"  Protected Resources: {len(config.get('resources', []))}")
        
        if dry_run:
            console.print("\n[yellow]DRY RUN MODE - No changes will be made[/yellow]")
        
        if not force and not dry_run:
            if not Confirm.ask("\nProceed with import?", default=False):
                return
        
        client = ctx.ensure_client()
        stats = {'success': 0, 'skipped': 0, 'failed': 0}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Import tokens
            if config.get('tokens'):
                task = progress.add_task("Importing tokens...", total=None)
                for token_data in config['tokens']:
                    try:
                        if dry_run:
                            console.print(f"  [dim]Would create token: {token_data['name']}[/dim]")
                        else:
                            # Check if exists
                            if skip_existing:
                                try:
                                    existing = client.get_sync(f"/api/v1/tokens/{token_data['name']}")
                                    if existing:
                                        stats['skipped'] += 1
                                        continue
                                except Exception:
                                    pass
                            
                            # Create token
                            create_data = {
                                'name': token_data['name'],
                                'cert_email': token_data.get('cert_email'),
                            }
                            if 'token' in token_data:
                                create_data['token'] = token_data['token']
                            
                            client.post_sync('/api/v1/tokens/', create_data)
                            stats['success'] += 1
                    except Exception as e:
                        stats['failed'] += 1
                        if not skip_existing:
                            console.print(f"  [red]Failed to import token {token_data['name']}: {e}[/red]")
                progress.update(task, description=f"Imported {stats['success']} tokens")
            
            # Import external services first (no dependencies)
            if config.get('services', {}).get('external'):
                task = progress.add_task("Importing external services...", total=None)
                for service in config['services']['external']:
                    try:
                        if dry_run:
                            console.print(f"  [dim]Would register external service: {service['service_name']}[/dim]")
                        else:
                            client.post_sync('/api/v1/services/external', service)
                            stats['success'] += 1
                    except Exception as e:
                        stats['failed'] += 1
                        if not skip_existing:
                            console.print(f"  [red]Failed to import external service {service['service_name']}: {e}[/red]")
                progress.update(task, description="Imported external services")
            
            # Import Docker services
            if config.get('services', {}).get('docker'):
                task = progress.add_task("Importing Docker services...", total=None)
                for service in config['services']['docker']:
                    try:
                        if dry_run:
                            console.print(f"  [dim]Would create Docker service: {service['service_name']}[/dim]")
                        else:
                            client.post_sync('/api/v1/services/', service)
                            stats['success'] += 1
                    except Exception as e:
                        stats['failed'] += 1
                        if not skip_existing:
                            console.print(f"  [red]Failed to import Docker service {service['service_name']}: {e}[/red]")
                progress.update(task, description="Imported Docker services")
            
            # Import certificates
            if config.get('certificates'):
                task = progress.add_task("Importing certificates...", total=None)
                for cert in config['certificates']:
                    try:
                        if dry_run:
                            console.print(f"  [dim]Would create certificate: {cert['cert_name']}[/dim]")
                        else:
                            # If we have the actual cert data, use it
                            if 'fullchain_pem' in cert and 'private_key_pem' in cert:
                                # Direct import (would need API support)
                                console.print(f"  [yellow]Certificate {cert['cert_name']} contains PEM data - manual import may be needed[/yellow]")
                            else:
                                # Request new certificate
                                cert_data = {
                                    'cert_name': cert['cert_name'],
                                    'domains': cert['domains'],
                                    'email': cert.get('email'),
                                }
                                client.post_sync('/api/v1/certificates/', cert_data)
                                stats['success'] += 1
                    except Exception as e:
                        stats['failed'] += 1
                        if not skip_existing:
                            console.print(f"  [red]Failed to import certificate {cert['cert_name']}: {e}[/red]")
                progress.update(task, description="Imported certificates")
            
            # Import proxies
            if config.get('proxies'):
                task = progress.add_task("Importing proxies...", total=None)
                for proxy in config['proxies']:
                    try:
                        if dry_run:
                            console.print(f"  [dim]Would create proxy: {proxy['hostname']}[/dim]")
                        else:
                            # Create proxy
                            proxy_data = {k: v for k, v in proxy.items() if k not in ['auth', 'mcp']}
                            client.post_sync('/api/v1/proxy/targets/', proxy_data)
                            
                            # Configure auth if present
                            if proxy.get('auth'):
                                client.post_sync(f'/api/v1/proxy/targets/{proxy["hostname"]}/auth', proxy['auth'])
                            
                            # Configure MCP if present
                            if proxy.get('mcp'):
                                client.post_sync(f'/api/v1/proxy/targets/{proxy["hostname"]}/mcp', proxy['mcp'])
                            
                            stats['success'] += 1
                    except Exception as e:
                        stats['failed'] += 1
                        if not skip_existing:
                            console.print(f"  [red]Failed to import proxy {proxy['hostname']}: {e}[/red]")
                progress.update(task, description="Imported proxies")
            
            # Import routes
            if config.get('routes'):
                task = progress.add_task("Importing routes...", total=None)
                for route in config['routes']:
                    try:
                        if dry_run:
                            console.print(f"  [dim]Would create route: {route.get('route_id', route['path_pattern'])}[/dim]")
                        else:
                            client.post_sync('/api/v1/routes/', route)
                            stats['success'] += 1
                    except Exception as e:
                        stats['failed'] += 1
                        if not skip_existing:
                            console.print(f"  [red]Failed to import route: {e}[/red]")
                progress.update(task, description="Imported routes")
        
        # Show summary
        console.print(f"\n[bold]Import Summary:[/bold]")
        console.print(f"  ✓ Success: {stats['success']}")
        console.print(f"  ⊘ Skipped: {stats['skipped']}")
        console.print(f"  ✗ Failed: {stats['failed']}")
        
        if dry_run:
            console.print("\n[yellow]DRY RUN COMPLETE - No changes were made[/yellow]")
        else:
            console.print("\n[green]✓ Configuration import complete![/green]")
            
    except Exception as e:
        ctx.handle_error(e)


@config_group.command('validate')
@click.argument('config-file', type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_obj
def validate_config_file(ctx, config_file):
    """Validate a configuration file without importing."""
    try:
        # Load configuration file
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        errors = []
        warnings = []
        
        # Check version
        if config.get('version') != '1.0':
            errors.append(f"Unsupported config version: {config.get('version')}")
        
        # Check metadata
        if not config.get('metadata'):
            warnings.append("Missing metadata section")
        
        # Validate structure
        expected_sections = ['tokens', 'certificates', 'services', 'proxies', 'routes', 'resources']
        for section in expected_sections:
            if section not in config:
                warnings.append(f"Missing section: {section}")
        
        # Validate tokens
        if config.get('tokens'):
            for i, token in enumerate(config['tokens']):
                if not token.get('name'):
                    errors.append(f"Token {i}: missing 'name' field")
        
        # Validate certificates
        if config.get('certificates'):
            for i, cert in enumerate(config['certificates']):
                if not cert.get('cert_name'):
                    errors.append(f"Certificate {i}: missing 'cert_name' field")
                if not cert.get('domains'):
                    errors.append(f"Certificate {i}: missing 'domains' field")
        
        # Validate proxies
        if config.get('proxies'):
            for i, proxy in enumerate(config['proxies']):
                if not proxy.get('hostname'):
                    errors.append(f"Proxy {i}: missing 'hostname' field")
                if not proxy.get('target_url'):
                    errors.append(f"Proxy {i}: missing 'target_url' field")
        
        # Validate routes
        if config.get('routes'):
            for i, route in enumerate(config['routes']):
                if not route.get('path_pattern'):
                    errors.append(f"Route {i}: missing 'path_pattern' field")
                if not route.get('target_type'):
                    errors.append(f"Route {i}: missing 'target_type' field")
        
        # Display results
        console.print(f"[bold]Validation Results for {config_file}:[/bold]\n")
        
        if errors:
            console.print("[red]Errors:[/red]")
            for error in errors:
                console.print(f"  ✗ {error}")
        
        if warnings:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  ⚠ {warning}")
        
        if not errors and not warnings:
            console.print("[green]✓ Configuration file is valid[/green]")
        elif not errors:
            console.print("\n[green]✓ Configuration file is valid with warnings[/green]")
        else:
            console.print("\n[red]✗ Configuration file has errors and cannot be imported[/red]")
            ctx.exit(1)
            
    except yaml.YAMLError as e:
        console.print(f"[red]Invalid YAML file: {e}[/red]")
        ctx.exit(1)
    except Exception as e:
        ctx.handle_error(e)