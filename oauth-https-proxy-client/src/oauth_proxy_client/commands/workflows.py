"""High-level workflow commands for common operations."""

import click
import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm

console = Console()


@click.group('workflow')
def workflow_group():
    """High-level workflow commands."""
    pass


@workflow_group.command('proxy-quickstart')
@click.argument('hostname')
@click.argument('target-url')
@click.option('--enable-auth', is_flag=True, help='Enable OAuth authentication')
@click.option('--auth-proxy', help='OAuth proxy hostname (default: auth.{base-domain})')
@click.option('--auth-users', help='Comma-separated list of allowed users')
@click.option('--staging', is_flag=True, help='Use staging certificates')
@click.option('--email', envvar='ADMIN_EMAIL', help='Email for certificates')
@click.pass_obj
def proxy_quickstart(ctx, hostname, target_url, enable_auth, auth_proxy, auth_users, staging, email):
    """Quick setup for a new proxy with certificate and optional auth.
    
    This workflow will:
    1. Create a certificate for the hostname (if HTTPS)
    2. Create the proxy with the certificate
    3. Configure authentication (if enabled)
    4. Setup necessary OAuth routes (if auth enabled)
    """
    try:
        client = ctx.ensure_client()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Step 1: Create certificate if needed
            if not target_url.startswith('http://localhost'):
                task = progress.add_task("Creating certificate...", total=None)
                
                cert_data = {
                    'cert_name': f'cert-{hostname.replace(".", "-")}',
                    'domains': [hostname],
                    'staging': staging,
                }
                
                if email:
                    cert_data['email'] = email
                
                try:
                    cert_result = client.post_sync('/api/v1/certificates/', cert_data)
                    
                    # Wait for certificate generation
                    max_attempts = 60
                    for attempt in range(max_attempts):
                        status = client.get_sync(f'/api/v1/certificates/{cert_data["cert_name"]}/status')
                        if status.get('status') == 'completed':
                            progress.update(task, description="[green]Certificate created![/green]")
                            break
                        elif status.get('status') == 'failed':
                            raise Exception(f"Certificate generation failed: {status.get('error')}")
                        time.sleep(2)
                    else:
                        raise Exception("Certificate generation timed out")
                    
                except Exception as e:
                    progress.update(task, description=f"[yellow]Certificate creation failed: {e}[/yellow]")
                    cert_data['cert_name'] = None
            else:
                cert_data = {'cert_name': None}
            
            # Step 2: Create proxy
            task = progress.add_task("Creating proxy...", total=None)
            
            proxy_data = {
                'hostname': hostname,
                'target_url': target_url,
                'preserve_host_header': True,
                'enable_http': True,
                'enable_https': cert_data['cert_name'] is not None,
            }
            
            if cert_data['cert_name']:
                proxy_data['cert_name'] = cert_data['cert_name']
            
            proxy_result = client.post_sync('/api/v1/proxy/targets/', proxy_data)
            progress.update(task, description="[green]Proxy created![/green]")
            
            # Step 3: Configure authentication if requested
            if enable_auth:
                task = progress.add_task("Configuring authentication...", total=None)
                
                if not auth_proxy:
                    # Extract base domain from hostname
                    parts = hostname.split('.')
                    if len(parts) > 2:
                        base_domain = '.'.join(parts[-2:])
                    else:
                        base_domain = hostname
                    auth_proxy = f'auth.{base_domain}'
                
                auth_data = {
                    'auth_enabled': True,
                    'auth_proxy': auth_proxy,
                    'auth_mode': 'forward',
                    'auth_pass_headers': True,
                }
                
                if auth_users:
                    auth_data['auth_required_users'] = auth_users.split(',')
                
                client.post_sync(f'/api/v1/proxy/targets/{hostname}/auth', auth_data)
                progress.update(task, description="[green]Authentication configured![/green]")
                
                # Step 4: Setup OAuth routes
                task = progress.add_task("Setting up OAuth routes...", total=None)
                
                oauth_paths = [
                    ('/authorize', 95),
                    ('/token', 95),
                    ('/callback', 95),
                    ('/verify', 95),
                    ('/.well-known/oauth-authorization-server', 95),
                    ('/jwks', 95),
                    ('/revoke', 95),
                    ('/introspect', 95),
                ]
                
                for path, priority in oauth_paths:
                    route_data = {
                        'path_pattern': path,
                        'target_type': 'hostname',
                        'target_value': auth_proxy,
                        'priority': priority,
                        'scope': 'proxy',
                        'proxy_hostnames': [auth_proxy],
                        'methods': ['*'],
                        'enabled': True,
                    }
                    
                    try:
                        client.post_sync('/api/v1/routes/', route_data)
                    except Exception:
                        # Route might already exist
                        pass
                
                progress.update(task, description="[green]OAuth routes configured![/green]")
        
        # Show summary
        console.print("\n[bold green]✓ Proxy quickstart completed![/bold green]")
        console.print(f"  Hostname: {hostname}")
        console.print(f"  Target: {target_url}")
        if cert_data.get('cert_name'):
            console.print(f"  Certificate: {cert_data['cert_name']}")
        if enable_auth:
            console.print(f"  Authentication: Enabled via {auth_proxy}")
            if auth_users:
                console.print(f"  Allowed Users: {auth_users}")
        
        console.print(f"\n[dim]Access your proxy at: {'https' if cert_data.get('cert_name') else 'http'}://{hostname}[/dim]")
        
    except Exception as e:
        ctx.handle_error(e)


@workflow_group.command('service-with-proxy')
@click.argument('name')
@click.argument('image')
@click.option('--port', type=int, default=8080, help='Service port')
@click.option('--hostname', help='Proxy hostname (default: {name}.{base-domain})')
@click.option('--enable-https', is_flag=True, help='Enable HTTPS with certificate')
@click.option('--memory', default='512m', help='Memory limit')
@click.option('--cpu', type=float, default=1.0, help='CPU limit')
@click.option('--env', multiple=True, help='Environment variables (KEY=value)')
@click.pass_obj
def service_with_proxy(ctx, name, image, port, hostname, enable_https, memory, cpu, env):
    """Create a Docker service with automatic proxy configuration.
    
    This workflow will:
    1. Create a Docker service
    2. Wait for the service to be healthy
    3. Create a proxy pointing to the service
    4. Optionally create an HTTPS certificate
    """
    try:
        client = ctx.ensure_client()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Step 1: Create Docker service
            task = progress.add_task("Creating Docker service...", total=None)
            
            service_data = {
                'service_name': name,
                'image': image,
                'memory_limit': memory,
                'cpu_limit': cpu,
                'internal_port': port,
                'expose_ports': False,  # We'll use proxy instead of exposing ports
            }
            
            if env:
                service_data['environment'] = dict(e.split('=', 1) for e in env)
            
            service_result = client.post_sync('/api/v1/services/', service_data)
            progress.update(task, description="[green]Service created![/green]")
            
            # Step 2: Wait for service to be healthy
            task = progress.add_task("Waiting for service to start...", total=None)
            
            max_attempts = 30
            for attempt in range(max_attempts):
                try:
                    stats = client.get_sync(f'/api/v1/services/{name}/stats')
                    if stats.get('status') == 'running':
                        progress.update(task, description="[green]Service is running![/green]")
                        break
                except Exception:
                    pass
                time.sleep(2)
            else:
                console.print("[yellow]Warning: Service might not be fully started[/yellow]")
            
            # Step 3: Create proxy
            if not hostname:
                # Try to get base domain from environment or use localhost
                hostname = f'{name}.localhost'
            
            task = progress.add_task("Creating proxy...", total=None)
            
            # Create certificate if HTTPS is requested
            cert_name = None
            if enable_https:
                cert_data = {
                    'cert_name': f'cert-{name}',
                    'domains': [hostname],
                }
                
                try:
                    cert_result = client.post_sync('/api/v1/certificates/', cert_data)
                    cert_name = cert_data['cert_name']
                    
                    # Wait for certificate
                    for attempt in range(60):
                        status = client.get_sync(f'/api/v1/certificates/{cert_name}/status')
                        if status.get('status') == 'completed':
                            break
                        elif status.get('status') == 'failed':
                            console.print(f"[yellow]Certificate generation failed[/yellow]")
                            cert_name = None
                            break
                        time.sleep(2)
                except Exception as e:
                    console.print(f"[yellow]Certificate creation failed: {e}[/yellow]")
                    cert_name = None
            
            # Create the proxy
            proxy_data = {
                'hostname': hostname,
                'target_url': f'http://{name}:{port}',
                'preserve_host_header': True,
                'enable_http': True,
                'enable_https': cert_name is not None,
            }
            
            if cert_name:
                proxy_data['cert_name'] = cert_name
            
            proxy_result = client.post_sync('/api/v1/proxy/targets/', proxy_data)
            progress.update(task, description="[green]Proxy created![/green]")
        
        # Show summary
        console.print("\n[bold green]✓ Service with proxy created![/bold green]")
        console.print(f"  Service: {name}")
        console.print(f"  Image: {image}")
        console.print(f"  Internal Port: {port}")
        console.print(f"  Proxy Hostname: {hostname}")
        if cert_name:
            console.print(f"  Certificate: {cert_name}")
        
        console.print(f"\n[dim]Access your service at: {'https' if cert_name else 'http'}://{hostname}[/dim]")
        
    except Exception as e:
        ctx.handle_error(e)


@workflow_group.command('oauth-setup')
@click.argument('domain')
@click.option('--generate-key', is_flag=True, help='Generate new JWT RSA key')
@click.option('--github-client-id', envvar='GITHUB_CLIENT_ID', help='GitHub OAuth client ID')
@click.option('--github-client-secret', envvar='GITHUB_CLIENT_SECRET', help='GitHub OAuth client secret')
@click.pass_obj
def oauth_setup(ctx, domain, generate_key, github_client_id, github_client_secret):
    """Complete OAuth setup for a domain.
    
    This workflow will:
    1. Generate JWT key if needed
    2. Create OAuth routes
    3. Create auth proxy with certificate
    4. Register OAuth as an external service
    """
    try:
        client = ctx.ensure_client()
        
        auth_hostname = f'auth.{domain}'
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Step 1: Generate JWT key if requested
            if generate_key:
                task = progress.add_task("Generating JWT RSA key...", total=None)
                
                try:
                    key_result = client.post_sync('/api/v1/oauth/key/generate')
                    progress.update(task, description="[green]JWT key generated![/green]")
                    console.print(f"\n[yellow]Save this key in your .env file:[/yellow]")
                    console.print(f"OAUTH_JWT_PRIVATE_KEY_B64={key_result.get('private_key_b64')[:50]}...")
                except Exception as e:
                    progress.update(task, description=f"[yellow]Key generation failed: {e}[/yellow]")
            
            # Step 2: Create certificate for auth domain
            task = progress.add_task(f"Creating certificate for {auth_hostname}...", total=None)
            
            cert_data = {
                'cert_name': f'cert-auth-{domain.replace(".", "-")}',
                'domains': [auth_hostname],
            }
            
            try:
                cert_result = client.post_sync('/api/v1/certificates/', cert_data)
                
                # Wait for certificate
                for attempt in range(60):
                    status = client.get_sync(f'/api/v1/certificates/{cert_data["cert_name"]}/status')
                    if status.get('status') == 'completed':
                        progress.update(task, description="[green]Certificate created![/green]")
                        break
                    elif status.get('status') == 'failed':
                        raise Exception(f"Certificate generation failed: {status.get('error')}")
                    time.sleep(2)
            except Exception as e:
                progress.update(task, description=f"[yellow]Certificate creation failed: {e}[/yellow]")
                cert_data['cert_name'] = None
            
            # Step 3: Create auth proxy
            task = progress.add_task("Creating OAuth proxy...", total=None)
            
            proxy_data = {
                'hostname': auth_hostname,
                'target_url': 'http://api:9000',  # OAuth runs on the API service
                'preserve_host_header': True,
                'enable_http': True,
                'enable_https': cert_data.get('cert_name') is not None,
            }
            
            if cert_data.get('cert_name'):
                proxy_data['cert_name'] = cert_data['cert_name']
            
            try:
                proxy_result = client.post_sync('/api/v1/proxy/targets/', proxy_data)
                progress.update(task, description="[green]OAuth proxy created![/green]")
            except Exception as e:
                if 'already exists' in str(e).lower():
                    progress.update(task, description="[yellow]OAuth proxy already exists[/yellow]")
                else:
                    raise e
            
            # Step 4: Setup OAuth routes
            task = progress.add_task("Setting up OAuth routes...", total=None)
            
            oauth_routes = [
                ('/authorize', 'OAuth authorization endpoint'),
                ('/token', 'Token exchange endpoint'),
                ('/callback', 'OAuth callback handler'),
                ('/verify', 'Token verification endpoint'),
                ('/revoke', 'Token revocation endpoint'),
                ('/introspect', 'Token introspection'),
                ('/register', 'Dynamic client registration'),
                ('/jwks', 'JSON Web Key Set'),
                ('/.well-known/oauth-authorization-server', 'Server metadata'),
            ]
            
            routes_created = 0
            for path, description in oauth_routes:
                route_data = {
                    'path_pattern': path,
                    'target_type': 'hostname',
                    'target_value': auth_hostname,
                    'priority': 95,
                    'scope': 'proxy',
                    'proxy_hostnames': [auth_hostname],
                    'methods': ['*'],
                    'enabled': True,
                    'description': description,
                }
                
                try:
                    client.post_sync('/api/v1/routes/', route_data)
                    routes_created += 1
                except Exception:
                    # Route might already exist
                    pass
            
            progress.update(task, description=f"[green]Created {routes_created} OAuth routes![/green]")
            
            # Step 5: Register OAuth as external service
            task = progress.add_task("Registering OAuth service...", total=None)
            
            try:
                service_data = {
                    'service_name': 'oauth',
                    'target_url': f'https://{auth_hostname}',
                    'service_type': 'external',
                    'description': 'OAuth 2.1 Authorization Server',
                    'routing_enabled': True,
                }
                
                client.post_sync('/api/v1/services/external', service_data)
                progress.update(task, description="[green]OAuth service registered![/green]")
            except Exception as e:
                if 'already exists' in str(e).lower():
                    progress.update(task, description="[yellow]OAuth service already registered[/yellow]")
                else:
                    progress.update(task, description=f"[yellow]Service registration failed: {e}[/yellow]")
        
        # Show summary and next steps
        console.print("\n[bold green]✓ OAuth setup completed![/bold green]")
        console.print(f"  OAuth Domain: {auth_hostname}")
        console.print(f"  Certificate: {cert_data.get('cert_name', 'None')}")
        console.print(f"  Target: http://api:9000")
        
        console.print("\n[bold]Next steps:[/bold]")
        
        if not github_client_id or not github_client_secret:
            console.print("[yellow]1. Configure GitHub OAuth application:[/yellow]")
            console.print(f"   - Go to https://github.com/settings/developers")
            console.print(f"   - Create new OAuth App")
            console.print(f"   - Authorization callback URL: https://{auth_hostname}/callback")
            console.print(f"   - Add to .env file:")
            console.print(f"     GITHUB_CLIENT_ID=your_client_id")
            console.print(f"     GITHUB_CLIENT_SECRET=your_client_secret")
        
        console.print("\n[yellow]2. Configure allowed users in .env:[/yellow]")
        console.print("   OAUTH_ALLOWED_GITHUB_USERS=user1,user2  # or * for all")
        
        console.print(f"\n[dim]OAuth server available at: https://{auth_hostname}[/dim]")
        console.print(f"[dim]Server metadata: https://{auth_hostname}/.well-known/oauth-authorization-server[/dim]")
        
    except Exception as e:
        ctx.handle_error(e)


@workflow_group.command('cleanup')
@click.option('--orphaned-only', is_flag=True, help='Only clean up orphaned resources')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def cleanup_resources(ctx, orphaned_only, force):
    """Clean up unused or orphaned resources.
    
    This will:
    1. Find orphaned Docker containers
    2. Remove unused certificates
    3. Clean up stale routes
    4. Remove disconnected services
    """
    try:
        if not force:
            if orphaned_only:
                msg = "Clean up orphaned resources?"
            else:
                msg = "Clean up all unused resources? This may delete active resources!"
            
            if not Confirm.ask(msg, default=False):
                return
        
        client = ctx.ensure_client()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            stats = {
                'containers': 0,
                'certificates': 0,
                'routes': 0,
                'services': 0,
            }
            
            # Clean up orphaned services
            task = progress.add_task("Cleaning up orphaned services...", total=None)
            try:
                result = client.post_sync('/api/v1/services/cleanup')
                if result.get('removed'):
                    stats['services'] = len(result['removed'])
                progress.update(task, description=f"[green]Cleaned {stats['services']} services[/green]")
            except Exception as e:
                progress.update(task, description=f"[yellow]Service cleanup failed: {e}[/yellow]")
            
            if not orphaned_only:
                # Clean up unused certificates
                task = progress.add_task("Finding unused certificates...", total=None)
                try:
                    certs = client.get_sync('/api/v1/certificates/')
                    proxies = client.get_sync('/api/v1/proxy/targets/')
                    
                    used_certs = {p.get('cert_name') for p in proxies if p.get('cert_name')}
                    
                    for cert in certs:
                        if cert['cert_name'] not in used_certs:
                            try:
                                client.delete_sync(f'/api/v1/certificates/{cert["cert_name"]}')
                                stats['certificates'] += 1
                            except Exception:
                                pass
                    
                    progress.update(task, description=f"[green]Removed {stats['certificates']} unused certificates[/green]")
                except Exception as e:
                    progress.update(task, description=f"[yellow]Certificate cleanup failed: {e}[/yellow]")
                
                # Clean up stale routes
                task = progress.add_task("Cleaning up stale routes...", total=None)
                try:
                    routes = client.get_sync('/api/v1/routes/')
                    services = client.get_sync('/api/v1/services/unified')
                    service_names = {s['service_name'] for s in services}
                    
                    for route in routes:
                        if route.get('target_type') == 'service':
                            if route.get('target_value') not in service_names:
                                try:
                                    client.delete_sync(f'/api/v1/routes/{route["route_id"]}')
                                    stats['routes'] += 1
                                except Exception:
                                    pass
                    
                    progress.update(task, description=f"[green]Removed {stats['routes']} stale routes[/green]")
                except Exception as e:
                    progress.update(task, description=f"[yellow]Route cleanup failed: {e}[/yellow]")
        
        # Show summary
        console.print("\n[bold]Cleanup Summary:[/bold]")
        console.print(f"  Services cleaned: {stats['services']}")
        console.print(f"  Certificates removed: {stats['certificates']}")
        console.print(f"  Routes removed: {stats['routes']}")
        
        total = sum(stats.values())
        if total > 0:
            console.print(f"\n[green]✓ Total resources cleaned: {total}[/green]")
        else:
            console.print("\n[dim]No resources needed cleaning[/dim]")
        
    except Exception as e:
        ctx.handle_error(e)