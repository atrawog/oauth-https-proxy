"""Service management commands."""

import click
from rich.console import Console
from rich.prompt import Confirm

console = Console()


@click.group('service')
def service_group():
    """Manage Docker and external services."""
    pass


@service_group.command('list')
@click.option('--type', 'service_type', type=click.Choice(['all', 'docker', 'external']), default='all')
@click.pass_obj
def list_services(ctx, service_type):
    """List services."""
    try:
        client = ctx.ensure_client()
        
        if service_type == 'all':
            services = client.get_sync('/api/v1/services/unified')
        elif service_type == 'docker':
            services = client.get_sync('/api/v1/services/')
        else:  # external
            services = client.get_sync('/api/v1/services/external')
        
        ctx.output(services, title=f"Services ({service_type})", data_type='services')
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('create')
@click.argument('name')
@click.argument('image')
@click.option('--port', type=int, help='Container port to expose')
@click.option('--memory', default='512m', help='Memory limit')
@click.option('--cpu', type=float, default=1.0, help='CPU limit')
@click.option('--env', multiple=True, help='Environment variables (KEY=value)')
@click.pass_obj
def create_service(ctx, name, image, port, memory, cpu, env):
    """Create a Docker service."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'service_name': name,
            'image': image,
            'memory_limit': memory,
            'cpu_limit': cpu,
        }
        
        if port:
            data['internal_port'] = port
            data['expose_ports'] = True
        
        if env:
            data['environment'] = dict(e.split('=', 1) for e in env)
        
        result = client.post_sync('/api/v1/services/', data)
        
        console.print(f"[green]Service '{name}' created successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('delete')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def delete_service(ctx, name, force):
    """Delete a service."""
    try:
        if not force:
            if not Confirm.ask(f"Delete service '{name}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/services/{name}')
        
        console.print(f"[green]Service '{name}' deleted successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('start')
@click.argument('name')
@click.pass_obj
def start_service(ctx, name):
    """Start a service."""
    try:
        client = ctx.ensure_client()
        client.post_sync(f'/api/v1/services/{name}/start')
        console.print(f"[green]Service '{name}' started![/green]")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('stop')
@click.argument('name')
@click.pass_obj
def stop_service(ctx, name):
    """Stop a service."""
    try:
        client = ctx.ensure_client()
        client.post_sync(f'/api/v1/services/{name}/stop')
        console.print(f"[green]Service '{name}' stopped![/green]")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('restart')
@click.argument('name')
@click.pass_obj
def restart_service(ctx, name):
    """Restart a service."""
    try:
        client = ctx.ensure_client()
        client.post_sync(f'/api/v1/services/{name}/restart')
        console.print(f"[green]Service '{name}' restarted![/green]")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('logs')
@click.argument('name')
@click.option('--lines', '-n', type=int, default=100, help='Number of lines to show')
@click.option('--follow', '-f', is_flag=True, help='Follow log output')
@click.pass_obj
def service_logs(ctx, name, lines, follow):
    """View service logs."""
    try:
        client = ctx.ensure_client()
        
        params = {'lines': lines}
        if follow:
            params['follow'] = 'true'
        
        logs = client.get_sync(f'/api/v1/services/{name}/logs', params)
        
        # Logs are returned as text
        console.print(logs)
    except Exception as e:
        ctx.handle_error(e)


# External service subcommands
@service_group.group('external')
def external_group():
    """Manage external service registry."""
    pass


@external_group.command('register')
@click.argument('name')
@click.argument('target-url')
@click.option('--description', help='Service description')
@click.pass_obj
def register_external(ctx, name, target_url, description):
    """Register an external service."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'service_name': name,
            'target_url': target_url,
            'service_type': 'external',
            'routing_enabled': True,
        }
        
        if description:
            data['description'] = description
        
        result = client.post_sync('/api/v1/services/external', data)
        
        console.print(f"[green]External service '{name}' registered successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@external_group.command('list')
@click.pass_obj
def list_external(ctx):
    """List all external services."""
    try:
        client = ctx.ensure_client()
        services = client.get_sync('/api/v1/services/external')
        ctx.output(services, title="External Services")
    except Exception as e:
        ctx.handle_error(e)


@external_group.command('show')
@click.argument('name')
@click.pass_obj
def show_external(ctx, name):
    """Show external service details."""
    try:
        client = ctx.ensure_client()
        service = client.get_sync(f'/api/v1/services/external/{name}')
        ctx.output(service, title=f"External Service: {name}")
    except Exception as e:
        ctx.handle_error(e)


@external_group.command('update')
@click.argument('name')
@click.argument('target-url')
@click.option('--description', help='Update service description')
@click.pass_obj
def update_external(ctx, name, target_url, description):
    """Update external service configuration."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'target_url': target_url,
        }
        
        if description is not None:
            data['description'] = description
        
        result = client.put_sync(f'/api/v1/services/external/{name}', data)
        
        console.print(f"[green]External service '{name}' updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@external_group.command('unregister')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def unregister_external(ctx, name, force):
    """Unregister an external service."""
    try:
        if not force:
            if not Confirm.ask(f"Unregister external service '{name}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/services/external/{name}')
        
        console.print(f"[green]External service '{name}' unregistered successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


# Additional service commands for completeness
@service_group.command('show')
@click.argument('name')
@click.pass_obj
def show_service(ctx, name):
    """Show service details (Docker or external)."""
    try:
        client = ctx.ensure_client()
        
        # Try Docker service first
        try:
            service = client.get_sync(f'/api/v1/services/{name}')
            ctx.output(service, title=f"Docker Service: {name}")
            return
        except Exception:
            pass
        
        # Try external service
        try:
            service = client.get_sync(f'/api/v1/services/external/{name}')
            ctx.output(service, title=f"External Service: {name}")
            return
        except Exception:
            pass
        
        console.print(f"[red]Service '{name}' not found[/red]")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('stats')
@click.argument('name')
@click.pass_obj
def service_stats(ctx, name):
    """Show service statistics."""
    try:
        client = ctx.ensure_client()
        stats = client.get_sync(f'/api/v1/services/{name}/stats')
        ctx.output(stats, title=f"Service Stats: {name}")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('cleanup')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def cleanup_services(ctx, force):
    """Clean up orphaned services."""
    try:
        if not force:
            if not Confirm.ask("Clean up orphaned services?", default=False):
                return
        
        client = ctx.ensure_client()
        result = client.post_sync('/api/v1/services/cleanup')
        
        console.print("[green]Service cleanup completed![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


# Port management subcommands
@service_group.group('port')
def port_group():
    """Manage service ports."""
    pass


@port_group.command('add')
@click.argument('service-name')
@click.argument('port', type=int)
@click.option('--bind-address', default='127.0.0.1', help='Bind address (127.0.0.1 or 0.0.0.0)')
@click.option('--name', help='Port name/identifier')
@click.option('--protocol', type=click.Choice(['tcp', 'udp']), default='tcp')
@click.option('--source-token', help='Optional access token for this port')
@click.pass_obj
def add_port(ctx, service_name, port, bind_address, name, protocol, source_token):
    """Add a port to an existing service."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'host_port': port,
            'container_port': port,
            'bind_address': bind_address,
            'protocol': protocol,
        }
        
        if name:
            data['port_name'] = name
        else:
            data['port_name'] = f'{protocol}-{port}'
        
        if source_token:
            data['source_token'] = source_token
        
        result = client.post_sync(f'/api/v1/services/{service_name}/ports', data)
        
        console.print(f"[green]Port {port} added to service '{service_name}'![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@port_group.command('remove')
@click.argument('service-name')
@click.argument('port-name')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def remove_port(ctx, service_name, port_name, force):
    """Remove a port from a service."""
    try:
        if not force:
            if not Confirm.ask(f"Remove port '{port_name}' from service '{service_name}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/services/{service_name}/ports/{port_name}')
        
        console.print(f"[green]Port '{port_name}' removed from service '{service_name}'![/green]")
    except Exception as e:
        ctx.handle_error(e)


@port_group.command('list')
@click.argument('service-name')
@click.pass_obj
def list_ports(ctx, service_name):
    """List all ports for a service."""
    try:
        client = ctx.ensure_client()
        ports = client.get_sync(f'/api/v1/services/{service_name}/ports')
        ctx.output(ports, title=f"Ports for service: {service_name}")
    except Exception as e:
        ctx.handle_error(e)


@port_group.command('check')
@click.argument('port', type=int)
@click.option('--bind-address', default='127.0.0.1', help='Bind address to check')
@click.pass_obj
def check_port(ctx, port, bind_address):
    """Check if a port is available."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'port': port,
            'bind_address': bind_address,
        }
        
        result = client.post_sync('/api/v1/services/ports/check', data)
        
        if result.get('available'):
            console.print(f"[green]✓ Port {port} on {bind_address} is available[/green]")
        else:
            console.print(f"[red]✗ Port {port} on {bind_address} is in use[/red]")
            if result.get('service'):
                console.print(f"  Used by: {result['service']}")
        
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('ports')
@click.option('--available-only', is_flag=True, help='Show only available port ranges')
@click.pass_obj
def global_ports(ctx, available_only):
    """List all allocated ports across all services."""
    try:
        client = ctx.ensure_client()
        
        params = {}
        if available_only:
            params['available_only'] = 'true'
            
        if available_only:
            result = client.get_sync('/api/v1/services/ports/available', params)
            ctx.output(result, title="Available Port Ranges")
        else:
            result = client.get_sync('/api/v1/services/ports', params)
            ctx.output(result, title="Allocated Ports")
    except Exception as e:
        ctx.handle_error(e)


# Additional service creation commands
@service_group.command('create-exposed')
@click.argument('name')
@click.argument('image')
@click.argument('port', type=int)
@click.option('--bind-address', default='127.0.0.1', help='Bind address (127.0.0.1 or 0.0.0.0)')
@click.option('--memory', default='512m', help='Memory limit')
@click.option('--cpu', type=float, default=1.0, help='CPU limit')
@click.option('--env', multiple=True, help='Environment variables (KEY=value)')
@click.pass_obj
def create_exposed_service(ctx, name, image, port, bind_address, memory, cpu, env):
    """Create a Docker service with exposed port."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'service_name': name,
            'image': image,
            'memory_limit': memory,
            'cpu_limit': cpu,
            'internal_port': port,
            'expose_ports': True,
            'bind_address': bind_address,
            'port_configs': [
                {
                    'name': 'main',
                    'host': port,
                    'container': port,
                    'bind': bind_address,
                    'protocol': 'tcp'
                }
            ]
        }
        
        if env:
            data['environment'] = dict(e.split('=', 1) for e in env)
        
        result = client.post_sync('/api/v1/services/', data)
        
        console.print(f"[green]Service '{name}' created with exposed port {port}![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('proxy-create')
@click.argument('service-name')
@click.option('--hostname', help='Proxy hostname (default: {service-name}.{base-domain})')
@click.option('--enable-https/--no-enable-https', default=True, help='Enable HTTPS')
@click.option('--staging', is_flag=True, help='Use staging certificates')
@click.pass_obj
def create_service_proxy(ctx, service_name, hostname, enable_https, staging):
    """Create a proxy for a service."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'service_name': service_name,
            'enable_https': enable_https,
            'staging': staging,
        }
        
        if hostname:
            data['hostname'] = hostname
        
        result = client.post_sync(f'/api/v1/services/{service_name}/proxy', data)
        
        console.print(f"[green]Proxy created for service '{service_name}'![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


# Additional service commands for missing endpoints

@service_group.command('update')
@click.argument('service-name')
@click.option('--image', help='Docker image')
@click.option('--internal-port', type=int, help='Internal port')
@click.option('--memory-limit', help='Memory limit (e.g., 512m)')
@click.option('--cpu-limit', type=float, help='CPU limit')
@click.option('--environment', help='Environment variables as JSON')
@click.option('--command', help='Command to run as JSON array')
@click.option('--bind-address', help='Default bind address for ports')
@click.pass_obj
def update_service(ctx, service_name, image, internal_port, memory_limit, cpu_limit, environment, command, bind_address):
    """Update service configuration."""
    try:
        import json
        client = ctx.ensure_client()
        
        # Get current configuration
        current = client.get_sync(f'/api/v1/services/{service_name}')
        
        # Build update data
        data = dict(current)
        
        if image:
            data['image'] = image
        if internal_port:
            data['internal_port'] = internal_port
        if memory_limit:
            data['memory_limit'] = memory_limit
        if cpu_limit:
            data['cpu_limit'] = cpu_limit
        if environment:
            data['environment'] = json.loads(environment)
        if command:
            data['command'] = json.loads(command)
        if bind_address:
            data['bind_address'] = bind_address
        
        result = client.put_sync(f'/api/v1/services/{service_name}', data)
        
        console.print(f"[green]Service '{service_name}' updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@port_group.command('update')
@click.argument('service-name')
@click.argument('port-name')
@click.option('--host-port', type=int, help='New host port')
@click.option('--container-port', type=int, help='New container port')
@click.option('--bind-address', help='New bind address')
@click.option('--protocol', type=click.Choice(['tcp', 'udp']), help='Protocol')
@click.option('--source-token', help='Source token for access control')
@click.pass_obj
def update_port(ctx, service_name, port_name, host_port, container_port, bind_address, protocol, source_token):
    """Update port configuration."""
    try:
        client = ctx.ensure_client()
        
        # Get current port configuration
        ports = client.get_sync(f'/api/v1/services/{service_name}/ports')
        current = next((p for p in ports if p.get('port_name') == port_name), None)
        
        if not current:
            console.print(f"[red]Port '{port_name}' not found for service '{service_name}'[/red]")
            return
        
        # Build update data
        data = dict(current)
        
        if host_port:
            data['host_port'] = host_port
        if container_port:
            data['container_port'] = container_port
        if bind_address:
            data['bind_address'] = bind_address
        if protocol:
            data['protocol'] = protocol
        if source_token:
            data['source_token'] = source_token
        
        result = client.put_sync(f'/api/v1/services/{service_name}/ports/{port_name}', data)
        
        console.print(f"[green]Port '{port_name}' updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('ports-global')
@click.option('--available-only', is_flag=True, help='Show only available ports')
@click.pass_obj
def list_global_ports(ctx, available_only):
    """List all allocated ports across all services."""
    try:
        client = ctx.ensure_client()
        
        if available_only:
            ports = client.get_sync('/api/v1/services/ports/available')
            ctx.output(ports, title="Available Port Ranges")
        else:
            ports = client.get_sync('/api/v1/services/ports')
            ctx.output(ports, title="All Allocated Ports")
    except Exception as e:
        ctx.handle_error(e)


@service_group.command('port-check-api')
@click.argument('port', type=int)
@click.option('--bind-address', default='127.0.0.1', help='Bind address to check')
@click.pass_obj
def check_port_api(ctx, port, bind_address):
    """Check if a port is available (using API endpoint)."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'port': port,
            'bind_address': bind_address
        }
        
        result = client.post_sync('/api/v1/services/ports/check', data)
        
        if result.get('available'):
            console.print(f"[green]Port {port} on {bind_address} is available[/green]")
        else:
            console.print(f"[red]Port {port} on {bind_address} is in use[/red]")
            if result.get('service_name'):
                console.print(f"Used by service: {result['service_name']}")
        
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)