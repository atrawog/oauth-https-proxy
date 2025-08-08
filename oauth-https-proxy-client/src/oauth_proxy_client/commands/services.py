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
        
        ctx.output(services, title=f"Services ({service_type})")
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