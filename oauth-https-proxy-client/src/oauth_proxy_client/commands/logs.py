"""Log query and analysis commands."""

import click
import asyncio
import time
from rich.console import Console
from rich.live import Live
from rich.table import Table

console = Console()


@click.group('log')
def log_group():
    """Query and analyze logs."""
    pass


@log_group.command('search')
@click.option('--query', '-q', help='Search query')
@click.option('--hours', type=int, default=24, help='Hours to look back')
@click.option('--hostname', help='Filter by hostname')
@click.option('--status', type=int, help='Filter by HTTP status code')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def search_logs(ctx, query, hours, hostname, status, limit):
    """Search logs with filters."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        if query:
            params['q'] = query
        if hostname:
            params['hostname'] = hostname
        if status:
            params['status'] = status
        
        logs = client.get_sync('/api/v1/logs/search', params)
        ctx.output(logs, title="Log Search Results")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('by-ip')
@click.argument('ip')
@click.option('--hours', type=int, default=24, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_ip(ctx, ip, hours, limit):
    """Query logs by IP address."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/api/v1/logs/ip/{ip}', params)
        ctx.output(logs, title=f"Logs from IP: {ip}")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('by-client')
@click.argument('client-id')
@click.option('--hours', type=int, default=24, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_client(ctx, client_id, hours, limit):
    """Query logs by OAuth client ID."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/api/v1/logs/client/{client_id}', params)
        ctx.output(logs, title=f"Logs from Client: {client_id}")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('errors')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--include-warnings', is_flag=True, help='Include 4xx errors')
@click.option('--limit', type=int, default=50, help='Maximum results')
@click.pass_obj
def show_errors(ctx, hours, include_warnings, limit):
    """Show recent errors."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'include_warnings': include_warnings,
            'limit': limit,
        }
        
        errors = client.get_sync('/api/v1/logs/errors', params)
        ctx.output(errors, title="Recent Errors")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('events')
@click.option('--hours', type=int, default=24, help='Hours to look back')
@click.pass_obj
def event_stats(ctx, hours):
    """Show event statistics."""
    try:
        client = ctx.ensure_client()
        
        params = {'hours': hours}
        stats = client.get_sync('/api/v1/logs/events', params)
        ctx.output(stats, title="Event Statistics")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('follow')
@click.option('--interval', type=int, default=2, help='Update interval in seconds')
@click.option('--hostname', help='Filter by hostname')
@click.option('--status', type=int, help='Filter by status code')
@click.pass_obj
def follow_logs(ctx, interval, hostname, status):
    """Follow logs in real-time."""
    try:
        client = ctx.ensure_client()
        
        console.print(f"[yellow]Following logs (Ctrl+C to stop)...[/yellow]")
        console.print(f"Update interval: {interval} seconds")
        
        if hostname:
            console.print(f"Filtering by hostname: {hostname}")
        if status:
            console.print(f"Filtering by status: {status}")
        
        last_timestamp = None
        
        try:
            while True:
                params = {
                    'hours': 0.1,  # Last 6 minutes
                    'limit': 20,
                }
                
                if hostname:
                    params['hostname'] = hostname
                if status:
                    params['status'] = status
                
                logs = client.get_sync('/api/v1/logs/search', params)
                
                # Filter to only new logs
                if last_timestamp and logs:
                    new_logs = [l for l in logs if l.get('timestamp', '') > last_timestamp]
                else:
                    new_logs = logs
                
                # Display new logs
                for log in new_logs:
                    timestamp = log.get('timestamp', 'N/A')
                    method = log.get('method', 'N/A')
                    path = log.get('path', 'N/A')
                    status_code = log.get('status', 'N/A')
                    ip = log.get('ip', 'N/A')
                    
                    # Color code by status
                    if isinstance(status_code, int):
                        if status_code >= 500:
                            status_color = 'red'
                        elif status_code >= 400:
                            status_color = 'yellow'
                        elif status_code >= 300:
                            status_color = 'blue'
                        else:
                            status_color = 'green'
                    else:
                        status_color = 'white'
                    
                    console.print(
                        f"[dim]{timestamp}[/dim] "
                        f"[{status_color}]{status_code}[/{status_color}] "
                        f"{method} {path} "
                        f"[dim]({ip})[/dim]"
                    )
                
                # Update last timestamp
                if logs:
                    last_timestamp = logs[0].get('timestamp')
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped following logs.[/yellow]")
    except Exception as e:
        ctx.handle_error(e)