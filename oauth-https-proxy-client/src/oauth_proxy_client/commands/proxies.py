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
        ctx.output(proxies, title="Proxy Targets", data_type='proxies')
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
        
        # Add certificate configuration
        if cert_name:
            data['cert_name'] = cert_name
        
        # Add ACME configuration for certificate generation
        if enable_https and not cert_name:
            if staging:
                data['acme_directory_url'] = 'https://acme-staging-v02.api.letsencrypt.org/directory'
            # No need to set production URL - API will use default
            
            if email:
                data['cert_email'] = email
        
        result = client.post_sync('/api/v1/proxy/targets/', data)
        
        # Check certificate status
        proxy_target = result.get('proxy_target', {})
        cert_status = result.get('certificate_status', '')
        
        console.print(f"[green]✓ Proxy created successfully![/green]")
        console.print(f"  Hostname: {proxy_target.get('hostname')}")
        console.print(f"  Target URL: {proxy_target.get('target_url')}")
        
        if proxy_target.get('enable_https'):
            if cert_status == 'existing':
                console.print(f"  Certificate: {proxy_target.get('cert_name')} [green](existing)[/green]")
            elif cert_status == 'Certificate generation started':
                console.print(f"  Certificate: {proxy_target.get('cert_name')} [yellow](generating...)[/yellow]")
            elif cert_status == 'https_disabled_no_cert':
                console.print(f"  [yellow]⚠ HTTPS requested but no certificate available[/yellow]")
                console.print(f"    Create one with: just cert-create {proxy_target.get('cert_name')} {hostname}")
        
        if proxy_target.get('enable_https') and proxy_target.get('cert_name'):
            console.print(f"\nTest with: curl https://{hostname}")
        elif proxy_target.get('enable_http'):
            console.print(f"\nTest with: curl http://{hostname}")
            
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
            'endpoint': endpoint,
            'scopes': [s.strip() for s in scopes.split(',')],
            'stateful': stateful,
            'override_backend': override_backend,
            'bearer_methods': [m.strip() for m in bearer_methods.split(',')],
            'documentation_suffix': doc_suffix,
        }
        
        # Parse JSON fields
        try:
            data['server_info'] = json.loads(server_info) if server_info != '{}' else {}
        except json.JSONDecodeError:
            console.print(f"[red]Invalid JSON for server-info: {server_info}[/red]")
            return
            
        try:
            data['custom_metadata'] = json.loads(custom_metadata) if custom_metadata != '{}' else {}
        except json.JSONDecodeError:
            console.print(f"[red]Invalid JSON for custom-metadata: {custom_metadata}[/red]")
            return
        
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/resource', data)
        
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
        resource_config = client.get_sync(f'/api/v1/proxy/targets/{hostname}/resource')
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
        client.delete_sync(f'/api/v1/proxy/targets/{hostname}/resource')
        
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


# OAuth Server subcommands
@proxy_group.group('oauth-server')
def proxy_oauth_server():
    """Manage OAuth authorization server configuration."""
    pass


@proxy_oauth_server.command('set')
@click.argument('hostname')
@click.option('--issuer', help='Custom issuer URL')
@click.option('--scopes', help='Comma-separated supported scopes')
@click.option('--grant-types', help='Comma-separated grant types')
@click.option('--response-types', help='Comma-separated response types')
@click.option('--token-auth-methods', help='Comma-separated token auth methods')
@click.option('--claims', help='Comma-separated supported claims')
@click.option('--pkce-required/--no-pkce-required', default=False, help='Require PKCE')
@click.option('--custom-metadata', help='JSON string of custom metadata')
@click.option('--override-defaults/--no-override-defaults', default=False, help='Override all defaults')
@click.pass_obj
def set_oauth_server(ctx, hostname, issuer, scopes, grant_types, response_types, 
                     token_auth_methods, claims, pkce_required, custom_metadata, override_defaults):
    """Configure OAuth authorization server metadata for a proxy."""
    try:
        import json
        client = ctx.ensure_client()
        
        data = {
            'pkce_required': pkce_required,
            'override_defaults': override_defaults
        }
        
        if issuer:
            data['issuer'] = issuer
        if scopes:
            data['scopes'] = scopes.split(',')
        if grant_types:
            data['grant_types'] = grant_types.split(',')
        if response_types:
            data['response_types'] = response_types.split(',')
        if token_auth_methods:
            data['token_auth_methods'] = token_auth_methods.split(',')
        if claims:
            data['claims'] = claims.split(',')
        if custom_metadata:
            data['custom_metadata'] = json.loads(custom_metadata)
        
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/oauth-server', data)
        
        console.print(f"[green]✓ OAuth server configuration updated for {hostname}![/green]")
        if result.get('oauth_server_config'):
            config = result['oauth_server_config']
            if config.get('issuer'):
                console.print(f"  Issuer: {config['issuer']}")
            if config.get('scopes'):
                console.print(f"  Scopes: {', '.join(config['scopes'])}")
            if config.get('override_defaults'):
                console.print(f"  [yellow]Override defaults: Enabled[/yellow]")
    except Exception as e:
        ctx.handle_error(e)


@proxy_oauth_server.command('show')
@click.argument('hostname')
@click.pass_obj
def show_oauth_server(ctx, hostname):
    """Show OAuth server configuration for a proxy."""
    try:
        client = ctx.ensure_client()
        result = client.get_sync(f'/api/v1/proxy/targets/{hostname}/oauth-server')
        
        if result.get('status') == 'not_configured':
            console.print(f"[yellow]No custom OAuth server configuration for {hostname}[/yellow]")
        else:
            ctx.output(result.get('oauth_server_config', {}), 
                      title=f"OAuth Server Config: {hostname}")
    except Exception as e:
        ctx.handle_error(e)


@proxy_oauth_server.command('clear')
@click.argument('hostname')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def clear_oauth_server(ctx, hostname, force):
    """Clear OAuth server configuration for a proxy."""
    try:
        if not force:
            if not Confirm.ask(f"Clear OAuth server configuration for '{hostname}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/api/v1/proxy/targets/{hostname}/oauth-server')
        
        console.print(f"[green]OAuth server configuration cleared for {hostname}![/green]")
    except Exception as e:
        ctx.handle_error(e)


@proxy_oauth_server.command('list')
@click.pass_obj
def list_oauth_servers(ctx):
    """List proxies with custom OAuth server configurations."""
    try:
        client = ctx.ensure_client()
        result = client.get_sync('/api/v1/proxy/targets/oauth-servers/configured')
        
        if result.get('count', 0) == 0:
            console.print("[yellow]No proxies with custom OAuth server configurations[/yellow]")
        else:
            ctx.output(result.get('proxies', []), 
                      title="Proxies with OAuth Server Config")
    except Exception as e:
        ctx.handle_error(e)


# Additional proxy commands for missing endpoints

@proxy_group.command('list-formatted')
@click.pass_obj
def list_proxies_formatted(ctx):
    """List all proxy targets in formatted display."""
    try:
        client = ctx.ensure_client()
        formatted = client.get_sync('/api/v1/proxy/targets/formatted')
        
        # Formatted endpoint returns text, not JSON
        console.print(formatted)
    except Exception as e:
        ctx.handle_error(e)


@proxy_group.command('update')
@click.argument('hostname')
@click.option('--target-url', help='New target URL')
@click.option('--cert-name', help='Certificate to use')
@click.option('--preserve-host/--no-preserve-host', default=None, help='Preserve host header')
@click.option('--enable-http/--no-enable-http', default=None, help='Enable HTTP')
@click.option('--enable-https/--no-enable-https', default=None, help='Enable HTTPS')
@click.option('--custom-headers', help='Custom headers as JSON')
@click.option('--custom-response-headers', help='Custom response headers as JSON')
@click.pass_obj
def update_proxy(ctx, hostname, target_url, cert_name, preserve_host, enable_http, enable_https, custom_headers, custom_response_headers):
    """Update proxy configuration."""
    try:
        import json
        client = ctx.ensure_client()
        
        # Get current configuration
        current = client.get_sync(f'/api/v1/proxy/targets/{hostname}')
        
        # Build update data
        data = dict(current)
        
        if target_url:
            data['target_url'] = target_url
        if cert_name:
            data['cert_name'] = cert_name
        if preserve_host is not None:
            data['preserve_host_header'] = preserve_host
        if enable_http is not None:
            data['enable_http'] = enable_http
        if enable_https is not None:
            data['enable_https'] = enable_https
        if custom_headers:
            data['custom_headers'] = json.loads(custom_headers)
        if custom_response_headers:
            data['custom_response_headers'] = json.loads(custom_response_headers)
        
        result = client.put_sync(f'/api/v1/proxy/targets/{hostname}', data)
        
        console.print(f"[green]Proxy '{hostname}' updated successfully![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


# Route management for proxies

@proxy_group.group('routes')
def proxy_routes():
    """Manage proxy-specific routes."""
    pass


@proxy_routes.command('list')
@click.argument('hostname')
@click.pass_obj
def list_proxy_routes(ctx, hostname):
    """List routes for a specific proxy."""
    try:
        client = ctx.ensure_client()
        routes = client.get_sync(f'/api/v1/proxy/targets/{hostname}/routes')
        ctx.output(routes, title=f"Routes for proxy: {hostname}")
    except Exception as e:
        ctx.handle_error(e)


@proxy_routes.command('update')
@click.argument('hostname')
@click.option('--route-mode', type=click.Choice(['all', 'allowlist', 'denylist']), help='Route filtering mode')
@click.option('--enabled-routes', help='Comma-separated list of enabled route IDs')
@click.option('--disabled-routes', help='Comma-separated list of disabled route IDs')
@click.pass_obj
def update_proxy_routes(ctx, hostname, route_mode, enabled_routes, disabled_routes):
    """Update route configuration for a proxy."""
    try:
        client = ctx.ensure_client()
        
        # Get current proxy config
        proxy = client.get_sync(f'/api/v1/proxy/targets/{hostname}')
        
        data = {
            'route_mode': route_mode or proxy.get('route_mode', 'all'),
            'enabled_routes': enabled_routes.split(',') if enabled_routes else proxy.get('enabled_routes', []),
            'disabled_routes': disabled_routes.split(',') if disabled_routes else proxy.get('disabled_routes', [])
        }
        
        result = client.put_sync(f'/api/v1/proxy/targets/{hostname}/routes', data)
        
        console.print(f"[green]Routes updated for proxy '{hostname}'![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@proxy_routes.command('enable')
@click.argument('hostname')
@click.argument('route-id')
@click.pass_obj
def enable_proxy_route(ctx, hostname, route_id):
    """Enable a specific route for a proxy."""
    try:
        client = ctx.ensure_client()
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/routes/{route_id}/enable', {})
        
        console.print(f"[green]Route '{route_id}' enabled for proxy '{hostname}'![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


@proxy_routes.command('disable')
@click.argument('hostname')
@click.argument('route-id')
@click.pass_obj
def disable_proxy_route(ctx, hostname, route_id):
    """Disable a specific route for a proxy."""
    try:
        client = ctx.ensure_client()
        result = client.post_sync(f'/api/v1/proxy/targets/{hostname}/routes/{route_id}/disable', {})
        
        console.print(f"[green]Route '{route_id}' disabled for proxy '{hostname}'![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)