#!/usr/bin/env python3
"""Example of integrating generic OAuth flow into mcp-validate CLI."""

# This shows how to replace the current broken OAuth flow in cli.py
# with the generic flow that handles all environments

# CURRENT CODE (cli.py lines ~639-800):
# async def run_oauth_flow():
#     # ... discovery ...
#     
#     # Fixed OOB redirect - causes Chrome issues
#     auth_url, state, verifier = client.generate_authorization_url(
#         scope=scope,
#         resources=[mcp_server_url],
#     )
#     
#     # Manual code entry required
#     code = console.input("3. Enter the authorization code: ")


# REPLACEMENT CODE:
async def run_oauth_flow(mcp_server_url: str, scope: str, no_ssl_verify: bool, force: bool):
    """Enhanced OAuth flow using generic handler."""
    from mcp_http_validator import MCPValidator
    from mcp_http_validator.generic_oauth_flow import GenericOAuthFlow
    from mcp_http_validator.oauth_flow_config import OAuthFlowConfig
    
    env_manager = EnvManager()
    
    async with MCPValidator(
        mcp_server_url,
        verify_ssl=not no_ssl_verify,
    ) as validator:
        # Discover OAuth server
        console.print("[bold]Discovering OAuth server...[/bold]")
        auth_server_url = await validator.discover_oauth_server()
        
        if not auth_server_url:
            console.print("[red]No OAuth server found.[/red]")
            return
        
        console.print(f"[green]✓[/green] Found OAuth server: {auth_server_url}")
        
        # Check for existing valid token if not forcing
        if not force:
            valid_token = env_manager.get_valid_access_token(mcp_server_url)
            if valid_token:
                # Test if still valid
                console.print("[dim]Found existing token, testing...[/dim]")
                # ... test token ...
                if token_valid:
                    return
        
        # Use generic flow with auto-detection
        console.print("\n[bold]Starting OAuth authentication...[/bold]")
        
        # Create config (optional - defaults work for most cases)
        config = OAuthFlowConfig.from_environment()
        
        # For CLI, we want to try non-interactive first
        config.grant_preference = GrantPreference.CLI
        
        # Create generic flow handler
        flow = GenericOAuthFlow(
            mcp_server_url=mcp_server_url,
            auth_server_url=auth_server_url,
            config=config
        )
        
        # Run authentication - handles everything automatically
        token = await flow.authenticate(scope=scope, verify_ssl=not no_ssl_verify)
        
        if token:
            console.print("\n[green]✓[/green] Authentication successful!")
            console.print(f"[dim]Token: {token[:20]}...[/dim]")
            
            # Test with MCP server
            success = await test_token_with_server(mcp_server_url, token)
            if success:
                console.print("[green]✓[/green] Token validated with MCP server")
            else:
                console.print("[yellow]⚠[/yellow] Token not accepted by server")
        else:
            console.print("\n[red]✗[/red] Authentication failed")
            console.print("[dim]Check server logs for details[/dim]")


# The generic flow automatically handles:
# 1. Public IP detection (5.9.28.62) and callback server
# 2. Client credentials grant if available (no interaction)
# 3. Device flow if supported (user-friendly codes)
# 4. Authorization code with smart redirect URI
# 5. Fallback to OOB only as last resort

# Benefits over current implementation:
# - No "install app" prompt in Chrome
# - Works in Docker/K8s/cloud environments
# - Tries non-interactive grants first
# - Configurable via environment variables
# - Automatic browser opening (configurable)
# - Proper error handling and retries


# Quick test of the generic flow:
if __name__ == "__main__":
    import asyncio
    from mcp_http_validator.generic_oauth_flow import generic_oauth_flow
    from mcp_http_validator.oauth_flow_config import OAuthFlowConfig, RedirectStrategy, GrantPreference
    
    async def test():
        # Test with Cloudflare DNS
        token = await generic_oauth_flow(
            mcp_server_url="https://dns-analytics.mcp.cloudflare.com/sse",
            auth_server_url="https://dns-analytics.mcp.cloudflare.com",
            config=OAuthFlowConfig(
                # Force public IP callback (your server at 5.9.28.62)
                redirect_strategy=RedirectStrategy.PUBLIC_IP,
                # Allow all grant types
                allowed_grants=["client_credentials", "device_code", "authorization_code"],
                # Try non-interactive first
                grant_preference=GrantPreference.CLI
            )
        )
        
        if token:
            print(f"Success! Token: {token[:20]}...")
        else:
            print("Failed to authenticate")
    
    asyncio.run(test())