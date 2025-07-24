#!/usr/bin/env python3
import asyncio
from mcp_http_validator.generic_oauth_flow import GenericOAuthFlow
from mcp_http_validator.oauth_flow_config import OAuthFlowConfig, RedirectStrategy

async def test():
    mcp_url = "https://dns-analytics.mcp.cloudflare.com/sse"
    auth_url = "https://dns-analytics.mcp.cloudflare.com"
    
    # Create config to force public IP
    config = OAuthFlowConfig(
        redirect_strategy=RedirectStrategy.PUBLIC_IP,
        suppress_console=False,
        auto_open_browser=False  # Don't open browser for testing
    )
    
    print(f"Config: redirect_strategy={config.redirect_strategy}")
    
    # Create flow
    flow = GenericOAuthFlow(mcp_url, auth_url, config)
    
    # Test redirect URI determination
    redirect_uri = await flow._determine_redirect_uri()
    print(f"Determined redirect URI: {redirect_uri}")

asyncio.run(test())