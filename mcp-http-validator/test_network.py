#!/usr/bin/env python3
import asyncio
from mcp_http_validator.network_utils import NetworkInfo, get_best_redirect_uri

async def test():
    public_ip = await NetworkInfo.detect_public_ip()
    print(f'Public IP: {public_ip}')
    redirect_uri, server = await get_best_redirect_uri()
    print(f'Best redirect URI: {redirect_uri}')
    if server:
        server.stop()

asyncio.run(test())