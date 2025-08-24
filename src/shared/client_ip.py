"""Helper to extract real client IP from request headers."""

from fastapi import Request


def get_real_client_ip(request: Request) -> str:
    """Get real client IP from headers or connection.
    
    Checks headers in priority order:
    1. CF-Connecting-IP (Cloudflare)
    2. True-Client-IP (Cloudflare Enterprise)
    3. X-Real-IP (PROXY protocol/nginx)
    4. X-Forwarded-For (standard proxy - first IP)
    5. X-Original-Forwarded-For (some proxies)
    6. X-Client-IP (general proxy)
    7. Forwarded (RFC 7239 standard)
    8. request.client.host (fallback)
    """
    # Priority order for IP extraction
    headers_to_check = [
        'cf-connecting-ip',      # Cloudflare
        'true-client-ip',        # Cloudflare Enterprise
        'x-real-ip',            # PROXY protocol/nginx
        'x-forwarded-for',      # Standard proxy (first IP in chain)
        'x-original-forwarded-for',  # Some proxies
        'x-client-ip',          # General proxy
        'forwarded',            # RFC 7239 standard
    ]
    
    for header in headers_to_check:
        value = request.headers.get(header)
        if value:
            # Handle X-Forwarded-For with multiple IPs
            if header == 'x-forwarded-for' and ',' in value:
                ip = value.split(',')[0].strip()
            # Handle Forwarded header (RFC 7239)
            elif header == 'forwarded':
                # Parse "for=192.0.2.60;proto=http;by=203.0.113.43"
                ip = None
                for part in value.split(';'):
                    if part.strip().startswith('for='):
                        ip = part.split('=')[1].strip('"[]')
                        # Remove port if present (IPv4 or IPv6)
                        if '[' in ip and ']:' in ip:
                            # IPv6 with port: [2001:db8::1]:8080
                            ip = ip.split(']:')[0].strip('[')
                        elif ':' in ip and ip.count(':') == 1:
                            # IPv4 with port: 192.0.2.60:8080
                            ip = ip.split(':')[0]
                        break
                if not ip:
                    continue
            else:
                ip = value.strip()
            
            # Validate and return if valid IP
            if ip and ip not in ['unknown', '127.0.0.1', 'localhost']:
                return ip
    
    # Fallback to connection info
    if request.client:
        return request.client.host
    
    return "unknown"