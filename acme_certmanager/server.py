"""FastAPI server with HTTPS support and ACME integration."""

import asyncio
import logging
import os
import ssl
import tempfile
import threading
from contextlib import asynccontextmanager
from typing import Dict, Optional, Union

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends, WebSocket
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from .unified_dispatcher import UnifiedMultiInstanceServer
import time
from datetime import datetime, timezone
from typing import Tuple

from .manager import CertificateManager
from .models import (
    CertificateRequest, Certificate, HealthStatus,
    ProxyTarget, ProxyTargetRequest, ProxyTargetUpdate
)
from .scheduler import CertificateScheduler
from .async_acme import create_certificate_task, get_generation_status
from .auth import get_current_token_info, require_owner, get_optional_token_info
from .proxy_handler_v2 import EnhancedProxyHandler as ProxyHandler

logger = logging.getLogger(__name__)


class HTTPSServer:
    """HTTPS server with dynamic certificate loading."""
    
    def __init__(self, manager: CertificateManager):
        """Initialize HTTPS server."""
        self.manager = manager
        self.ssl_contexts: Dict[str, ssl.SSLContext] = {}
        self.default_context: Optional[ssl.SSLContext] = None
        
    def create_ssl_context(self, certificate: Certificate) -> ssl.SSLContext:
        """Create SSL context from certificate."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Write certificate and key to temporary files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write(certificate.fullchain_pem)
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
            key_file.write(certificate.private_key_pem)
            key_path = key_file.name
        
        try:
            context.load_cert_chain(cert_path, key_path)
        finally:
            # Clean up temporary files
            os.unlink(cert_path)
            os.unlink(key_path)
        
        return context
    
    def load_certificates(self):
        """Load all certificates from storage."""
        certificates = self.manager.list_certificates()
        
        for certificate in certificates:
                if certificate.fullchain_pem and certificate.private_key_pem:
                    try:
                        context = self.create_ssl_context(certificate)
                        
                        # Store context for each domain
                        for domain in certificate.domains:
                            self.ssl_contexts[domain] = context
                            
                        logger.info(f"Loaded certificate for domains: {certificate.domains}")
                    except Exception as e:
                        logger.error(f"Failed to load certificate {certificate.cert_name}: {e}")
        
        # Create default self-signed certificate if no certificates loaded
        if not self.ssl_contexts:
            self.create_self_signed_default()
    
    def create_self_signed_default(self):
        """Create self-signed certificate for fallback."""
        try:
            # Generate self-signed certificate using cryptography
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from datetime import datetime, timedelta, timezone
            
            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=int(os.getenv('RSA_KEY_SIZE')),
            )
            
            # Generate certificate
            cn = os.getenv('SELF_SIGNED_CN')
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=int(os.getenv('SELF_SIGNED_DAYS')))
            ).sign(key, hashes.SHA256())
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as cert_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                cert_path = cert_file.name
            
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False) as key_file:
                key_file.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                key_path = key_file.name
            
            try:
                context.load_cert_chain(cert_path, key_path)
                self.default_context = context
                logger.info("Created self-signed default certificate")
            finally:
                os.unlink(cert_path)
                os.unlink(key_path)
                
        except Exception as e:
            logger.error(f"Failed to create self-signed certificate: {e}")
    
    def update_ssl_context(self, certificate: Certificate):
        """Update SSL context for certificate domains."""
        try:
            context = self.create_ssl_context(certificate)
            
            for domain in certificate.domains:
                self.ssl_contexts[domain] = context
                
            logger.info(f"Updated SSL context for domains: {certificate.domains}")
        except Exception as e:
            logger.error(f"Failed to update SSL context: {e}")
    
    def remove_ssl_context(self, domains: list):
        """Remove SSL context for domains."""
        for domain in domains:
            if domain in self.ssl_contexts:
                del self.ssl_contexts[domain]
                logger.info(f"Removed SSL context for domain: {domain}")


# Global instances - initialized on startup
manager: Optional[CertificateManager] = None
https_server: Optional[HTTPSServer] = None
scheduler: Optional[CertificateScheduler] = None
proxy_handler: Optional[ProxyHandler] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting ACME Certificate Manager")
    
    # Initialize global instances
    global manager, https_server, scheduler, proxy_handler
    manager = CertificateManager()
    https_server = HTTPSServer(manager)
    scheduler = CertificateScheduler(manager)
    proxy_handler = ProxyHandler(manager.storage)
    
    # Load certificates
    https_server.load_certificates()
    
    # Start scheduler
    scheduler.start()
    
    yield
    
    # Shutdown
    logger.info("Shutting down ACME Certificate Manager")
    scheduler.stop()
    await proxy_handler.close()


# Create FastAPI app
app = FastAPI(
    title="ACME Certificate Manager",
    description="HTTPS server with automatic certificate management via ACME protocol",
    version="0.1.0",
    lifespan=lifespan
)

# Mount static files for web GUI
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


# Add middleware to log ALL requests
@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    """Log all incoming HTTP requests with full details."""
    start_time = time.time()
    
    # Log request details
    logger.info(f"\n{'='*60}")
    logger.info(f"INCOMING REQUEST:")
    logger.info(f"  Method: {request.method}")
    logger.info(f"  URL: {request.url}")
    logger.info(f"  Path: {request.url.path}")
    logger.info(f"  Client: {request.client}")
    logger.info(f"  Headers:")
    for name, value in request.headers.items():
        logger.info(f"    {name}: {value}")
    
    # Check if it's an ACME challenge request
    if request.url.path.startswith("/.well-known/acme-challenge/"):
        token = request.url.path.split("/")[-1]
        logger.info(f"  ACME Challenge Token: {token}")
        logger.info(f"  User-Agent indicates: {'Let\'s Encrypt' if 'Let' in request.headers.get('user-agent', '') else 'Other'}")
    
    # Process request
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(f"  Response Status: {response.status_code}")
        logger.info(f"  Process Time: {process_time*1000:.1f}ms")
        logger.info(f"{'='*60}\n")
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"  Request failed after {process_time*1000:.1f}ms: {e}")
        logger.error(f"{'='*60}\n")
        raise


# API Endpoints

@app.get("/")
async def read_root(request: Request):
    """Serve the web GUI or proxy root requests."""
    # Check if this is a proxy request by examining the Host header
    hostname = request.headers.get("host", "").split(":")[0]
    
    # Check if this hostname has a proxy target configured
    if hostname and manager.storage.get_proxy_target(hostname):
        # This is a proxy request, forward it
        return await proxy_handler.handle_request(request)
    
    # Otherwise, serve the web GUI
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.post("/certificates")
async def create_certificate(
    request: CertificateRequest,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Create new certificate via ACME."""
    token_hash, token_name, cert_email = token_info
    
    # Run certificate generation in background to avoid blocking
    result = await create_certificate_task(
        manager, request, https_server,
        owner_token_hash=token_hash,
        created_by=token_name
    )
    return result


@app.get("/certificates")
async def list_certificates(
    token_info: Optional[Tuple[str, Optional[str], Optional[str]]] = Depends(get_optional_token_info)
):
    """List certificates - all if no auth, filtered if authenticated."""
    all_certs = manager.list_certificates()
    
    if token_info:
        # Authenticated - show only owned certificates
        token_hash, _, _ = token_info
        return [cert for cert in all_certs if cert.owner_token_hash == token_hash]
    else:
        # Not authenticated - show all certificates
        return all_certs


@app.get("/certificates/{cert_name}/status")
async def get_certificate_status(cert_name: str):
    """Get status of certificate generation."""
    return get_generation_status(cert_name)


@app.get("/certificates/{cert_name}", response_model=Certificate)
async def get_certificate(cert_name: str):
    """Get certificate by name - public access."""
    certificate = manager.get_certificate(cert_name)
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return certificate


@app.post("/certificates/{cert_name}/renew", 
          response_model=Certificate,
          dependencies=[Depends(require_owner)])
async def renew_certificate(cert_name: str, background_tasks: BackgroundTasks):
    """Renew certificate (owner only)."""
    try:
        certificate = manager.renew_certificate(cert_name)
        if not certificate:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Update SSL context in background
        background_tasks.add_task(https_server.update_ssl_context, certificate)
        
        return certificate
    except Exception as e:
        logger.error(f"Failed to renew certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/certificates/{cert_name}/domains/{domain}",
            dependencies=[Depends(require_owner)])
async def remove_domain(cert_name: str, domain: str, background_tasks: BackgroundTasks):
    """Remove domain from certificate (owner only)."""
    try:
        certificate = manager.remove_domain_from_certificate(cert_name, domain)
        
        if certificate:
            # Update SSL context in background
            background_tasks.add_task(https_server.update_ssl_context, certificate)
            return certificate
        else:
            # Certificate was deleted (no domains left)
            background_tasks.add_task(https_server.remove_ssl_context, [domain])
            return {"message": "Certificate deleted (no domains remaining)"}
            
    except Exception as e:
        logger.error(f"Failed to remove domain: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
async def acme_challenge(request: Request, token: str):
    """ACME HTTP-01 challenge endpoint."""
    logger.info(f"Challenge endpoint called for token: {token}")
    logger.info(f"Request from: {request.client}")
    logger.info(f"User-Agent: {request.headers.get('user-agent', 'None')}")
    
    authorization = manager.get_challenge_response(token)
    if not authorization:
        logger.warning(f"Challenge not found for token: {token}")
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    logger.info(f"Found authorization, returning: {authorization[:50]}...")
    return authorization


@app.get("/health", response_model=HealthStatus)
async def health_check():
    """Health check endpoint."""
    health = manager.check_health()
    
    # Determine overall status
    status = "healthy"
    if health["redis"] != "healthy":
        status = "degraded"
    elif health.get("orphaned_resources", 0) > 0:
        status = "degraded"
    
    return HealthStatus(
        status=status,
        scheduler=scheduler.is_running(),
        redis=health["redis"],
        certificates_loaded=health["certificates_loaded"],
        https_enabled=True,  # HTTPS is enabled
        orphaned_resources=health.get("orphaned_resources", 0)
    )


# Token management endpoints
@app.put("/token/email")
async def update_token_email(
    request: Request,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Update the certificate email for the current token."""
    token_hash, token_name, current_email = token_info
    
    # Parse request body
    try:
        body = await request.json()
        new_email = body.get("cert_email")
        
        if not new_email:
            raise HTTPException(400, "cert_email is required")
        
        # Basic email validation
        if "@" not in new_email:
            raise HTTPException(400, "Invalid email format")
        
    except Exception as e:
        raise HTTPException(400, f"Invalid request body: {str(e)}")
    
    # Update token email
    if manager.storage.update_api_token_email(token_hash, new_email):
        logger.info(f"Updated cert_email for token {token_name} to {new_email}")
        return {
            "status": "success",
            "message": f"Certificate email updated to {new_email}",
            "cert_email": new_email
        }
    else:
        raise HTTPException(500, "Failed to update certificate email")


@app.get("/token/info")
async def get_token_info(
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Get information about the current token."""
    token_hash, token_name, cert_email = token_info
    
    return {
        "name": token_name,
        "cert_email": cert_email,
        "hash_preview": token_hash[:16] + "..."
    }


# Proxy management endpoints
@app.post("/proxy/targets",
          dependencies=[Depends(get_current_token_info)])
async def create_proxy_target(
    request: ProxyTargetRequest,
    background_tasks: BackgroundTasks,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Create new proxy target with automatic certificate generation."""
    token_hash, token_name, cert_email = token_info
    
    # Check if target already exists
    existing = manager.storage.get_proxy_target(request.hostname)
    if existing:
        raise HTTPException(409, f"Proxy target for {request.hostname} already exists")
    
    # Create proxy target
    cert_name = f"proxy-{request.hostname.replace('.', '-')}"
    target = ProxyTarget(
        hostname=request.hostname,
        target_url=request.target_url,
        cert_name=cert_name,
        owner_token_hash=token_hash,
        created_by=token_name,
        created_at=datetime.now(timezone.utc),
        enabled=True,
        enable_http=request.enable_http,
        enable_https=request.enable_https,
        preserve_host_header=request.preserve_host_header,
        custom_headers=request.custom_headers
    )
    
    # Store proxy target
    if not manager.storage.store_proxy_target(request.hostname, target):
        raise HTTPException(500, "Failed to store proxy target")
    
    # Check if certificate exists and HTTPS is enabled
    cert_status = "not_required"
    if request.enable_https:
        cert = manager.get_certificate(cert_name)
        if not cert:
            # Create certificate request
            # Use provided ACME URL or default to staging for tests
            acme_url = request.acme_directory_url or os.getenv("ACME_STAGING_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")
            
            # Use token's cert_email if not provided in request
            email = request.cert_email if request.cert_email else cert_email
            if not email:
                raise HTTPException(400, "Certificate email required - provide in request or configure in token")
            
            cert_request = CertificateRequest(
                domain=request.hostname,
                email=email,
                cert_name=cert_name,
                acme_directory_url=acme_url
            )
            
            # Trigger async certificate generation
            result = await create_certificate_task(
                manager, cert_request, https_server,
                owner_token_hash=token_hash,
                created_by=token_name
            )
            cert_status = result["message"]
        else:
            cert_status = "existing"
    else:
        logger.info(f"HTTPS disabled for {request.hostname}, skipping certificate generation")
        
    return {
        "proxy_target": target,
        "certificate_status": cert_status,
        "cert_name": cert_name if request.enable_https else None
    }


@app.get("/proxy/targets")
async def list_proxy_targets(
    token_info: Optional[Tuple[str, Optional[str], Optional[str]]] = Depends(get_optional_token_info)
):
    """List proxy targets - all if no auth, filtered if authenticated."""
    all_targets = manager.storage.list_proxy_targets()
    
    if token_info:
        # Authenticated - show only owned targets
        token_hash, _, _ = token_info
        return [target for target in all_targets if target.owner_token_hash == token_hash]
    else:
        # Not authenticated - show all targets
        return all_targets


@app.get("/proxy/targets/{hostname}")
async def get_proxy_target(hostname: str):
    """Get specific proxy target details - public access."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    return target


async def require_proxy_owner(
    hostname: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
) -> None:
    """Require current token to be proxy target owner."""
    token_hash, _, _ = token_info
    target = manager.storage.get_proxy_target(hostname)
    
    if not target:
        raise HTTPException(404, "Proxy target not found")
    
    if target.owner_token_hash != token_hash:
        raise HTTPException(403, "Not authorized to modify this proxy target")


@app.put("/proxy/targets/{hostname}",
         dependencies=[Depends(require_proxy_owner)])
async def update_proxy_target(
    hostname: str,
    updates: ProxyTargetUpdate
):
    """Update proxy target configuration - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Apply updates
    if updates.target_url is not None:
        target.target_url = updates.target_url
    if updates.enabled is not None:
        target.enabled = updates.enabled
    if updates.enable_http is not None:
        target.enable_http = updates.enable_http
    if updates.enable_https is not None:
        target.enable_https = updates.enable_https
    if updates.preserve_host_header is not None:
        target.preserve_host_header = updates.preserve_host_header
    if updates.custom_headers is not None:
        target.custom_headers = updates.custom_headers
    
    # Store updated target
    if not manager.storage.store_proxy_target(hostname, target):
        raise HTTPException(500, "Failed to update proxy target")
    
    return target


@app.delete("/proxy/targets/{hostname}",
            dependencies=[Depends(require_proxy_owner)])
async def delete_proxy_target(
    hostname: str,
    delete_certificate: bool = False
):
    """Delete proxy target and optionally its certificate - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Delete proxy target
    if not manager.storage.delete_proxy_target(hostname):
        raise HTTPException(500, "Failed to delete proxy target")
    
    # Optionally delete certificate
    if delete_certificate and target.cert_name:
        manager.delete_certificate(target.cert_name)
    
    return {"message": f"Proxy target {hostname} deleted successfully"}


# Catch-all proxy route - MUST be last
@app.api_route("/{path:path}", 
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
               include_in_schema=False)
async def proxy_request(request: Request, path: str):
    """Handle all unmatched requests as potential proxy targets."""
    return await proxy_handler.handle_request(request)


# WebSocket proxy route - also catch-all, must be after HTTP routes
@app.websocket("/{path:path}")
async def proxy_websocket(websocket: WebSocket, path: str):
    """Handle WebSocket connections for proxy targets."""
    await proxy_handler.handle_websocket(websocket, path)


def get_ssl_context(server_name: str) -> Optional[ssl.SSLContext]:
    """SNI callback to select SSL context by domain."""
    # Try exact match
    if server_name in https_server.ssl_contexts:
        return https_server.ssl_contexts[server_name]
    
    # Try wildcard match
    parts = server_name.split('.')
    if len(parts) > 2:
        wildcard = f"*.{'.'.join(parts[1:])}"
        if wildcard in https_server.ssl_contexts:
            return https_server.ssl_contexts[wildcard]
    
    # Return default context
    return https_server.default_context


def create_temp_cert_files():
    """Create temporary certificate files for uvicorn SSL."""
    # Generate self-signed certificate
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta
    
    # Generate key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(os.getenv('RSA_KEY_SIZE')),
    )
    
    # Generate certificate
    cn = os.getenv('SELF_SIGNED_CN')
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=int(os.getenv('SELF_SIGNED_DAYS')))
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
            x509.DNSName(os.getenv('SERVER_HOST')),
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    # Write to temp files
    cert_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False)
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.close()
    
    key_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False)
    key_file.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_file.close()
    
    return cert_file.name, key_file.name




def run_server():
    """Run unified server with multi-instance architecture."""
    http_port = int(os.getenv('HTTP_PORT'))
    https_port = int(os.getenv('HTTPS_PORT'))
    
    logger.info(f"Starting unified dispatcher on HTTP port {http_port} and HTTPS port {https_port}")
    logger.info("Each domain will have its own dedicated Hypercorn instance")
    
    # Initialize the global instances before running the server
    global manager, https_server, scheduler, proxy_handler
    if not manager:
        manager = CertificateManager()
    if not https_server:
        https_server = HTTPSServer(manager)
        https_server.load_certificates()
    if not scheduler:
        scheduler = CertificateScheduler(manager)
    if not proxy_handler:
        proxy_handler = ProxyHandler(manager.storage)
    
    async def run_servers():
        # Start scheduler
        scheduler.start()
        
        try:
            # Run unified multi-instance server with dispatchers for both HTTP and HTTPS
            unified_server = UnifiedMultiInstanceServer(
                https_server_instance=https_server,
                app=app,
                host=os.getenv('SERVER_HOST')
            )
            await unified_server.run()
        finally:
            scheduler.stop()
    
    asyncio.run(run_servers())


if __name__ == "__main__":
    run_server()