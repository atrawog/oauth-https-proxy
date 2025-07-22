"""FastAPI server with HTTPS support and ACME integration."""

import asyncio
import logging
import os
import ssl
import tempfile
import threading
from contextlib import asynccontextmanager
from typing import Dict, Optional, Union, List

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends, WebSocket
from fastapi.responses import PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from .unified_dispatcher import UnifiedMultiInstanceServer
import time
from datetime import datetime, timezone
from typing import Tuple

from .manager import CertificateManager
from .models import (
    CertificateRequest, MultiDomainCertificateRequest, Certificate, HealthStatus,
    ProxyTarget, ProxyTargetRequest, ProxyTargetUpdate, ProxyAuthConfig, ProxyRoutesConfig
)
from .routes import Route, RouteCreateRequest, RouteUpdateRequest, RouteTargetType
from .scheduler import CertificateScheduler
from .async_acme import create_certificate_task, create_multi_domain_certificate_task, get_generation_status
from .auth import (
    get_current_token_info, require_owner, get_optional_token_info,
    require_proxy_owner, require_route_owner
)
from .proxy_handler_v2 import EnhancedProxyHandler as ProxyHandler
from .oauth_status import create_oauth_status_router
from .resource_registry import MCPResourceRegistry

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
        """Load all certificates from storage with proxy-aware prioritization."""
        certificates = self.manager.list_certificates()
        
        # First pass: Load all certificates into a temporary structure
        cert_contexts = {}  # cert_name -> (context, domains)
        for certificate in certificates:
            if certificate.fullchain_pem and certificate.private_key_pem:
                try:
                    context = self.create_ssl_context(certificate)
                    cert_contexts[certificate.cert_name] = (context, certificate.domains)
                    logger.info(f"Loaded certificate {certificate.cert_name} for domains: {certificate.domains}")
                except Exception as e:
                    logger.error(f"Failed to load certificate {certificate.cert_name}: {e}")
        
        # Second pass: Check proxy configurations to determine which certificates to use
        proxy_targets = self.manager.storage.list_proxy_targets()
        domain_to_cert = {}  # domain -> cert_name mapping based on proxy config
        
        for proxy in proxy_targets:
            if proxy.cert_name and proxy.cert_name in cert_contexts:
                domain_to_cert[proxy.hostname] = proxy.cert_name
        
        # Third pass: Apply certificates with proxy preferences taking priority
        for cert_name, (context, domains) in cert_contexts.items():
            for domain in domains:
                # If this domain has a proxy preference, only use that certificate
                if domain in domain_to_cert:
                    if domain_to_cert[domain] == cert_name:
                        self.ssl_contexts[domain] = context
                        logger.info(f"Applied certificate {cert_name} to {domain} (proxy configured)")
                else:
                    # No proxy preference, apply if not already set
                    if domain not in self.ssl_contexts:
                        self.ssl_contexts[domain] = context
                        logger.info(f"Applied certificate {cert_name} to {domain} (no proxy preference)")
        
        logger.info(f"SSL contexts loaded for domains: {list(self.ssl_contexts.keys())}")
        
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
        """Update SSL context for certificate domains with proxy awareness."""
        try:
            context = self.create_ssl_context(certificate)
            
            # Check proxy configurations
            proxy_targets = self.manager.storage.list_proxy_targets()
            domain_to_cert = {}
            
            for proxy in proxy_targets:
                if proxy.cert_name:
                    domain_to_cert[proxy.hostname] = proxy.cert_name
            
            # Update contexts respecting proxy preferences
            for domain in certificate.domains:
                # Only update if this domain uses this certificate via proxy config
                # or if no proxy config exists for this domain
                if domain in domain_to_cert:
                    if domain_to_cert[domain] == certificate.cert_name:
                        self.ssl_contexts[domain] = context
                        logger.info(f"Updated SSL context for {domain} (proxy configured)")
                else:
                    # No proxy config, update if this cert contains the domain
                    self.ssl_contexts[domain] = context
                    logger.info(f"Updated SSL context for {domain} (no proxy preference)")
                    
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
resource_registry: Optional[MCPResourceRegistry] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting ACME Certificate Manager")
    
    # Initialize global instances
    global manager, https_server, scheduler, proxy_handler, oauth_router, resource_registry
    manager = CertificateManager()
    https_server = HTTPSServer(manager)
    scheduler = CertificateScheduler(manager)
    proxy_handler = ProxyHandler(manager.storage)
    resource_registry = MCPResourceRegistry(manager.storage.redis_client)
    
    # Create and add OAuth status router BEFORE catch-all routes
    oauth_router = create_oauth_status_router(manager.storage)
    app.include_router(oauth_router)
    
    # Register catch-all routes LAST to ensure all other routes take precedence
    @app.api_route("/{path:path}", 
                   methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                   include_in_schema=False)
    async def proxy_request(request: Request, path: str):
        """Handle all unmatched requests as potential proxy targets."""
        return await proxy_handler.handle_request(request)
    
    # WebSocket proxy route - also catch-all
    @app.websocket("/{path:path}")
    async def proxy_websocket(websocket: WebSocket, path: str):
        """Handle WebSocket connections for proxy targets."""
        await proxy_handler.handle_websocket(websocket, path)
    
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

# Add OAuth status router (will be initialized with storage during lifespan)
oauth_router = None


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
    
    # Otherwise redirect to the web GUI
    return RedirectResponse(url="/static/index.html", status_code=302)


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


@app.post("/certificates/multi-domain")
async def create_multi_domain_certificate(
    request: MultiDomainCertificateRequest,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Create multi-domain certificate via ACME."""
    token_hash, token_name, cert_email = token_info
    
    # Use token's cert_email if not provided in request
    if not request.email and cert_email:
        request.email = cert_email
    elif not request.email:
        raise HTTPException(400, "Email required for certificate generation")
    
    # Run certificate generation in background to avoid blocking
    result = await create_multi_domain_certificate_task(
        manager, request, https_server,
        owner_token_hash=token_hash,
        created_by=token_name
    )
    return result


@app.get("/certificates",
         dependencies=[Depends(get_current_token_info)])
async def list_certificates(
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """List certificates - filtered by ownership or all for admin."""
    all_certs = manager.list_certificates()
    
    token_hash, token_name, _ = token_info
    
    # Admin sees all certificates
    if token_name == "ADMIN":
        return all_certs
    
    # Regular users see only their own certificates
    return [cert for cert in all_certs if cert.owner_token_hash == token_hash]


@app.get("/certificates/{cert_name}/status",
         dependencies=[Depends(get_current_token_info)])
async def get_certificate_status(cert_name: str):
    """Get status of certificate generation."""
    return get_generation_status(cert_name)


@app.get("/certificates/{cert_name}", response_model=Certificate,
         dependencies=[Depends(get_current_token_info)])
async def get_certificate(cert_name: str):
    """Get certificate by name."""
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


@app.post("/certificates/{cert_name}/convert-to-production",
          dependencies=[Depends(require_owner)])
async def convert_to_production(cert_name: str, background_tasks: BackgroundTasks):
    """Convert certificate from staging to production (owner only)."""
    try:
        # Get existing certificate
        cert = manager.get_certificate(cert_name)
        if not cert:
            raise HTTPException(404, f"Certificate {cert_name} not found")
        
        # Check if already production
        if cert.acme_directory_url == os.getenv('ACME_DIRECTORY_URL'):
            raise HTTPException(400, "Certificate is already using production ACME")
        
        # Check if staging
        if cert.acme_directory_url != os.getenv('ACME_STAGING_URL'):
            raise HTTPException(400, "Certificate is not using staging ACME")
        
        logger.info(f"Converting certificate {cert_name} from staging to production")
        
        # Get ownership info from existing cert
        owner_token_hash = cert.owner_token_hash
        created_by = cert.created_by
        
        # Delete old staging certificate
        if not manager.delete_certificate(cert_name):
            raise HTTPException(500, "Failed to delete staging certificate")
        
        # Check if this is a multi-domain certificate
        if len(cert.domains) > 1:
            # Create multi-domain request for production certificate
            request = MultiDomainCertificateRequest(
                cert_name=cert_name,
                domains=cert.domains,
                email=cert.email,
                acme_directory_url=os.getenv('ACME_DIRECTORY_URL')
            )
            
            # Generate new production certificate asynchronously
            result = await create_multi_domain_certificate_task(
                manager,
                request, 
                https_server,
                owner_token_hash=owner_token_hash,
                created_by=created_by
            )
        else:
            # Create single-domain request for production certificate
            request = CertificateRequest(
                domain=cert.domains[0],  # Primary domain
                email=cert.email,
                cert_name=cert_name,
                acme_directory_url=os.getenv('ACME_DIRECTORY_URL')
            )
            
            # Generate new production certificate asynchronously
            result = await create_certificate_task(
                manager,  # Correct order - manager first
                request, 
                https_server,
                owner_token_hash=owner_token_hash,
                created_by=created_by
            )
        
        return result  # Return the actual result from create_certificate_task
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to convert certificate to production: {e}")
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
            # Use provided ACME URL or get from environment
            acme_url = request.acme_directory_url
            if not acme_url:
                acme_url = os.getenv("ACME_STAGING_URL")
                if not acme_url:
                    raise HTTPException(400, "ACME directory URL required - provide in request or set ACME_STAGING_URL in environment")
            
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
    
    # Create instance for the proxy
    from .unified_dispatcher import unified_server_instance
    logger.info(f"Attempting to create instance for {request.hostname}, unified_server_instance: {unified_server_instance}")
    if unified_server_instance:
        try:
            await unified_server_instance.create_instance_for_proxy(request.hostname)
            logger.info(f"Instance creation initiated for {request.hostname}")
        except Exception as e:
            logger.error(f"Failed to create instance for {request.hostname}: {e}")
    else:
        logger.warning("Unified server not yet initialized, instance will be created on restart")
        
    return {
        "proxy_target": target,
        "certificate_status": cert_status,
        "cert_name": cert_name if request.enable_https else None
    }


@app.get("/proxy/targets",
         dependencies=[Depends(get_current_token_info)])
async def list_proxy_targets(
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """List proxy targets - filtered by ownership or all for admin."""
    all_targets = manager.storage.list_proxy_targets()
    
    token_hash, token_name, _ = token_info
    
    # Admin sees all proxy targets
    if token_name == "ADMIN":
        return all_targets
    
    # Regular users see only their own targets
    return [target for target in all_targets if target.owner_token_hash == token_hash]


@app.get("/proxy/targets/{hostname}",
         dependencies=[Depends(get_current_token_info)])
async def get_proxy_target(hostname: str):
    """Get specific proxy target details."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    return target



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
    if updates.cert_name is not None:
        target.cert_name = updates.cert_name
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
    
    # Remove instance for the proxy
    from .unified_dispatcher import unified_server_instance
    if unified_server_instance:
        await unified_server_instance.remove_instance_for_proxy(hostname)
    
    # Optionally delete certificate
    if delete_certificate and target.cert_name:
        manager.delete_certificate(target.cert_name)
    
    return {"message": f"Proxy target {hostname} deleted successfully"}


# Proxy auth configuration endpoints
@app.post("/proxy/targets/{hostname}/auth",
          dependencies=[Depends(require_proxy_owner)])
async def configure_proxy_auth(
    hostname: str,
    config: ProxyAuthConfig,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Configure unified auth for a proxy target - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Validate auth proxy exists
    if config.auth_proxy:
        auth_target = manager.storage.get_proxy_target(config.auth_proxy)
        if not auth_target:
            raise HTTPException(400, f"Auth proxy {config.auth_proxy} not found")
    
    # Update auth configuration
    target.auth_enabled = config.enabled
    target.auth_proxy = config.auth_proxy
    target.auth_mode = config.mode
    target.auth_required_users = config.required_users
    target.auth_required_emails = config.required_emails
    target.auth_required_groups = config.required_groups
    target.auth_pass_headers = config.pass_headers
    target.auth_cookie_name = config.cookie_name
    target.auth_header_prefix = config.header_prefix
    
    # Store updated target
    if not manager.storage.store_proxy_target(hostname, target):
        raise HTTPException(500, "Failed to update proxy target")
    
    logger.info(f"Auth configured for proxy {hostname}: enabled={config.enabled}, proxy={config.auth_proxy}, mode={config.mode}")
    
    return {"status": "Auth configured", "proxy_target": target}


@app.delete("/proxy/targets/{hostname}/auth",
            dependencies=[Depends(require_proxy_owner)])
async def remove_proxy_auth(
    hostname: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Disable auth protection for a proxy target - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Disable auth
    target.auth_enabled = False
    target.auth_proxy = None
    target.auth_required_users = None
    target.auth_required_emails = None
    target.auth_required_groups = None
    
    # Store updated target
    if not manager.storage.store_proxy_target(hostname, target):
        raise HTTPException(500, "Failed to update proxy target")
    
    logger.info(f"Auth disabled for proxy {hostname}")
    
    return {"status": "Auth protection removed", "proxy_target": target}


@app.get("/proxy/targets/{hostname}/auth")
async def get_proxy_auth_config(
    hostname: str,
    token_info: Optional[Tuple[str, Optional[str], Optional[str]]] = Depends(get_optional_token_info)
):
    """Get auth configuration for a proxy target."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Return auth configuration
    return {
        "auth_enabled": target.auth_enabled,
        "auth_proxy": target.auth_proxy,
        "auth_mode": target.auth_mode,
        "auth_required_users": target.auth_required_users,
        "auth_required_emails": target.auth_required_emails,
        "auth_required_groups": target.auth_required_groups,
        "auth_pass_headers": target.auth_pass_headers,
        "auth_cookie_name": target.auth_cookie_name,
        "auth_header_prefix": target.auth_header_prefix
    }


# Proxy-specific route management endpoints
@app.get("/proxy/targets/{hostname}/routes",
         dependencies=[Depends(get_current_token_info)])
async def get_proxy_routes(
    hostname: str,
    token_info: Optional[Tuple[str, Optional[str], Optional[str]]] = Depends(get_optional_token_info)
):
    """Get route configuration for a proxy target."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Get all routes and filter applicable ones
    all_routes = manager.storage.list_routes()
    
    # Determine applicable routes based on route_mode
    if target.route_mode == "none":
        applicable_routes = []
    elif target.route_mode == "selective":
        applicable_routes = [r for r in all_routes if r.route_id in target.enabled_routes]
    else:  # route_mode == "all"
        applicable_routes = [r for r in all_routes if r.route_id not in target.disabled_routes]
    
    return {
        "route_mode": target.route_mode,
        "enabled_routes": target.enabled_routes,
        "disabled_routes": target.disabled_routes,
        "applicable_routes": applicable_routes
    }


@app.put("/proxy/targets/{hostname}/routes",
         dependencies=[Depends(require_proxy_owner)])
async def update_proxy_routes(
    hostname: str,
    config: ProxyRoutesConfig,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Update route settings for a proxy target - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Update proxy target
    updates = ProxyTargetUpdate(
        route_mode=config.route_mode,
        enabled_routes=config.enabled_routes,
        disabled_routes=config.disabled_routes
    )
    
    if not manager.storage.update_proxy_target(hostname, updates):
        raise HTTPException(500, "Failed to update proxy routes")
    
    # Get updated target
    target = manager.storage.get_proxy_target(hostname)
    
    logger.info(f"Routes updated for proxy {hostname}: mode={config.route_mode}")
    
    return {"status": "Routes configured", "proxy_target": target}


@app.post("/proxy/targets/{hostname}/routes/{route_id}/enable",
          dependencies=[Depends(require_proxy_owner)])
async def enable_proxy_route(
    hostname: str,
    route_id: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Enable a specific route for a proxy target - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Verify route exists
    route = manager.storage.get_route(route_id)
    if not route:
        raise HTTPException(404, f"Route {route_id} not found")
    
    # Update based on route_mode
    updates = ProxyTargetUpdate()
    
    if target.route_mode == "selective":
        # Add to enabled_routes
        if route_id not in target.enabled_routes:
            enabled_routes = target.enabled_routes.copy()
            enabled_routes.append(route_id)
            updates.enabled_routes = enabled_routes
    elif target.route_mode == "all":
        # Remove from disabled_routes
        if route_id in target.disabled_routes:
            disabled_routes = target.disabled_routes.copy()
            disabled_routes.remove(route_id)
            updates.disabled_routes = disabled_routes
    else:
        raise HTTPException(400, "Cannot enable routes when route_mode is 'none'")
    
    if not manager.storage.update_proxy_target(hostname, updates):
        raise HTTPException(500, "Failed to enable route")
    
    logger.info(f"Route {route_id} enabled for proxy {hostname}")
    
    return {"status": "Route enabled", "route_id": route_id}


@app.post("/proxy/targets/{hostname}/routes/{route_id}/disable",
          dependencies=[Depends(require_proxy_owner)])
async def disable_proxy_route(
    hostname: str,
    route_id: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Disable a specific route for a proxy target - owner only."""
    target = manager.storage.get_proxy_target(hostname)
    if not target:
        raise HTTPException(404, f"Proxy target {hostname} not found")
    
    # Verify route exists
    route = manager.storage.get_route(route_id)
    if not route:
        raise HTTPException(404, f"Route {route_id} not found")
    
    # Update based on route_mode
    updates = ProxyTargetUpdate()
    
    if target.route_mode == "selective":
        # Remove from enabled_routes
        if route_id in target.enabled_routes:
            enabled_routes = target.enabled_routes.copy()
            enabled_routes.remove(route_id)
            updates.enabled_routes = enabled_routes
    elif target.route_mode == "all":
        # Add to disabled_routes
        if route_id not in target.disabled_routes:
            disabled_routes = target.disabled_routes.copy()
            disabled_routes.append(route_id)
            updates.disabled_routes = disabled_routes
    else:
        raise HTTPException(400, "Cannot disable routes when route_mode is 'none'")
    
    if not manager.storage.update_proxy_target(hostname, updates):
        raise HTTPException(500, "Failed to disable route")
    
    logger.info(f"Route {route_id} disabled for proxy {hostname}")
    
    return {"status": "Route disabled", "route_id": route_id}


# Route management endpoints
@app.post("/routes",
          dependencies=[Depends(get_current_token_info)])
async def create_route(
    request: RouteCreateRequest,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
):
    """Create a new routing rule."""
    token_hash, token_name, _ = token_info
    
    # Generate unique route ID
    import uuid
    route_id = f"{request.path_pattern.replace('/', '-').strip('-')}-{uuid.uuid4().hex[:8]}"
    
    # Create route
    route = Route(
        route_id=route_id,
        path_pattern=request.path_pattern,
        target_type=request.target_type,
        target_value=request.target_value,
        priority=request.priority,
        methods=request.methods,
        is_regex=request.is_regex,
        description=request.description,
        enabled=request.enabled,
        owner_token_hash=token_hash,
        created_by=token_name
    )
    
    # Store in Redis
    if not manager.storage.store_route(route):
        raise HTTPException(500, "Failed to store route")
    
    return route


@app.get("/routes",
         dependencies=[Depends(get_current_token_info)])
async def list_routes():
    """List all routing rules sorted by priority."""
    routes = manager.storage.list_routes()
    return routes


@app.get("/routes/{route_id}",
         dependencies=[Depends(get_current_token_info)])
async def get_route(route_id: str):
    """Get specific route details."""
    route = manager.storage.get_route(route_id)
    if not route:
        raise HTTPException(404, f"Route {route_id} not found")
    return route


@app.put("/routes/{route_id}",
         dependencies=[Depends(require_route_owner)])
async def update_route(
    route_id: str,
    request: RouteUpdateRequest
):
    """Update an existing route."""
    # Get existing route
    route = manager.storage.get_route(route_id)
    if not route:
        raise HTTPException(404, f"Route {route_id} not found")
    
    # Update fields
    update_data = request.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(route, field, value)
    
    # Re-validate if pattern changed
    if request.path_pattern is not None or request.is_regex is not None:
        try:
            # This will trigger validation
            route = Route(**route.dict())
        except Exception as e:
            raise HTTPException(400, f"Invalid route configuration: {e}")
    
    # Update priority index if priority changed
    if request.priority is not None:
        # Delete old priority index
        manager.storage.delete_route(route_id)
    
    # Store updated route
    if not manager.storage.store_route(route):
        raise HTTPException(500, "Failed to update route")
    
    return route


@app.delete("/routes/{route_id}",
            dependencies=[Depends(require_route_owner)])
async def delete_route(
    route_id: str
):
    """Delete a route."""
    route = manager.storage.get_route(route_id)
    if not route:
        raise HTTPException(404, f"Route {route_id} not found")
    
    if not manager.storage.delete_route(route_id):
        raise HTTPException(500, "Failed to delete route")
    
    return {"message": f"Route {route_id} deleted successfully"}


# MCP Resource Registry endpoints (RFC 8707 Resource Indicators)
@app.post("/resources",
          dependencies=[Depends(get_current_token_info)])
async def register_resource(
    resource_uri: str,
    proxy_hostname: str,
    name: str,
    scopes: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Union[str, int, bool]]] = None
):
    """Register an MCP resource for OAuth audience validation."""
    resource = await resource_registry.register_resource(
        resource_uri=resource_uri,
        proxy_hostname=proxy_hostname,
        name=name,
        scopes=scopes,
        metadata=metadata
    )
    return resource


@app.get("/resources",
         dependencies=[Depends(get_current_token_info)])
async def list_resources():
    """List all registered MCP resources."""
    resources = await resource_registry.list_resources()
    return {"resources": resources}


@app.get("/resources/{resource_uri:path}",
         dependencies=[Depends(get_current_token_info)])
async def get_resource(resource_uri: str):
    """Get a specific MCP resource."""
    # Reconstruct full URI (FastAPI path params don't include protocol)
    if not resource_uri.startswith(("http://", "https://")):
        resource_uri = f"https://{resource_uri}"
    
    resource = await resource_registry.get_resource(resource_uri)
    if not resource:
        raise HTTPException(404, f"Resource {resource_uri} not found")
    return resource


@app.put("/resources/{resource_uri:path}",
         dependencies=[Depends(get_current_token_info)])
async def update_resource(
    resource_uri: str,
    updates: Dict[str, Union[str, int, bool, List[str]]]
):
    """Update an MCP resource."""
    # Reconstruct full URI
    if not resource_uri.startswith(("http://", "https://")):
        resource_uri = f"https://{resource_uri}"
    
    resource = await resource_registry.update_resource(resource_uri, updates)
    if not resource:
        raise HTTPException(404, f"Resource {resource_uri} not found")
    return resource


@app.delete("/resources/{resource_uri:path}",
            dependencies=[Depends(get_current_token_info)])
async def delete_resource(resource_uri: str):
    """Delete an MCP resource."""
    # Reconstruct full URI
    if not resource_uri.startswith(("http://", "https://")):
        resource_uri = f"https://{resource_uri}"
    
    if not await resource_registry.delete_resource(resource_uri):
        raise HTTPException(404, f"Resource {resource_uri} not found")
    
    return {"message": f"Resource {resource_uri} deleted successfully"}


@app.post("/resources/auto-register",
          dependencies=[Depends(get_current_token_info)])
async def auto_register_resources():
    """Auto-register MCP resources from existing proxy targets."""
    count = await resource_registry.auto_register_proxy_resources()
    return {
        "message": f"Auto-registered {count} MCP resources",
        "count": count
    }


@app.post("/resources/{resource_uri:path}/validate-token",
          dependencies=[Depends(get_current_token_info)])
async def validate_token_for_resource(
    resource_uri: str,
    token_audience: List[str],
    required_scope: Optional[str] = None
):
    """Validate if a token audience is valid for a resource."""
    # Reconstruct full URI
    if not resource_uri.startswith(("http://", "https://")):
        resource_uri = f"https://{resource_uri}"
    
    valid = await resource_registry.validate_token_for_resource(
        resource_uri=resource_uri,
        token_audience=token_audience,
        required_scope=required_scope
    )
    
    return {
        "resource": resource_uri,
        "valid": valid,
        "audience": token_audience,
        "scope": required_scope
    }


# Note: Catch-all routes are registered in lifespan to ensure they come after all other routes


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
    global manager, https_server, scheduler, proxy_handler, resource_registry
    if not manager:
        manager = CertificateManager()
    if not https_server:
        https_server = HTTPSServer(manager)
        https_server.load_certificates()
    if not scheduler:
        scheduler = CertificateScheduler(manager)
    if not proxy_handler:
        proxy_handler = ProxyHandler(manager.storage)
    if not resource_registry:
        resource_registry = MCPResourceRegistry(manager.storage.redis_client)
    
    async def run_servers():
        # Start scheduler
        scheduler.start()
        
        try:
            # Run unified multi-instance server with dispatchers for both HTTP and HTTPS
            server_host = os.getenv('SERVER_HOST')
            if not server_host:
                raise ValueError("SERVER_HOST not set in environment - required for server configuration")
            
            unified_server = UnifiedMultiInstanceServer(
                https_server_instance=https_server,
                app=app,
                host=server_host
            )
            await unified_server.run()
        finally:
            scheduler.stop()
    
    asyncio.run(run_servers())


if __name__ == "__main__":
    run_server()