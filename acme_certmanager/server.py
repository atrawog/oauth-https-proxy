"""FastAPI server with HTTPS support and ACME integration."""

import asyncio
import logging
import os
import ssl
import tempfile
from contextlib import asynccontextmanager
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import PlainTextResponse
import uvicorn

from .manager import CertificateManager
from .models import CertificateRequest, Certificate, HealthStatus
from .scheduler import CertificateScheduler

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
        
        for cert_dict in certificates:
            for cert_name, certificate in cert_dict.items():
                if certificate.fullchain_pem and certificate.private_key_pem:
                    try:
                        context = self.create_ssl_context(certificate)
                        
                        # Store context for each domain
                        for domain in certificate.domains:
                            self.ssl_contexts[domain] = context
                            
                        logger.info(f"Loaded certificate for domains: {certificate.domains}")
                    except Exception as e:
                        logger.error(f"Failed to load certificate {cert_name}: {e}")
        
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
                key_size=2048,
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
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
                datetime.now(timezone.utc) + timedelta(days=365)
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting ACME Certificate Manager")
    
    # Initialize global instances
    global manager, https_server, scheduler
    manager = CertificateManager()
    https_server = HTTPSServer(manager)
    scheduler = CertificateScheduler(manager)
    
    # Load certificates
    https_server.load_certificates()
    
    # Start scheduler
    scheduler.start()
    
    yield
    
    # Shutdown
    logger.info("Shutting down ACME Certificate Manager")
    scheduler.stop()


# Create FastAPI app
app = FastAPI(
    title="ACME Certificate Manager",
    description="HTTPS server with automatic certificate management via ACME protocol",
    version="0.1.0",
    lifespan=lifespan
)


# API Endpoints

@app.post("/certificates", response_model=Certificate)
async def create_certificate(request: CertificateRequest, background_tasks: BackgroundTasks):
    """Create new certificate via ACME."""
    try:
        certificate = manager.create_certificate(request)
        
        # Update SSL context in background
        background_tasks.add_task(https_server.update_ssl_context, certificate)
        
        return certificate
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Failed to create certificate: {type(e).__name__}: {e}")
        logger.error(f"Traceback:\n{error_details}")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")


@app.get("/certificates")
async def list_certificates():
    """List all certificates."""
    return manager.list_certificates()


@app.get("/certificates/{cert_name}", response_model=Certificate)
async def get_certificate(cert_name: str):
    """Get certificate by name."""
    certificate = manager.get_certificate(cert_name)
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return certificate


@app.post("/certificates/{cert_name}/renew", response_model=Certificate)
async def renew_certificate(cert_name: str, background_tasks: BackgroundTasks):
    """Renew certificate."""
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


@app.delete("/certificates/{cert_name}/domains/{domain}")
async def remove_domain(cert_name: str, domain: str, background_tasks: BackgroundTasks):
    """Remove domain from certificate."""
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
async def acme_challenge(token: str):
    """ACME HTTP-01 challenge endpoint."""
    logger.info(f"Challenge request for token: {token}")
    authorization = manager.get_challenge_response(token)
    if not authorization:
        logger.warning(f"Challenge not found for token: {token}")
        raise HTTPException(status_code=404, detail="Challenge not found")
    logger.info(f"Returning challenge authorization: {authorization[:50]}...")
    return authorization


@app.get("/health", response_model=HealthStatus)
async def health_check():
    """Health check endpoint."""
    health = manager.check_health()
    
    return HealthStatus(
        status="healthy" if health["redis"] == "healthy" else "degraded",
        scheduler=scheduler.is_running(),
        redis=health["redis"],
        certificates_loaded=health["certificates_loaded"],
        https_enabled=False  # Simplified to HTTP only for now
    )


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
        key_size=2048,
    )
    
    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
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
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
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
    """Run the HTTPS server."""
    http_port = int(os.getenv('HTTP_PORT', '80'))
    https_port = int(os.getenv('HTTPS_PORT', '443'))
    
    # For now, just run HTTP server for ACME challenges
    # HTTPS with dynamic certificates is complex with uvicorn
    # In production, use a reverse proxy like nginx for SSL termination
    
    logger.info(f"Starting HTTP server on port {http_port}")
    
    # HTTP server config
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=http_port,
        log_level=os.getenv('LOG_LEVEL', 'info').lower()
    )
    
    server = uvicorn.Server(config)
    
    # Run server
    asyncio.run(server.serve())


if __name__ == "__main__":
    run_server()