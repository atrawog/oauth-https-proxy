"""ACME protocol client implementation."""

import logging
import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import josepy as jose
from acme import client, challenges, messages, crypto_util, errors
from acme.challenges import HTTP01Response
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .models import Certificate

logger = logging.getLogger(__name__)


class ACMEClient:
    """ACME protocol client for certificate management."""
    
    def __init__(self, storage):
        """Initialize ACME client with storage backend."""
        self.storage = storage
        from ..shared.config import Config
        self.account_key_size = Config.RSA_KEY_SIZE
        self.cert_key_size = Config.RSA_KEY_SIZE
        
        # Initialize sync Redis client for use in sync context
        import redis
        import os
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self._sync_redis = redis.from_url(redis_url, decode_responses=True)
    
    def _generate_rsa_key(self, key_size: int) -> Tuple[rsa.RSAPrivateKey, str]:
        """Generate RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        return private_key, private_pem
    
    def _get_or_create_account_key(self, provider: str, email: str) -> jose.JWKRSA:
        """Get existing or create new account key."""
        # Extract provider name from URL
        parsed = urlparse(provider)
        provider_name = parsed.hostname.replace('.', '_')
        
        # Use sync Redis directly to avoid event loop issues
        account_key_name = f"acme:account:{provider_name}:{email}"
        key_pem = self._sync_redis.get(account_key_name)
        
        if key_pem:
            private_key = serialization.load_pem_private_key(
                key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            return jose.JWKRSA(key=private_key)
        
        # Generate new key
        private_key, private_pem = self._generate_rsa_key(self.account_key_size)
        
        # Store key using sync Redis
        self._sync_redis.set(account_key_name, private_pem)
        
        # Convert to JWKRSA for ACME
        return jose.JWKRSA(key=private_key)
    
    def _create_acme_client(self, directory_url: str, account_key: jose.JWKRSA) -> client.ClientV2:
        """Create ACME client instance."""
        net = client.ClientNetwork(account_key)
        directory = messages.Directory.from_json(net.get(directory_url).json())
        return client.ClientV2(directory, net=net)
    
    def _register_or_login(self, acme_client: client.ClientV2, email: str) -> messages.RegistrationResource:
        """Register new account or login with existing."""
        try:
            # Try to register new account
            # Create registration with contacts list
            logger.info(f"Attempting to register ACME account for email: {email}")
            new_reg = messages.NewRegistration(
                contact=(f"mailto:{email}",),
                terms_of_service_agreed=True
            )
            logger.info(f"Registration object created with contact: {new_reg.contact}")
            regr = acme_client.new_account(new_reg)
            logger.info(f"Registered new ACME account for {email}")
            return regr
        except errors.ConflictError as e:
            # Account already exists, need to find it
            # The Location header in the ConflictError contains the account URI
            logger.info(f"Account already exists for {email}, retrieving it")
            
            # Query existing registration
            regr = messages.RegistrationResource(
                body=messages.Registration(key=acme_client.net.key.public_key()),
                uri=str(e.location) if hasattr(e, 'location') else None
            )
            
            # Update the registration to get current info
            updated_regr = acme_client.query_registration(regr)
            logger.info(f"Using existing ACME account for {email}")
            return updated_regr
    
    def generate_certificate(
        self,
        domains: List[str],
        email: str,
        acme_directory_url: str,
        cert_name: str,
        created_by: str = None
    ) -> Certificate:
        """Generate certificate using ACME protocol."""
        logger.info(f"Generating certificate for domains: {domains}")
        
        # Get or create account key - returns jose.JWKRSA
        account_jwk = self._get_or_create_account_key(acme_directory_url, email)
        
        # Create ACME client
        acme_client = self._create_acme_client(acme_directory_url, account_jwk)
        
        # Register or login
        registration = self._register_or_login(acme_client, email)
        
        # Generate certificate key
        cert_key, cert_key_pem = self._generate_rsa_key(self.cert_key_size)
        
        # Create CSR
        csr = self._create_csr(cert_key, domains)
        
        # Create order
        order = acme_client.new_order(csr)
        
        # Process challenges
        for auth in order.authorizations:
            self._process_authorization(acme_client, auth)
        
        # Finalize order (challenges are already validated)
        order = acme_client.poll_and_finalize(order)
        
        # Get certificate
        fullchain_pem = order.fullchain_pem
        
        # Parse certificate for metadata
        cert_obj = x509.load_pem_x509_certificate(
            fullchain_pem.encode('utf-8'),
            default_backend()
        )
        
        # Calculate fingerprint
        fingerprint = f"sha256:{cert_obj.fingerprint(hashes.SHA256()).hex()}"
        
        # Create certificate object
        certificate = Certificate(
            cert_name=cert_name,
            domains=domains,
            email=email,
            acme_directory_url=acme_directory_url,
            status="active",
            expires_at=cert_obj.not_valid_after.replace(tzinfo=timezone.utc),
            issued_at=cert_obj.not_valid_before.replace(tzinfo=timezone.utc),
            fingerprint=fingerprint,
            fullchain_pem=fullchain_pem,
            private_key_pem=cert_key_pem,
            created_by=created_by
        )
        
        # Store certificate using sync Redis directly
        import json
        cert_key = f"cert:{cert_name}"
        cert_json = json.dumps({
            "cert_name": certificate.cert_name,
            "domains": certificate.domains,
            "email": certificate.email,
            "acme_directory_url": certificate.acme_directory_url,
            "status": certificate.status,
            "expires_at": certificate.expires_at.isoformat(),
            "issued_at": certificate.issued_at.isoformat(),
            "fingerprint": certificate.fingerprint,
            "fullchain_pem": certificate.fullchain_pem,
            "private_key_pem": certificate.private_key_pem,
            "created_by": certificate.created_by
        })
        
        if not self._sync_redis.set(cert_key, cert_json):
            logger.error(f"Failed to store certificate in Redis for {cert_name}")
            raise Exception(f"Failed to store certificate in Redis for {cert_name}")
        
        # Store domain mapping
        for domain in certificate.domains:
            self._sync_redis.set(f"cert:domain:{domain}", cert_name)
        
        # Verify certificate was stored
        if not self._sync_redis.exists(cert_key):
            logger.error(f"Certificate verification failed - not found in Redis after storage for {cert_name}")
            raise Exception(f"Certificate not found in Redis after storage for {cert_name}")
            
        logger.info(f"Certificate generated and stored successfully for {domains}")
        return certificate
    
    def _create_csr(self, private_key, domains: List[str]) -> bytes:
        """Create Certificate Signing Request in PEM format."""
        builder = x509.CertificateSigningRequestBuilder()
        
        # Add common name (first domain)
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0])
        ]))
        
        # Add all domains as SANs
        san_list = [x509.DNSName(domain) for domain in domains]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        
        # Sign CSR
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        
        # Return as PEM format (ACME expects PEM, not DER)
        return csr.public_bytes(serialization.Encoding.PEM)
    
    def _process_authorization(self, acme_client: client.ClientV2, authz: messages.AuthorizationResource):
        """Process authorization challenges."""
        # Find HTTP-01 challenge
        http_challenge = None
        for challenge in authz.body.challenges:
            if isinstance(challenge.chall, challenges.HTTP01):
                http_challenge = challenge
                break
        
        if not http_challenge:
            raise Exception("No HTTP-01 challenge found")
        
        # Get challenge response
        response, validation = http_challenge.chall.response_and_validation(acme_client.net.key)
        
        # Validate response object
        if not isinstance(response, HTTP01Response):
            raise Exception(f"Invalid response type: {type(response)}, expected HTTP01Response")
        
        # Store challenge in Redis
        # The token needs to be the base64url-encoded string, not raw bytes
        token = http_challenge.chall.encode('token')
        
        logger.info(f"Storing challenge token: {token}")
        logger.info(f"Challenge validation: {validation[:50]}...")
        logger.info(f"Response details: typ={getattr(response, 'typ', 'N/A')}, key_authorization={getattr(response, 'key_authorization', 'N/A')}")
        
        # Store challenge using sync Redis directly in the correct format
        import json
        from datetime import datetime, timedelta, timezone
        challenge_key = f"challenge:{token}"
        
        # Create challenge token object matching what the API expects
        challenge_data = {
            "token": token,
            "authorization": validation,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        }
        
        success = self._sync_redis.setex(challenge_key, 300, json.dumps(challenge_data))  # 5 minute TTL
        if not success:
            raise Exception("Failed to store challenge in Redis")
        
        # Verify storage
        stored = self._sync_redis.get(challenge_key)
        if not stored:
            raise Exception("Challenge not found after storage")
        logger.info(f"Challenge stored successfully, retrieved: {stored[:50]}...")
        
        # Answer challenge
        logger.info("Answering ACME challenge...")
        logger.info(f"  Challenge URI: {http_challenge.uri}")
        logger.info(f"  Challenge type: {http_challenge.chall.typ}")
        logger.info(f"  Response type: {type(response)}")
        logger.info(f"  Response content: {response}")
        
        # Add request/response logging to debug ACME protocol
        import json
        original_post = acme_client.net.post
        
        def logged_post(url, *args, **kwargs):
            logger.info(f"ACME POST to {url}")
            if args:
                logger.info(f"  Body: {args[0]}")
            result = original_post(url, *args, **kwargs)
            logger.info(f"  Response status: {result.status_code}")
            logger.info(f"  Response headers: {dict(result.headers)}")
            try:
                logger.info(f"  Response body: {result.json()}")
            except:
                logger.info(f"  Response body: {result.text}")
            return result
        
        # Temporarily patch the post method
        acme_client.net.post = logged_post
        
        try:
            acme_client.answer_challenge(http_challenge, response)
        finally:
            # Restore original method
            acme_client.net.post = original_post
        
        # Don't wait here - Let's Encrypt will validate when ready
        logger.info("Challenge answer submitted, Let's Encrypt will validate when ready")
        
        # Check status with shorter intervals to avoid blocking too long
        import os
        import time
        max_attempts_str = os.getenv("ACME_POLL_MAX_ATTEMPTS")
        if not max_attempts_str:
            raise ValueError("ACME_POLL_MAX_ATTEMPTS not set in environment - required for ACME polling")
        max_attempts = int(max_attempts_str)
        
        poll_interval_str = os.getenv("ACME_POLL_INTERVAL_SECONDS")
        if not poll_interval_str:
            raise ValueError("ACME_POLL_INTERVAL_SECONDS not set in environment - required for ACME polling")
        poll_interval = int(poll_interval_str)
        
        logger.info("Checking authorization status...")
        for attempt in range(max_attempts):
            try:
                # Refresh the authorization status
                authz_resource = acme_client.net.get(authz.uri)
                authz = messages.AuthorizationResource(
                    body=messages.Authorization.from_json(authz_resource.json()),
                    uri=authz.uri
                )
                
                status = authz.body.status
                logger.info(f"Authorization status: {status} (attempt {attempt + 1}/{max_attempts})")
                
                if status == messages.STATUS_VALID:
                    logger.info("Authorization validated successfully!")
                    return
                elif status == messages.STATUS_INVALID:
                    # Get detailed error information
                    logger.error(f"Authorization invalid! Full details:")
                    logger.error(f"  Authorization URI: {authz.uri}")
                    logger.error(f"  Domain: {authz.body.identifier.value if authz.body.identifier else 'unknown'}")
                    
                    for idx, challenge in enumerate(authz.body.challenges):
                        logger.error(f"  Challenge {idx + 1}:")
                        logger.error(f"    Type: {challenge.chall.typ if hasattr(challenge.chall, 'typ') else 'unknown'}")
                        logger.error(f"    Status: {challenge.status}")
                        logger.error(f"    Token: {challenge.chall.encode('token') if hasattr(challenge.chall, 'encode') else 'unknown'}")
                        if challenge.error:
                            logger.error(f"    Error: {challenge.error}")
                            logger.error(f"    Error detail: {challenge.error.detail if hasattr(challenge.error, 'detail') else 'no detail'}")
                    
                    raise Exception(f"Authorization failed with status: {status}")
                
                # Still pending, wait before next check
                if attempt < max_attempts - 1:
                    logger.info(f"Still pending, waiting {poll_interval}s before next check...")
                    import time
                    time.sleep(poll_interval)
                
            except Exception as e:
                if "Authorization failed" in str(e):
                    raise  # Don't retry on explicit failure
                logger.error(f"Error checking authorization: {e}")
                if attempt == max_attempts - 1:
                    raise
                time.sleep(poll_interval)
        
        raise Exception("Authorization validation timed out")
        
        # Don't delete challenge here - let it expire naturally with TTL
    
    def renew_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Renew existing certificate."""
        # Get existing certificate using sync Redis
        import json
        cert_json = self._sync_redis.get(f"cert:{cert_name}")
        if not cert_json:
            logger.error(f"Certificate {cert_name} not found")
            return None
        
        cert_data = json.loads(cert_json)
        from .models import Certificate
        from datetime import datetime, timezone
        existing_cert = Certificate(
            cert_name=cert_data['cert_name'],
            domains=cert_data['domains'],
            email=cert_data['email'],
            acme_directory_url=cert_data['acme_directory_url'],
            status=cert_data.get('status', 'active'),
            expires_at=datetime.fromisoformat(cert_data['expires_at']).replace(tzinfo=timezone.utc),
            issued_at=datetime.fromisoformat(cert_data['issued_at']).replace(tzinfo=timezone.utc),
            fingerprint=cert_data.get('fingerprint'),
            fullchain_pem=cert_data.get('fullchain_pem'),
            private_key_pem=cert_data.get('private_key_pem'),
            created_by=cert_data.get('created_by')
        )
        
        logger.info(f"Renewing certificate {cert_name}")
        
        # Generate new certificate with same parameters, preserving ownership
        return self.generate_certificate(
            domains=existing_cert.domains,
            email=existing_cert.email,
            acme_directory_url=existing_cert.acme_directory_url,
            cert_name=cert_name,
            created_by=existing_cert.created_by
        )