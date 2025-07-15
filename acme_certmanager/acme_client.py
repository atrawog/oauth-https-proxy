"""ACME protocol client implementation."""

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import josepy as jose
from acme import client, challenges, messages, crypto_util
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .models import Certificate
from .storage import RedisStorage

logger = logging.getLogger(__name__)


class ACMEClient:
    """ACME protocol client for certificate management."""
    
    def __init__(self, storage: RedisStorage):
        """Initialize ACME client with storage backend."""
        self.storage = storage
        self.account_key_size = 2048
        self.cert_key_size = 2048
    
    def _generate_rsa_key(self, key_size: int = 2048) -> Tuple[jose.JWKRSA, str]:
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
        
        jwk = jose.JWKRSA(key=private_key)
        return jwk, private_pem
    
    def _get_or_create_account_key(self, provider: str, email: str) -> jose.JWKRSA:
        """Get existing or create new account key."""
        # Extract provider name from URL
        parsed = urlparse(provider)
        provider_name = parsed.hostname.replace('.', '_')
        
        # Check for existing key
        key_pem = self.storage.get_account_key(provider_name, email)
        
        if key_pem:
            private_key = serialization.load_pem_private_key(
                key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            return jose.JWKRSA(key=private_key)
        
        # Generate new key
        jwk, private_pem = self._generate_rsa_key(self.account_key_size)
        
        # Store key
        self.storage.store_account_key(provider_name, email, private_pem)
        
        return jwk
    
    def _create_acme_client(self, directory_url: str, account_key: jose.JWKRSA) -> client.ClientV2:
        """Create ACME client instance."""
        net = client.ClientNetwork(account_key)
        directory = messages.Directory.from_json(net.get(directory_url).json())
        return client.ClientV2(directory, net=net)
    
    def _register_or_login(self, acme_client: client.ClientV2, email: str) -> messages.RegistrationResource:
        """Register new account or login with existing."""
        try:
            # Try to register new account
            regr = acme_client.new_account(
                messages.NewRegistration.from_data(
                    email=email,
                    terms_of_service_agreed=True
                )
            )
            logger.info(f"Registered new ACME account for {email}")
            return regr
        except messages.Error as e:
            if e.code == 'accountDoesNotExist':
                raise
            # Account exists, query it
            regr = acme_client.query_registration(messages.RegistrationResource(
                body=messages.Registration(key=acme_client.net.key.public_key()),
                uri=None
            ))
            logger.info(f"Using existing ACME account for {email}")
            return regr
    
    def generate_certificate(
        self,
        domains: List[str],
        email: str,
        acme_directory_url: str,
        cert_name: str
    ) -> Certificate:
        """Generate certificate using ACME protocol."""
        logger.info(f"Generating certificate for domains: {domains}")
        
        # Get or create account key
        account_key = self._get_or_create_account_key(acme_directory_url, email)
        
        # Create ACME client
        acme_client = self._create_acme_client(acme_directory_url, account_key)
        
        # Register or login
        registration = self._register_or_login(acme_client, email)
        
        # Generate certificate key
        cert_key, cert_key_pem = self._generate_rsa_key(self.cert_key_size)
        
        # Create CSR
        csr = self._create_csr(cert_key.key, domains)
        
        # Create order
        order = acme_client.new_order(csr)
        
        # Process challenges
        for auth in order.authorizations:
            self._process_authorization(acme_client, auth)
        
        # Finalize order
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
            domains=domains,
            email=email,
            acme_directory_url=acme_directory_url,
            status="active",
            expires_at=cert_obj.not_valid_after.replace(tzinfo=timezone.utc),
            issued_at=cert_obj.not_valid_before.replace(tzinfo=timezone.utc),
            fingerprint=fingerprint,
            fullchain_pem=fullchain_pem,
            private_key_pem=cert_key_pem
        )
        
        # Store certificate
        self.storage.store_certificate(cert_name, certificate)
        
        logger.info(f"Certificate generated successfully for {domains}")
        return certificate
    
    def _create_csr(self, private_key, domains: List[str]) -> bytes:
        """Create Certificate Signing Request."""
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
        
        return csr.public_bytes(serialization.Encoding.DER)
    
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
        
        # Store challenge in Redis
        token = http_challenge.chall.token.decode('utf-8')
        self.storage.store_challenge(token, validation)
        
        try:
            # Answer challenge
            acme_client.answer_challenge(http_challenge, response)
            
            # Wait for challenge validation
            finalized = acme_client.poll_and_finalize(authz)
            
        finally:
            # Clean up challenge
            self.storage.delete_challenge(token)
    
    def renew_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Renew existing certificate."""
        # Get existing certificate
        existing_cert = self.storage.get_certificate(cert_name)
        if not existing_cert:
            logger.error(f"Certificate {cert_name} not found")
            return None
        
        logger.info(f"Renewing certificate {cert_name}")
        
        # Generate new certificate with same parameters
        return self.generate_certificate(
            domains=existing_cert.domains,
            email=existing_cert.email,
            acme_directory_url=existing_cert.acme_directory_url,
            cert_name=cert_name
        )