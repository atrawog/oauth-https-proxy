"""Redis storage implementation for ACME Certificate Manager."""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import redis
from redis.exceptions import RedisError
from .models import Certificate, ChallengeToken

logger = logging.getLogger(__name__)


class RedisStorage:
    """Redis storage backend for certificates and ACME data."""
    
    def __init__(self, redis_url: str):
        """Initialize Redis connection."""
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
        self.challenge_ttl = 3600  # 1 hour TTL for challenges
        
    def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            return self.redis_client.ping()
        except RedisError:
            return False
    
    # Certificate operations
    def store_certificate(self, cert_name: str, certificate: Certificate) -> bool:
        """Store certificate in Redis."""
        try:
            key = f"cert:{cert_name}"
            value = certificate.json()
            return self.redis_client.set(key, value)
        except RedisError as e:
            logger.error(f"Failed to store certificate: {e}")
            return False
    
    def get_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Retrieve certificate from Redis."""
        try:
            key = f"cert:{cert_name}"
            value = self.redis_client.get(key)
            if value:
                return Certificate.parse_raw(value)
            return None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get certificate: {e}")
            return None
    
    def list_certificates(self) -> List[Dict[str, Certificate]]:
        """List all certificates."""
        try:
            certificates = []
            for key in self.redis_client.scan_iter(match="cert:*"):
                cert_name = key.split(":", 1)[1]
                cert = self.get_certificate(cert_name)
                if cert:
                    certificates.append({cert_name: cert})
            return certificates
        except RedisError as e:
            logger.error(f"Failed to list certificates: {e}")
            return []
    
    def delete_certificate(self, cert_name: str) -> bool:
        """Delete certificate from Redis."""
        try:
            key = f"cert:{cert_name}"
            return bool(self.redis_client.delete(key))
        except RedisError as e:
            logger.error(f"Failed to delete certificate: {e}")
            return False
    
    # Challenge operations
    def store_challenge(self, token: str, authorization: str) -> bool:
        """Store ACME challenge with TTL."""
        try:
            key = f"challenge:{token}"
            challenge = ChallengeToken(
                token=token,
                authorization=authorization,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.challenge_ttl)
            )
            return self.redis_client.setex(
                key, 
                self.challenge_ttl, 
                challenge.json()
            )
        except RedisError as e:
            logger.error(f"Failed to store challenge: {e}")
            return False
    
    def get_challenge(self, token: str) -> Optional[str]:
        """Retrieve challenge authorization."""
        try:
            key = f"challenge:{token}"
            value = self.redis_client.get(key)
            if value:
                challenge = ChallengeToken.parse_raw(value)
                return challenge.authorization
            return None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get challenge: {e}")
            return None
    
    def delete_challenge(self, token: str) -> bool:
        """Delete challenge from Redis."""
        try:
            key = f"challenge:{token}"
            return bool(self.redis_client.delete(key))
        except RedisError as e:
            logger.error(f"Failed to delete challenge: {e}")
            return False
    
    # Account key operations
    def store_account_key(self, provider: str, email: str, key_pem: str) -> bool:
        """Store ACME account private key."""
        try:
            key = f"account:{provider}:{email}"
            return self.redis_client.set(key, key_pem)
        except RedisError as e:
            logger.error(f"Failed to store account key: {e}")
            return False
    
    def get_account_key(self, provider: str, email: str) -> Optional[str]:
        """Retrieve ACME account private key."""
        try:
            key = f"account:{provider}:{email}"
            return self.redis_client.get(key)
        except RedisError as e:
            logger.error(f"Failed to get account key: {e}")
            return None
    
    # Certificate expiry operations
    def get_expiring_certificates(self, days: int = 30) -> List[tuple[str, Certificate]]:
        """Get certificates expiring within specified days."""
        try:
            expiring = []
            threshold = datetime.now(timezone.utc) + timedelta(days=days)
            
            for key in self.redis_client.scan_iter(match="cert:*"):
                cert_name = key.split(":", 1)[1]
                cert = self.get_certificate(cert_name)
                
                if cert and cert.expires_at and cert.expires_at <= threshold:
                    expiring.append((cert_name, cert))
            
            return expiring
        except RedisError as e:
            logger.error(f"Failed to get expiring certificates: {e}")
            return []
    
    # API Token operations
    def store_api_token(self, token_hash: str, name: str) -> bool:
        """Store API token metadata."""
        try:
            key = f"auth:token:{token_hash}"
            data = {
                "name": name,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            return self.redis_client.set(key, json.dumps(data))
        except RedisError as e:
            logger.error(f"Failed to store API token: {e}")
            return False
    
    def get_api_token(self, token_hash: str) -> Optional[dict]:
        """Get API token metadata."""
        try:
            key = f"auth:token:{token_hash}"
            value = self.redis_client.get(key)
            return json.loads(value) if value else None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get API token: {e}")
            return None
    
    def delete_api_token(self, token_hash: str) -> bool:
        """Delete API token."""
        try:
            key = f"auth:token:{token_hash}"
            return bool(self.redis_client.delete(key))
        except RedisError as e:
            logger.error(f"Failed to delete API token: {e}")
            return False