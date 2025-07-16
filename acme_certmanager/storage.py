"""Redis storage implementation for ACME Certificate Manager."""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import redis
from redis.exceptions import RedisError
from .models import Certificate, ChallengeToken, ProxyTarget

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
    
    def list_certificates(self) -> List[Certificate]:
        """List all certificates."""
        try:
            certificates = []
            for key in self.redis_client.scan_iter(match="cert:*"):
                cert_name = key.split(":", 1)[1]
                cert = self.get_certificate(cert_name)
                if cert:
                    certificates.append(cert)
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
    def store_api_token(self, token_hash: str, name: str, full_token: str, cert_email: Optional[str] = None) -> bool:
        """Store API token with full token for retrieval."""
        try:
            data = {
                "name": name,
                "hash": token_hash,
                "token": full_token,  # Store full token
                "cert_email": cert_email,  # Certificate email for this token
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Store by hash (for auth)
            auth_key = f"auth:token:{token_hash}"
            result1 = self.redis_client.set(auth_key, json.dumps(data))
            
            # Store by name (for management)
            name_key = f"token:{name}"
            result2 = self.redis_client.hset(name_key, mapping={
                "name": name,
                "hash": token_hash,
                "token": full_token,
                "cert_email": cert_email or "",
                "created_at": data["created_at"]
            })
            
            return result1 and result2
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
    
    def get_api_token_by_name(self, name: str) -> Optional[dict]:
        """Get API token metadata by name."""
        try:
            key = f"token:{name}"
            data = self.redis_client.hgetall(key)
            return data if data else None
        except RedisError as e:
            logger.error(f"Failed to get API token by name: {e}")
            return None
    
    def delete_api_token(self, token_hash: str) -> bool:
        """Delete API token by hash."""
        try:
            # Get token data to find name
            auth_key = f"auth:token:{token_hash}"
            token_json = self.redis_client.get(auth_key)
            
            if token_json:
                token_data = json.loads(token_json)
                name = token_data.get('name')
                
                # Delete both keys
                result1 = bool(self.redis_client.delete(auth_key))
                result2 = True
                if name:
                    name_key = f"token:{name}"
                    result2 = bool(self.redis_client.delete(name_key))
                
                return result1 and result2
            
            return False
        except RedisError as e:
            logger.error(f"Failed to delete API token: {e}")
            return False
    
    def delete_api_token_by_name(self, name: str) -> bool:
        """Delete API token by name."""
        try:
            # Get token hash from name
            name_key = f"token:{name}"
            token_data = self.redis_client.hgetall(name_key)
            
            if not token_data:
                return False
            
            token_hash = token_data.get('hash')
            if token_hash:
                # Delete both keys
                auth_key = f"auth:token:{token_hash}"
                result1 = bool(self.redis_client.delete(auth_key))
                result2 = bool(self.redis_client.delete(name_key))
                return result1 and result2
            
            return False
        except RedisError as e:
            logger.error(f"Failed to delete API token by name: {e}")
            return False
    
    def delete_api_token_cascade(self, token_hash: str) -> dict:
        """Delete API token and all resources owned by it.
        
        Returns dict with deletion statistics.
        """
        try:
            stats = {
                'token_deleted': False,
                'certificates_deleted': 0,
                'proxy_targets_deleted': 0,
                'errors': []
            }
            
            # Delete all certificates owned by this token
            cert_cursor = 0
            while True:
                cert_cursor, cert_keys = self.redis_client.scan(
                    cert_cursor, match="cert:*", count=100
                )
                for cert_key in cert_keys:
                    cert_json = self.redis_client.get(cert_key)
                    if cert_json:
                        cert = json.loads(cert_json)
                        if cert.get('owner_token_hash') == token_hash:
                            if self.redis_client.delete(cert_key):
                                stats['certificates_deleted'] += 1
                            else:
                                stats['errors'].append(f"Failed to delete certificate: {cert_key}")
                if cert_cursor == 0:
                    break
            
            # Delete all proxy targets owned by this token
            proxy_cursor = 0
            while True:
                proxy_cursor, proxy_keys = self.redis_client.scan(
                    proxy_cursor, match="proxy:*", count=100
                )
                for proxy_key in proxy_keys:
                    proxy_json = self.redis_client.get(proxy_key)
                    if proxy_json:
                        proxy = json.loads(proxy_json)
                        if proxy.get('owner_token_hash') == token_hash:
                            if self.redis_client.delete(proxy_key):
                                stats['proxy_targets_deleted'] += 1
                            else:
                                stats['errors'].append(f"Failed to delete proxy: {proxy_key}")
                if proxy_cursor == 0:
                    break
            
            # Delete the token itself
            stats['token_deleted'] = self.delete_api_token(token_hash)
            if not stats['token_deleted']:
                stats['errors'].append("Failed to delete token")
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to cascade delete token: {e}")
            return {
                'token_deleted': False,
                'certificates_deleted': 0,
                'proxy_targets_deleted': 0,
                'errors': [str(e)]
            }
    
    def delete_api_token_cascade_by_name(self, name: str) -> dict:
        """Delete API token by name and all resources owned by it."""
        try:
            # Get token hash from name
            name_key = f"token:{name}"
            token_data = self.redis_client.hgetall(name_key)
            
            if not token_data:
                return {
                    'token_deleted': False,
                    'certificates_deleted': 0,
                    'proxy_targets_deleted': 0,
                    'errors': ['Token not found']
                }
            
            token_hash = token_data.get('hash')
            if token_hash:
                return self.delete_api_token_cascade(token_hash)
            
            return {
                'token_deleted': False,
                'certificates_deleted': 0,
                'proxy_targets_deleted': 0,
                'errors': ['Token hash not found']
            }
        except Exception as e:
            logger.error(f"Failed to cascade delete token by name: {e}")
            return {
                'token_deleted': False,
                'certificates_deleted': 0,
                'proxy_targets_deleted': 0,
                'errors': [str(e)]
            }
    
    def update_api_token_email(self, token_hash: str, cert_email: str) -> bool:
        """Update the certificate email for a token."""
        try:
            # Get token data
            auth_key = f"auth:token:{token_hash}"
            token_json = self.redis_client.get(auth_key)
            if not token_json:
                return False
            
            token_data = json.loads(token_json)
            token_data["cert_email"] = cert_email
            
            # Update auth key
            result1 = self.redis_client.set(auth_key, json.dumps(token_data))
            
            # Update name key
            name = token_data.get("name")
            if name:
                name_key = f"token:{name}"
                result2 = self.redis_client.hset(name_key, "cert_email", cert_email)
                return result1 and result2
            
            return result1
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to update API token email: {e}")
            return False
    
    # Proxy target operations
    def store_proxy_target(self, hostname: str, target: ProxyTarget) -> bool:
        """Store proxy target configuration."""
        try:
            key = f"proxy:{hostname}"
            value = target.json()
            return self.redis_client.set(key, value)
        except RedisError as e:
            logger.error(f"Failed to store proxy target: {e}")
            return False
    
    def get_proxy_target(self, hostname: str) -> Optional[ProxyTarget]:
        """Retrieve proxy target configuration."""
        try:
            key = f"proxy:{hostname}"
            value = self.redis_client.get(key)
            if value:
                return ProxyTarget.parse_raw(value)
            return None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get proxy target: {e}")
            return None
    
    def list_proxy_targets(self) -> List[ProxyTarget]:
        """List all proxy targets."""
        try:
            targets = []
            for key in self.redis_client.scan_iter(match="proxy:*"):
                hostname = key.split(":", 1)[1]
                target = self.get_proxy_target(hostname)
                if target:
                    targets.append(target)
            return targets
        except RedisError as e:
            logger.error(f"Failed to list proxy targets: {e}")
            return []
    
    def delete_proxy_target(self, hostname: str) -> bool:
        """Delete proxy target configuration."""
        try:
            key = f"proxy:{hostname}"
            return bool(self.redis_client.delete(key))
        except RedisError as e:
            logger.error(f"Failed to delete proxy target: {e}")
            return False
    
    def get_targets_by_owner(self, token_hash: str) -> List[ProxyTarget]:
        """Get proxy targets owned by a specific token."""
        try:
            owned_targets = []
            for target in self.list_proxy_targets():
                if target.owner_token_hash == token_hash:
                    owned_targets.append(target)
            return owned_targets
        except RedisError as e:
            logger.error(f"Failed to get targets by owner: {e}")
            return []