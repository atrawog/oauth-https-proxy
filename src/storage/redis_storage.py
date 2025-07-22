"""Redis storage implementation for MCP HTTP Proxy."""

import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import redis
from redis.exceptions import RedisError

from ..certmanager.models import Certificate
from ..proxy.models import ProxyTarget
from ..proxy.routes import Route

logger = logging.getLogger(__name__)


class ChallengeToken:
    """ACME challenge token."""
    def __init__(self, token: str, authorization: str, expires_at: datetime):
        self.token = token
        self.authorization = authorization
        self.expires_at = expires_at
    
    def json(self):
        return json.dumps({
            'token': self.token,
            'authorization': self.authorization,
            'expires_at': self.expires_at.isoformat()
        })
    
    @classmethod
    def parse_raw(cls, raw: str):
        data = json.loads(raw)
        return cls(
            token=data['token'],
            authorization=data['authorization'],
            expires_at=datetime.fromisoformat(data['expires_at'])
        )


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
        """Store certificate in Redis with domain uniqueness checking."""
        try:
            # Check if any of the domains already have certificates
            for domain in certificate.domains:
                existing_cert_name = self.redis_client.get(f"cert:domain:{domain}")
                if existing_cert_name and existing_cert_name != cert_name:
                    logger.error(
                        f"Domain {domain} already has certificate {existing_cert_name}. "
                        f"Cannot create certificate {cert_name}"
                    )
                    return False
            
            # Store certificate data
            key = f"cert:{cert_name}"
            value = certificate.json()
            result = self.redis_client.set(key, value)
            
            if result:
                # Create domain indexes
                for domain in certificate.domains:
                    self.redis_client.set(f"cert:domain:{domain}", cert_name)
                
                logger.info(f"Successfully stored certificate {cert_name} for domains {certificate.domains}")
            else:
                logger.error(f"Redis set returned False for certificate {cert_name}")
            
            return result
        except RedisError as e:
            logger.error(f"Failed to store certificate {cert_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error storing certificate {cert_name}: {e}")
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
        """Delete certificate from Redis and clean up associated proxy targets and domain indexes."""
        try:
            # Get certificate to find domains
            cert = self.get_certificate(cert_name)
            
            # First, find all proxy targets that reference this certificate
            proxy_targets_cleaned = 0
            for key in self.redis_client.scan_iter(match="proxy:*"):
                proxy_json = self.redis_client.get(key)
                if proxy_json:
                    proxy_data = json.loads(proxy_json)
                    if proxy_data.get('cert_name') == cert_name:
                        # Clear the cert_name from this proxy target
                        proxy_data['cert_name'] = None
                        self.redis_client.set(key, json.dumps(proxy_data))
                        proxy_targets_cleaned += 1
                        logger.info(f"Cleaned up cert_name from proxy target: {key.split(':', 1)[1]}")
            
            if proxy_targets_cleaned > 0:
                logger.info(f"Cleaned up {proxy_targets_cleaned} proxy targets that referenced certificate {cert_name}")
            
            # Delete domain indexes if certificate exists
            if cert and cert.domains:
                for domain in cert.domains:
                    self.redis_client.delete(f"cert:domain:{domain}")
                logger.info(f"Cleaned up domain indexes for domains: {cert.domains}")
            
            # Now delete the certificate
            key = f"cert:{cert_name}"
            return bool(self.redis_client.delete(key))
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to delete certificate: {e}")
            return False
    
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
    
    # API Token operations
    def store_api_token(self, name: str, token: str, cert_email: Optional[str] = None) -> bool:
        """Store API token with full token for retrieval."""
        try:
            # Create token hash
            import hashlib
            token_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
            
            data = {
                "name": name,
                "hash": token_hash,
                "token": token,  # Store full token
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
                "token": token,
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
        """Update the certificate email for an API token."""
        try:
            # Get token data
            auth_key = f"auth:token:{token_hash}"
            token_json = self.redis_client.get(auth_key)
            
            if not token_json:
                return False
            
            token_data = json.loads(token_json)
            token_data['cert_email'] = cert_email
            
            # Update in auth key
            result1 = self.redis_client.set(auth_key, json.dumps(token_data))
            
            # Update in name key
            name = token_data.get('name')
            if name:
                name_key = f"token:{name}"
                result2 = self.redis_client.hset(name_key, 'cert_email', cert_email)
                return result1 and result2
            
            return result1
            
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to update API token email: {e}")
            return False
    
    # Proxy Target operations
    def store_proxy_target(self, hostname: str, target: ProxyTarget) -> bool:
        """Store proxy target configuration."""
        try:
            key = f"proxy:{hostname}"
            return self.redis_client.set(key, target.json())
        except RedisError as e:
            logger.error(f"Failed to store proxy target: {e}")
            return False
    
    def get_proxy_target(self, hostname: str) -> Optional[ProxyTarget]:
        """Get proxy target configuration."""
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
        """Delete proxy target."""
        try:
            key = f"proxy:{hostname}"
            return bool(self.redis_client.delete(key))
        except RedisError as e:
            logger.error(f"Failed to delete proxy target: {e}")
            return False
    
    def get_targets_by_owner(self, token_hash: str) -> List[ProxyTarget]:
        """Get all proxy targets owned by a specific token."""
        try:
            targets = []
            for target in self.list_proxy_targets():
                if target.owner_token_hash == token_hash:
                    targets.append(target)
            return targets
        except Exception as e:
            logger.error(f"Failed to get targets by owner: {e}")
            return []
    
    def update_proxy_target(self, hostname: str, updates) -> bool:
        """Update proxy target with partial data."""
        try:
            target = self.get_proxy_target(hostname)
            if not target:
                return False
            
            # Apply updates
            for field, value in updates.dict(exclude_unset=True).items():
                setattr(target, field, value)
            
            return self.store_proxy_target(hostname, target)
        except Exception as e:
            logger.error(f"Failed to update proxy target: {e}")
            return False
    
    # Route operations
    def store_route(self, route: Route) -> bool:
        """Store routing rule with priority indexing and uniqueness check."""
        try:
            # Create unique key for path+priority combination
            # Use base64 encoding to handle special characters in path
            path_encoded = base64.b64encode(route.path_pattern.encode()).decode()
            unique_key = f"route:unique:{path_encoded}:{route.priority}"
            
            # Check if route with same path and priority already exists
            existing_route_id = self.redis_client.get(unique_key)
            if existing_route_id and existing_route_id != route.route_id:
                # A different route already exists with same path and priority
                logger.error(
                    f"Route already exists with path={route.path_pattern} and priority={route.priority}. "
                    f"Existing route ID: {existing_route_id}"
                )
                return False
            
            # Store route data
            route_key = f"route:{route.route_id}"
            result1 = self.redis_client.set(route_key, route.json())
            
            # Store priority index
            priority_key = f"route:priority:{100 - route.priority:04d}:{route.route_id}"
            result2 = self.redis_client.set(priority_key, route.route_id)
            
            # Store unique constraint
            result3 = self.redis_client.set(unique_key, route.route_id)
            
            return result1 and result2 and result3
        except RedisError as e:
            logger.error(f"Failed to store route: {e}")
            return False
    
    def get_route(self, route_id: str) -> Optional[Route]:
        """Get route by ID."""
        try:
            key = f"route:{route_id}"
            value = self.redis_client.get(key)
            if value:
                return Route.parse_raw(value)
            return None
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get route: {e}")
            return None
    
    def list_routes(self) -> List[Route]:
        """List all routes sorted by priority (highest first)."""
        try:
            routes = []
            route_ids = set()
            
            # Get routes ordered by priority
            for key in self.redis_client.scan_iter(match="route:priority:*"):
                route_id = self.redis_client.get(key)
                if route_id and route_id not in route_ids:
                    route_ids.add(route_id)
                    route = self.get_route(route_id)
                    if route and route.enabled:
                        routes.append(route)
            
            # Also get any routes without priority index (shouldn't happen)
            for key in self.redis_client.scan_iter(match="route:*"):
                if not key.startswith("route:priority:") and not key.startswith("route:unique:"):
                    route_id = key.split(":", 1)[1]
                    if route_id not in route_ids:
                        route = self.get_route(route_id)
                        if route and route.enabled:
                            routes.append(route)
            
            # Sort by priority (descending)
            routes.sort(key=lambda r: r.priority, reverse=True)
            return routes
            
        except RedisError as e:
            logger.error(f"Failed to list routes: {e}")
            return []
    
    def delete_route(self, route_id: str) -> bool:
        """Delete route and all its indexes."""
        try:
            route = self.get_route(route_id)
            if not route:
                return False
            
            # Delete route data
            route_key = f"route:{route_id}"
            result1 = bool(self.redis_client.delete(route_key))
            
            # Delete priority index
            priority_key = f"route:priority:{100 - route.priority:04d}:{route_id}"
            result2 = bool(self.redis_client.delete(priority_key))
            
            # Delete unique constraint
            path_encoded = base64.b64encode(route.path_pattern.encode()).decode()
            unique_key = f"route:unique:{path_encoded}:{route.priority}"
            result3 = bool(self.redis_client.delete(unique_key))
            
            return result1 and result2 and result3
        except RedisError as e:
            logger.error(f"Failed to delete route: {e}")
            return False
    
    def initialize_default_routes(self) -> None:
        """Initialize default routing rules if none exist."""
        try:
            # Check if any routes exist
            if list(self.redis_client.scan_iter(match="route:*", count=1)):
                logger.info("Routes already exist, skipping default initialization")
                return
            
            logger.info("Initializing default routes...")
            
            # Import DEFAULT_ROUTES from proxy module
            from ..proxy.models import DEFAULT_ROUTES
            
            for route in DEFAULT_ROUTES:
                if self.store_route(route):
                    logger.info(f"Created default route: {route.route_id}")
                else:
                    logger.error(f"Failed to create default route: {route.route_id}")
                    
        except Exception as e:
            logger.error(f"Failed to initialize default routes: {e}")
    
    def count_certificates_by_owner(self, owner_token_hash: str) -> int:
        """Count certificates owned by a specific token."""
        try:
            count = 0
            for key in self.redis_client.scan_iter(match="cert:*"):
                cert_data = self.redis_client.get(key)
                if cert_data:
                    cert_dict = json.loads(cert_data)
                    if cert_dict.get('owner_token_hash') == owner_token_hash:
                        count += 1
            return count
        except Exception as e:
            logger.error(f"Failed to count certificates by owner: {e}")
            return 0
    
    def count_proxies_by_owner(self, owner_token_hash: str) -> int:
        """Count proxy targets owned by a specific token."""
        try:
            count = 0
            for key in self.redis_client.scan_iter(match="proxy:*"):
                proxy_data = self.redis_client.get(key)
                if proxy_data:
                    proxy_dict = json.loads(proxy_data)
                    if proxy_dict.get('owner_token_hash') == owner_token_hash:
                        count += 1
            return count
        except Exception as e:
            logger.error(f"Failed to count proxies by owner: {e}")
            return 0
    
    def list_certificate_names_by_owner(self, owner_token_hash: str) -> List[str]:
        """List certificate names owned by a specific token."""
        try:
            names = []
            for key in self.redis_client.scan_iter(match="cert:*"):
                cert_data = self.redis_client.get(key)
                if cert_data:
                    cert_dict = json.loads(cert_data)
                    if cert_dict.get('owner_token_hash') == owner_token_hash:
                        names.append(cert_dict.get('cert_name', ''))
            return names
        except Exception as e:
            logger.error(f"Failed to list certificate names by owner: {e}")
            return []
    
    def list_proxy_names_by_owner(self, owner_token_hash: str) -> List[str]:
        """List proxy hostnames owned by a specific token."""
        try:
            names = []
            for key in self.redis_client.scan_iter(match="proxy:*"):
                proxy_data = self.redis_client.get(key)
                if proxy_data:
                    proxy_dict = json.loads(proxy_data)
                    if proxy_dict.get('owner_token_hash') == owner_token_hash:
                        names.append(proxy_dict.get('hostname', ''))
            return names
        except Exception as e:
            logger.error(f"Failed to list proxy names by owner: {e}")
            return []