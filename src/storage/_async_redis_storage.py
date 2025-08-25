"""Async Redis storage implementation for MCP HTTP Proxy.

This module provides a fully async Redis storage backend that doesn't block
the event loop. It replaces the synchronous RedisStorage class.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import redis.asyncio as redis
from redis.exceptions import RedisError

from ..certmanager.models import Certificate
from ..proxy.models import ProxyTarget
from ..proxy.routes import Route
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace


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


class AsyncRedisStorage:
    """Async Redis storage backend for certificates and ACME data."""
    
    def __init__(self, redis_url: str):
        """Initialize Redis connection."""
        self.redis_url = redis_url
        self.redis_client = None
        self.challenge_ttl = 3600  # 1 hour TTL for challenges
        
    async def initialize(self):
        """Initialize async Redis connection."""
        if not self.redis_client:
            self.redis_client = await redis.from_url(
                self.redis_url, 
                decode_responses=True
            )
            # Test connection
            await self.redis_client.ping()
            log_info("AsyncRedisStorage initialized successfully", component="redis_storage")
    
    async def close(self):
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
    
    async def ensure_initialized(self) -> bool:
        """Ensure Redis client is initialized."""
        if not self.redis_client:
            try:
                await self.initialize()
                return self.redis_client is not None
            except Exception as e:
                log_error(f"Failed to initialize Redis client: {e}", component="redis_storage")
                return False
        return True
    
    async def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            if not self.redis_client:
                await self.initialize()
            return await self.redis_client.ping()
        except RedisError:
            return False
    
    async def get(self, key: str) -> Optional[str]:
        """Get raw value from Redis.
        
        Args:
            key: Redis key to retrieve
            
        Returns:
            String value or None if not found
        """
        await self.ensure_initialized()
        try:
            value = await self.redis_client.get(key)
            # Since we use decode_responses=True, value is already a string or None
            return value
        except Exception as e:
            log_error(f"Failed to get value for key {key}: {e}", component="redis_storage")
            return None
    
    # Certificate operations
    async def store_certificate(self, cert_name: str, certificate: Certificate) -> bool:
        """Store certificate in Redis with domain uniqueness checking."""
        try:
            # Check if any of the domains already have certificates
            for domain in certificate.domains:
                existing_cert_name = await self.redis_client.get(f"cert:domain:{domain}")
                if existing_cert_name and existing_cert_name != cert_name:
                    log_error(
                        f"Domain {domain} already has certificate {existing_cert_name}. "
                        f"Cannot create certificate {cert_name}",
                        component="redis_storage"
                    )
                    return False
            
            # Store certificate data
            key = f"cert:{cert_name}"
            value = certificate.json()
            result = await self.redis_client.set(key, value)
            
            if result:
                # Create domain indexes
                for domain in certificate.domains:
                    await self.redis_client.set(f"cert:domain:{domain}", cert_name)
                
                log_info(f"Successfully stored certificate {cert_name} for domains {certificate.domains}", component="redis_storage")
            else:
                log_error(f"Redis set returned False for certificate {cert_name}", component="redis_storage")
            
            return result
        except RedisError as e:
            log_error(f"Failed to store certificate {cert_name}: {e}", component="redis_storage", error=e)
            return False
        except Exception as e:
            log_error(f"Unexpected error storing certificate {cert_name}: {e}", component="redis_storage", error=e)
            return False
    
    async def get_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Retrieve certificate from Redis."""
        try:
            key = f"cert:{cert_name}"
            value = await self.redis_client.get(key)
            if value:
                return Certificate.parse_raw(value)
            return None
        except (RedisError, json.JSONDecodeError) as e:
            log_error(f"Failed to get certificate: {e}", component="redis_storage", error=e)
            return None
    
    async def list_certificates(self) -> List[Certificate]:
        """List all certificates."""
        # Ensure Redis client is initialized
        if not self.redis_client:
            await self.initialize()
            if not self.redis_client:
                log_error("Failed to initialize Redis client in list_certificates", component="redis_storage")
                return []
        
        try:
            certificates = []
            async for key in self.redis_client.scan_iter(match="cert:*"):
                # Skip domain mappings and status keys
                if key.startswith("cert:domain:") or key.startswith("cert:status"):
                    continue
                cert_name = key.split(":", 1)[1]
                cert = await self.get_certificate(cert_name)
                if cert:
                    certificates.append(cert)
            return certificates
        except RedisError as e:
            log_error(f"Failed to list certificates: {e}", component="redis_storage", error=e)
            return []
    
    async def delete_certificate(self, cert_name: str) -> bool:
        """Delete certificate from Redis and clean up associated proxy targets and domain indexes."""
        if not await self.ensure_initialized():
            return False
        
        try:
            # Get certificate to find domains
            cert = await self.get_certificate(cert_name)
            
            # First, find all proxy targets that reference this certificate
            proxy_targets_cleaned = 0
            async for key in self.redis_client.scan_iter(match="proxy:*"):
                # Skip non-proxy target keys (streams, client info, etc)
                if ":" in key[6:]:  # Skip keys like proxy:events:stream, proxy:client:*, etc
                    continue
                proxy_json = await self.redis_client.get(key)
                if proxy_json:
                    proxy_data = json.loads(proxy_json)
                    if proxy_data.get('cert_name') == cert_name:
                        # Clear the cert_name from this proxy target
                        proxy_data['cert_name'] = None
                        await self.redis_client.set(key, json.dumps(proxy_data))
                        proxy_targets_cleaned += 1
                        log_info(f"Cleaned up cert_name from proxy target: {key.split(':', 1)[1]}", component="redis_storage")
            
            if proxy_targets_cleaned > 0:
                log_info(f"Cleaned up {proxy_targets_cleaned} proxy targets that referenced certificate {cert_name}", component="redis_storage")
            
            # Delete domain indexes if certificate exists
            if cert and cert.domains:
                for domain in cert.domains:
                    await self.redis_client.delete(f"cert:domain:{domain}")
                log_info(f"Cleaned up domain indexes for domains: {cert.domains}", component="redis_storage")
            
            # Now delete the certificate
            key = f"cert:{cert_name}"
            return bool(await self.redis_client.delete(key))
        except (RedisError, json.JSONDecodeError) as e:
            log_error(f"Failed to delete certificate: {e}", component="redis_storage", error=e)
            return False
    
    async def get_expiring_certificates(self, days: int = 30) -> List[tuple[str, Certificate]]:
        """Get certificates expiring within specified days."""
        try:
            expiring = []
            threshold = datetime.now(timezone.utc) + timedelta(days=days)
            
            async for key in self.redis_client.scan_iter(match="cert:*"):
                # Skip domain mappings and status keys
                if key.startswith("cert:domain:") or key.startswith("cert:status"):
                    continue
                cert_name = key.split(":", 1)[1]
                cert = await self.get_certificate(cert_name)
                
                if cert and cert.expires_at and cert.expires_at <= threshold:
                    expiring.append((cert_name, cert))
            
            return expiring
        except RedisError as e:
            log_error(f"Failed to get expiring certificates: {e}", component="redis_storage", error=e)
            return []
    
    # Challenge operations
    async def store_challenge(self, token: str, authorization: str) -> bool:
        """Store ACME challenge with TTL."""
        try:
            key = f"challenge:{token}"
            challenge = ChallengeToken(
                token=token,
                authorization=authorization,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.challenge_ttl)
            )
            return await self.redis_client.setex(
                key, 
                self.challenge_ttl, 
                challenge.json()
            )
        except RedisError as e:
            log_error(f"Failed to store challenge: {e}", component="redis_storage", error=e)
            return False
    
    async def get_challenge(self, token: str) -> Optional[str]:
        """Retrieve challenge authorization."""
        try:
            key = f"challenge:{token}"
            value = await self.redis_client.get(key)
            if value:
                challenge = ChallengeToken.parse_raw(value)
                return challenge.authorization
            return None
        except (RedisError, json.JSONDecodeError) as e:
            log_error(f"Failed to get challenge: {e}", component="redis_storage", error=e)
            return None
    
    async def delete_challenge(self, token: str) -> bool:
        """Delete challenge from Redis."""
        try:
            key = f"challenge:{token}"
            return bool(await self.redis_client.delete(key))
        except RedisError as e:
            log_error(f"Failed to delete challenge: {e}", component="redis_storage", error=e)
            return False
    
    # Account key operations
    async def store_account_key(self, provider: str, email: str, key_pem: str) -> bool:
        """Store ACME account private key."""
        try:
            key = f"account:{provider}:{email}"
            return await self.redis_client.set(key, key_pem)
        except RedisError as e:
            log_error(f"Failed to store account key: {e}", component="redis_storage", error=e)
            return False
    
    async def get_account_key(self, provider: str, email: str) -> Optional[str]:
        """Retrieve ACME account private key."""
        try:
            key = f"account:{provider}:{email}"
            return await self.redis_client.get(key)
        except RedisError as e:
            log_error(f"Failed to get account key: {e}", component="redis_storage", error=e)
            return None
    
    # API Token operations
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    async def store_proxy_target(self, proxy_hostname: str, target: ProxyTarget) -> bool:
        """Store proxy target configuration."""
        try:
            key = f"proxy:{proxy_hostname}"
            return await self.redis_client.set(key, target.json())
        except RedisError as e:
            log_error(f"Failed to store proxy target: {e}", component="redis_storage", error=e)
            return False
    
    async def get_proxy_target(self, proxy_hostname: str) -> Optional[ProxyTarget]:
        """Get proxy target configuration."""
        try:
            key = f"proxy:{proxy_hostname}"
            value = await self.redis_client.get(key)
            if value:
                # Decode bytes to string if needed
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                log_trace(f"Parsing proxy data for {proxy_hostname}: {value[:100]}", component="redis_storage")
                parsed = ProxyTarget.parse_raw(value)
                log_trace(f"Successfully parsed proxy target for {proxy_hostname}", component="redis_storage")
                return parsed
            else:
                log_warning(f"No data found for key {key}", component="redis_storage")
            return None
        except (RedisError, json.JSONDecodeError) as e:
            log_error(f"Failed to get proxy target for {proxy_hostname}: {e}", exc_info=True)
            return None
    
    async def list_proxy_targets(self) -> List[ProxyTarget]:
        """List all proxy targets."""
        import sys
        print(f"DEBUG async_redis_storage.list_proxy_targets() called", file=sys.stderr)
        
        # Ensure Redis client is initialized
        if not self.redis_client:
            await self.initialize()
            if not self.redis_client:
                log_error("Failed to initialize Redis client in list_proxy_targets", component="redis_storage")
                return []
        
        try:
            targets = []
            key_count = 0
            async for key in self.redis_client.scan_iter(match="proxy:*"):
                key_count += 1
                # Decode bytes to string if needed
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
                # Skip client info keys (proxy:client:*), port mappings, and event streams
                if ":client:" in key or ":ports:" in key or key == "proxy:events:stream":
                    log_trace(f"Skipping non-proxy key: {key}", component="redis_storage")
                    continue
                proxy_hostname = key.split(":", 1)[1]
                log_trace(f"Getting proxy target for hostname: {proxy_hostname}", component="redis_storage")
                target = await self.get_proxy_target(proxy_hostname)
                if target:
                    targets.append(target)
                    log_trace(f"Added proxy target: {proxy_hostname}", component="redis_storage")
                else:
                    log_error(f"Could not get proxy target for {proxy_hostname} - get_proxy_target returned None", component="redis_storage")
            log_trace(f"list_proxy_targets: scanned {key_count} keys, found {len(targets)} proxy targets", component="redis_storage")
            return targets
        except RedisError as e:
            log_error(f"Failed to list proxy targets: {e}", component="redis_storage", error=e)
            return []
    
    async def delete_proxy_target(self, proxy_hostname: str) -> bool:
        """Delete proxy target."""
        try:
            key = f"proxy:{proxy_hostname}"
            return bool(await self.redis_client.delete(key))
        except RedisError as e:
            log_error(f"Failed to delete proxy target: {e}", component="redis_storage", error=e)
            return False
    
    # Token method removed - OAuth only authentication
    async def update_proxy_target(self, proxy_hostname: str, updates) -> bool:
        """Update proxy target with partial data."""
        try:
            target = await self.get_proxy_target(proxy_hostname)
            if not target:
                return False
            
            # Apply updates
            for field, value in updates.dict(exclude_unset=True).items():
                setattr(target, field, value)
            
            return await self.store_proxy_target(proxy_hostname, target)
        except Exception as e:
            log_error(f"Failed to update proxy target: {e}", component="redis_storage", error=e)
            return False
    
    # Protected Resource Metadata operations
    async def get_proxy_targets_with_resource_metadata(self) -> List[ProxyTarget]:
        """Get all proxy targets with protected resource metadata configured."""
        try:
            targets = []
            for target in await self.list_proxy_targets():
                if target.resource_endpoint:
                    targets.append(target)
            return targets
        except Exception as e:
            log_error(f"Failed to get proxy targets with resource metadata: {e}", component="redis_storage", error=e)
            return []
    
    # Route operations
    async def store_route(self, route: Route) -> bool:
        """Store routing rule with priority indexing and uniqueness check."""
        try:
            # Create unique key for path+priority combination
            # Use base64 encoding to handle special characters in path
            path_encoded = base64.b64encode(route.path_pattern.encode()).decode()
            unique_key = f"route:unique:{path_encoded}:{route.priority}"
            
            # Check if route with same path and priority already exists
            existing_route_id = await self.redis_client.get(unique_key)
            if existing_route_id and existing_route_id != route.route_id:
                # A different route already exists with same path and priority
                log_error(
                    f"Route already exists with path={route.path_pattern} and priority={route.priority}. "
                    f"Existing route ID: {existing_route_id}"
                )
                return False
            
            # Store route data
            route_key = f"route:{route.route_id}"
            result1 = await self.redis_client.set(route_key, route.json())
            
            # Store priority index
            priority_key = f"route:priority:{100 - route.priority:04d}:{route.route_id}"
            result2 = await self.redis_client.set(priority_key, route.route_id)
            
            # Store unique constraint
            result3 = await self.redis_client.set(unique_key, route.route_id)
            
            return result1 and result2 and result3
        except RedisError as e:
            log_error(f"Failed to store route: {e}", component="redis_storage", error=e)
            return False
    
    async def get_route(self, route_id: str) -> Optional[Route]:
        """Get route by ID."""
        try:
            key = f"route:{route_id}"
            value = await self.redis_client.get(key)
            if value:
                try:
                    return Route.parse_raw(value)
                except Exception:
                    # Handle old routes without scope field
                    route_dict = json.loads(value)
                    if 'scope' not in route_dict:
                        route_dict['scope'] = 'global'  # Default to global scope
                        route_dict['proxy_hostnames'] = []
                    return Route(**route_dict)
            return None
        except (RedisError, json.JSONDecodeError) as e:
            log_error(f"Failed to get route: {e}", component="redis_storage", error=e)
            return None
    
    async def list_routes(self) -> List[Route]:
        """List all routes sorted by priority (highest first)."""
        if not await self.ensure_initialized():
            return []
        
        try:
            routes = []
            route_ids = set()
            
            # Get routes ordered by priority
            async for key in self.redis_client.scan_iter(match="route:priority:*"):
                route_id = await self.redis_client.get(key)
                if route_id and route_id not in route_ids:
                    route_ids.add(route_id)
                    route = await self.get_route(route_id)
                    if route and route.enabled:
                        routes.append(route)
            
            # Also get any routes without priority index (shouldn't happen)
            async for key in self.redis_client.scan_iter(match="route:*"):
                if not key.startswith("route:priority:") and not key.startswith("route:unique:"):
                    route_id = key.split(":", 1)[1]
                    if route_id not in route_ids:
                        route = await self.get_route(route_id)
                        if route and route.enabled:
                            routes.append(route)
            
            # Sort by priority (descending)
            routes.sort(key=lambda r: r.priority, reverse=True)
            return routes
            
        except RedisError as e:
            log_error(f"Failed to list routes: {e}", component="redis_storage", error=e)
            return []
    
    async def delete_route(self, route_id: str) -> bool:
        """Delete route and all its indexes."""
        try:
            route = await self.get_route(route_id)
            if not route:
                return False
            
            # Delete route data
            route_key = f"route:{route_id}"
            result1 = bool(await self.redis_client.delete(route_key))
            
            # Delete priority index
            priority_key = f"route:priority:{100 - route.priority:04d}:{route_id}"
            result2 = bool(await self.redis_client.delete(priority_key))
            
            # Delete unique constraint
            path_encoded = base64.b64encode(route.path_pattern.encode()).decode()
            unique_key = f"route:unique:{path_encoded}:{route.priority}"
            result3 = bool(await self.redis_client.delete(unique_key))
            
            return result1 and result2 and result3
        except RedisError as e:
            log_error(f"Failed to delete route: {e}", component="redis_storage", error=e)
            return False
    
    async def initialize_default_routes(self) -> None:
        """Initialize default routing rules that don't already exist."""
        try:
            log_info("Checking default routes...", component="redis_storage")
            
            # Import DEFAULT_ROUTES from proxy module
            from ..proxy.routes import DEFAULT_ROUTES, Route
            
            created_count = 0
            existing_count = 0
            
            for route_dict in DEFAULT_ROUTES:
                route_id = route_dict["route_id"]
                
                # Check if this specific default route already exists
                if await self.get_route(route_id):
                    existing_count += 1
                    continue
                
                # Create the missing default route
                route = Route(**route_dict)
                if await self.store_route(route):
                    log_info(f"Created missing default route: {route.route_id}", component="redis_storage")
                    created_count += 1
                else:
                    log_error(f"Failed to create default route: {route.route_id}", component="redis_storage")
            
            if created_count > 0:
                log_info(f"Created {created_count} missing default routes", component="redis_storage")
            if existing_count > 0:
                log_info(f"Found {existing_count} existing default routes", component="redis_storage")
                    
        except Exception as e:
            log_error(f"Failed to initialize default routes: {e}", component="redis_storage", error=e)
    
    async def initialize_default_proxies(self) -> None:
        """Initialize default proxy configurations and update resource metadata if missing."""
        try:
            log_info("Checking default proxies...", component="redis_storage")
            
            # Import DEFAULT_PROXIES from proxy module
            from ..proxy.models import DEFAULT_PROXIES, ProxyTarget
            from datetime import datetime, timezone
            
            created_count = 0
            updated_count = 0
            existing_count = 0
            
            for proxy_dict in DEFAULT_PROXIES:
                proxy_hostname = proxy_dict["proxy_hostname"]
                
                # Check if this proxy already exists
                existing_proxy = await self.get_proxy_target(proxy_hostname)
                if existing_proxy:
                    # Update localhost proxy with critical settings
                    if proxy_hostname == "localhost":
                        needs_update = False
                        
                        # Always ensure auth_excluded_paths are set for localhost to prevent circular dependency
                        if not existing_proxy.auth_excluded_paths or existing_proxy.auth_excluded_paths != proxy_dict.get("auth_excluded_paths"):
                            existing_proxy.auth_excluded_paths = proxy_dict.get("auth_excluded_paths")
                            needs_update = True
                            log_info(f"Updating auth_excluded_paths for localhost proxy", component="redis_storage")
                        
                        # Update resource metadata if missing
                        if not existing_proxy.resource_endpoint:
                            existing_proxy.resource_endpoint = proxy_dict.get("resource_endpoint")
                            existing_proxy.resource_scopes = proxy_dict.get("resource_scopes")
                            existing_proxy.resource_stateful = proxy_dict.get("resource_stateful", False)
                            existing_proxy.resource_versions = proxy_dict.get("resource_versions")
                            existing_proxy.resource_server_info = proxy_dict.get("resource_server_info")
                            existing_proxy.resource_bearer_methods = proxy_dict.get("resource_bearer_methods")
                            existing_proxy.resource_documentation_suffix = proxy_dict.get("resource_documentation_suffix")
                            existing_proxy.resource_custom_metadata = proxy_dict.get("resource_custom_metadata")
                            needs_update = True
                        
                        if needs_update and await self.store_proxy_target(proxy_hostname, existing_proxy):
                            log_info(f"Updated default proxy configuration: {proxy_hostname}", component="redis_storage")
                            updated_count += 1
                        else:
                            existing_count += 1
                    else:
                        existing_count += 1
                    continue
                
                # Add created_at timestamp
                proxy_dict["created_at"] = datetime.now(timezone.utc)
                
                # Create the missing default proxy
                proxy = ProxyTarget(**proxy_dict)
                if await self.store_proxy_target(proxy_hostname, proxy):
                    log_info(f"Created missing default proxy: {proxy_hostname}", component="redis_storage")
                    created_count += 1
                else:
                    log_error(f"Failed to create default proxy: {proxy_hostname}", component="redis_storage")
            
            if created_count > 0:
                log_info(f"Created {created_count} missing default proxies", component="redis_storage")
            if updated_count > 0:
                log_info(f"Updated {updated_count} default proxies with resource metadata", component="redis_storage")
            if existing_count > 0:
                log_info(f"Found {existing_count} existing default proxies", component="redis_storage")
                    
        except Exception as e:
            log_error(f"Failed to initialize default proxies: {e}", component="redis_storage", error=e)
    
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    # Token method removed - OAuth only authentication
    async def store_auth_config(self, config_id: str, config_data: dict) -> bool:
        """Store authentication configuration.
        
        Args:
            config_id: Unique identifier for this configuration
            config_data: Configuration data dictionary
            
        Returns:
            True if stored successfully
        """
        try:
            # Add timestamps if not present
            if 'created_at' not in config_data:
                config_data['created_at'] = datetime.now(timezone.utc).isoformat()
            config_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            # Store configuration
            key = f"auth:config:pattern:{config_id}"
            result = await self.redis_client.set(key, json.dumps(config_data))
            
            # Add to index for efficient listing
            if result:
                await self.redis_client.sadd("auth:config:index", config_id)
            
            return bool(result)
        except Exception as e:
            log_error(f"Failed to store auth config: {e}", component="redis_storage", error=e)
            return False
    
    async def get_auth_config(self, config_id: str) -> Optional[dict]:
        """Get authentication configuration by ID.
        
        Args:
            config_id: Configuration identifier
            
        Returns:
            Configuration data or None
        """
        try:
            key = f"auth:config:pattern:{config_id}"
            data = await self.redis_client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            log_error(f"Failed to get auth config: {e}", component="redis_storage", error=e)
            return None
    
    async def list_auth_configs(self) -> List[dict]:
        """List all authentication configurations.
        
        Returns:
            List of configuration dictionaries
        """
        try:
            configs = []
            # Use index for efficient listing
            config_ids = await self.redis_client.smembers("auth:config:index")
            
            for config_id in config_ids:
                config = await self.get_auth_config(config_id)
                if config:
                    config['id'] = config_id
                    configs.append(config)
            
            # Sort by priority (highest first)
            configs.sort(key=lambda x: x.get('priority', 50), reverse=True)
            
            return configs
        except Exception as e:
            log_error(f"Failed to list auth configs: {e}", component="redis_storage", error=e)
            return []
    
    async def delete_auth_config(self, config_id: str) -> bool:
        """Delete authentication configuration.
        
        Args:
            config_id: Configuration identifier
            
        Returns:
            True if deleted successfully
        """
        try:
            key = f"auth:config:pattern:{config_id}"
            result = await self.redis_client.delete(key)
            
            # Remove from index
            if result:
                await self.redis_client.srem("auth:config:index", config_id)
                
                # Clear cache entries that might be affected
                # Cache keys follow pattern auth:config:cache:{method}:{path}
                async for cache_key in self.redis_client.scan_iter(match="auth:config:cache:*"):
                    await self.redis_client.delete(cache_key)
            
            return bool(result)
        except Exception as e:
            log_error(f"Failed to delete auth config: {e}", component="redis_storage", error=e)
            return False
    
    async def find_auth_configs_by_pattern(self, path_pattern: str) -> List[dict]:
        """Find all configurations matching a specific path pattern.
        
        Args:
            path_pattern: The path pattern to search for
            
        Returns:
            List of matching configurations
        """
        try:
            configs = []
            all_configs = await self.list_auth_configs()
            
            for config in all_configs:
                if config.get('path_pattern') == path_pattern:
                    configs.append(config)
            
            return configs
        except Exception as e:
            log_error(f"Failed to find auth configs by pattern: {e}", component="redis_storage", error=e)
            return []
    
    async def update_auth_config(self, config_id: str, updates: dict) -> bool:
        """Update authentication configuration.
        
        Args:
            config_id: Configuration identifier
            updates: Dictionary of fields to update
            
        Returns:
            True if updated successfully
        """
        try:
            # Get existing config
            config = await self.get_auth_config(config_id)
            if not config:
                return False
            
            # Apply updates
            config.update(updates)
            config['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            # Store updated config
            return await self.store_auth_config(config_id, config)
        except Exception as e:
            log_error(f"Failed to update auth config: {e}", component="redis_storage", error=e)
            return False
    
    async def clear_auth_config_cache(self) -> int:
        """Clear all cached auth configurations.
        
        Returns:
            Number of cache entries cleared
        """
        try:
            count = 0
            async for cache_key in self.redis_client.scan_iter(match="auth:config:cache:*"):
                if await self.redis_client.delete(cache_key):
                    count += 1
            
            log_info(f"Cleared {count} auth config cache entries", component="redis_storage")
            return count
        except Exception as e:
            log_error(f"Failed to clear auth config cache: {e}", component="redis_storage", error=e)
            return 0
    
    # =====================================================================
    # Logging Methods with Redis Streams
    # =====================================================================
    
    async def initialize_logging(self):
        """Initialize logging stream and consumer group."""
        try:
            # Import the async log storage
            from .async_log_storage import AsyncLogStorage
            self.log_storage = AsyncLogStorage(self.redis_client)
            await self.log_storage.initialize()
            log_info("Async logging initialized with Redis Streams", component="redis_storage")
        except Exception as e:
            log_error(f"Failed to initialize logging: {e}", component="redis_storage", error=e)
            self.log_storage = None
    
    async def log_request(self, log_entry: dict) -> str:
        """Log a request using Redis Streams."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.log_request(log_entry)
        return ""
    
    async def search_logs(self, **kwargs) -> dict:
        """Search logs with filters."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.search_logs(**kwargs)
        return {'total': 0, 'logs': []}
    
    async def get_logs_by_ip(self, ip: str, hours: int = 24, limit: int = 100) -> list:
        """Get logs by IP address."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_logs_by_ip(ip, hours, limit)
        return []
    
    async def get_logs_by_hostname(self, proxy_hostname: str, hours: int = 24, limit: int = 100) -> list:
        """Get logs by hostname."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_logs_by_hostname(hostname, hours, limit)
        return []
    
    async def get_logs_by_proxy(self, proxy_hostname: str, hours: int = 24, limit: int = 100) -> list:
        """Get logs by proxy hostname."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_logs_by_proxy(hostname, hours, limit)
        return []
    
    async def get_logs_by_client(self, client_id: str, hours: int = 24, limit: int = 100) -> list:
        """Get logs by OAuth client ID."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_logs_by_client(client_id, hours, limit)
        return []
    
    async def get_error_logs(self, hours: int = 1, include_4xx: bool = False, limit: int = 50) -> list:
        """Get error logs."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_error_logs(hours, include_4xx, limit)
        return []
    
    async def get_event_statistics(self, hours: int = 24) -> dict:
        """Get event statistics."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_event_statistics(hours)
        return {}
    
    async def get_log_statistics(self, hours: int = 24) -> dict:
        """Get log statistics."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_log_statistics(hours)
        return {}
    
    async def get_oauth_activity(self, ip: str, hours: int = 24, limit: int = 100) -> list:
        """Get OAuth activity for an IP."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_oauth_activity(ip, hours, limit)
        return []
    
    async def get_oauth_debug(self, ip: str, hours: int = 24, limit: int = 100) -> dict:
        """Get OAuth debug information."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.get_oauth_debug(ip, hours, limit)
        return {}
    
    async def track_oauth_flows(self, client_id: str = None, username: str = None, 
                                session_id: str = None, hours: int = 1) -> list:
        """Track OAuth flows."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.track_oauth_flows(client_id, username, session_id, hours)
        return []
    
    async def clear_logs(self) -> int:
        """Clear all logs."""
        if not hasattr(self, 'log_storage') or not self.log_storage:
            await self.initialize_logging()
        
        if self.log_storage:
            return await self.log_storage.clear_logs()
        return 0