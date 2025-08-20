"""Default authentication configurations and migration support.

This module provides default auth configurations and tools for
migrating from the old auth system to the flexible auth system.
"""

import logging
import json
from typing import List, Dict, Any
from datetime import datetime, timezone

from .models import EndpointAuthConfig

logger = logging.getLogger(__name__)


# Default endpoint auth configurations
DEFAULT_ENDPOINT_CONFIGS: List[Dict[str, Any]] = [
    # Admin-only endpoints
    {
        "path_pattern": "/api/v1/tokens/*",
        "methods": ["*"],
        "auth_type": "admin",
        "priority": 90,
        "description": "Token management - admin only",
        "enabled": True
    },
    {
        "path_pattern": "/api/v1/auth/*",
        "methods": ["*"],
        "auth_type": "admin",
        "priority": 90,
        "description": "Auth configuration - admin only",
        "enabled": True
    },
    {
        "path_pattern": "/api/v1/auth-config/*",
        "methods": ["*"],
        "auth_type": "admin",
        "priority": 90,
        "description": "Legacy auth configuration - admin only",
        "enabled": True
    },
    
    # Bearer auth for most API endpoints
    {
        "path_pattern": "/api/v1/certificates/*",
        "methods": ["POST", "PUT", "DELETE"],
        "auth_type": "bearer",
        "bearer_check_owner": True,
        "owner_param": "cert_name",
        "priority": 80,
        "description": "Certificate management - owner or admin",
        "enabled": True
    },
    {
        "path_pattern": "/api/v1/proxy/*",
        "methods": ["POST", "PUT", "DELETE"],
        "auth_type": "bearer",
        "bearer_check_owner": True,
        "owner_param": "hostname",
        "priority": 80,
        "description": "Proxy management - owner or admin",
        "enabled": True
    },
    {
        "path_pattern": "/api/v1/routes/*",
        "methods": ["POST", "PUT", "DELETE"],
        "auth_type": "bearer",
        "bearer_check_owner": True,
        "owner_param": "route_id",
        "priority": 80,
        "description": "Route management - owner or admin",
        "enabled": True
    },
    {
        "path_pattern": "/api/v1/services/*",
        "methods": ["POST", "PUT", "DELETE"],
        "auth_type": "bearer",
        "bearer_check_owner": True,
        "owner_param": "service_name",
        "priority": 80,
        "description": "Service management - owner or admin",
        "enabled": True
    },
    
    # Read operations require bearer auth
    {
        "path_pattern": "/api/v1/*",
        "methods": ["GET"],
        "auth_type": "bearer",
        "priority": 70,
        "description": "API read operations - any valid token",
        "enabled": True
    },
    
    # OAuth endpoints
    {
        "path_pattern": "/oauth/*",
        "methods": ["*"],
        "auth_type": "none",
        "priority": 100,
        "description": "OAuth endpoints - public",
        "enabled": True
    },
    {
        "path_pattern": "/.well-known/*",
        "methods": ["*"],
        "auth_type": "none",
        "priority": 100,
        "description": "Well-known endpoints - public",
        "enabled": True
    },
    
    # Health and status endpoints
    {
        "path_pattern": "/health",
        "methods": ["GET"],
        "auth_type": "none",
        "priority": 100,
        "description": "Health check - public",
        "enabled": True
    },
    {
        "path_pattern": "/",
        "methods": ["GET"],
        "auth_type": "none",
        "priority": 100,
        "description": "Root/UI - public",
        "enabled": True
    },
    {
        "path_pattern": "/favicon.ico",
        "methods": ["GET"],
        "auth_type": "none",
        "priority": 100,
        "description": "Favicon - public",
        "enabled": True
    },
    {
        "path_pattern": "/static/*",
        "methods": ["GET"],
        "auth_type": "none",
        "priority": 100,
        "description": "Static assets - public",
        "enabled": True
    },
    
    # Default fallback for API - require bearer auth
    {
        "path_pattern": "/api/*",
        "methods": ["*"],
        "auth_type": "bearer",
        "priority": 10,
        "description": "Default API auth - bearer token required",
        "enabled": True
    },
    
    # Default for everything else - public
    {
        "path_pattern": "*",
        "methods": ["*"],
        "auth_type": "none",
        "priority": 0,
        "description": "Default - public access",
        "enabled": True
    }
]


async def load_default_configs(storage):
    """Load default endpoint auth configurations into storage.
    
    Args:
        storage: AsyncRedisStorage instance
    """
    loaded_count = 0
    
    for config_dict in DEFAULT_ENDPOINT_CONFIGS:
        try:
            # Generate config ID
            import hashlib
            config_id = hashlib.md5(
                f"{config_dict['path_pattern']}:{'-'.join(config_dict['methods'])}".encode()
            ).hexdigest()[:16]
            
            # Check if already exists
            existing = await storage.redis_client.get(f"auth:endpoint:{config_id}")
            if existing:
                logger.debug(f"Config already exists for {config_dict['path_pattern']}")
                continue
            
            # Add metadata
            config_dict["config_id"] = config_id
            config_dict["created_at"] = datetime.now(timezone.utc).isoformat()
            config_dict["created_by"] = "system"
            
            # Store config
            await storage.redis_client.set(
                f"auth:endpoint:{config_id}",
                json.dumps(config_dict)
            )
            
            loaded_count += 1
            logger.info(f"Loaded default config for {config_dict['path_pattern']}")
            
        except Exception as e:
            logger.error(f"Failed to load default config: {e}")
    
    logger.info(f"Loaded {loaded_count} default auth configurations")
    return loaded_count


async def migrate_from_old_auth(storage):
    """Migrate from old auth system to flexible auth system.
    
    This function analyzes existing auth patterns and creates
    equivalent configurations in the new system.
    
    Args:
        storage: AsyncRedisStorage instance
    """
    migrated_count = 0
    
    try:
        # Check for existing auth configs from old system
        # Old system used auth:config:pattern:* keys
        old_configs = []
        async for key in storage.redis_client.scan_iter(match="auth:config:pattern:*"):
            if isinstance(key, bytes):
                key = key.decode('utf-8')
            
            config_data = await storage.redis_client.get(key)
            if config_data:
                try:
                    config = json.loads(config_data)
                    old_configs.append(config)
                except Exception as e:
                    logger.error(f"Invalid old config: {e}")
        
        logger.info(f"Found {len(old_configs)} old auth configurations to migrate")
        
        # Migrate each old config
        for old_config in old_configs:
            try:
                # Map old auth type to new
                auth_type = old_config.get("auth_type", "bearer")
                if auth_type == "unified":
                    # Old unified auth - determine actual type
                    if old_config.get("oauth_scopes"):
                        auth_type = "oauth"
                    elif old_config.get("require_admin"):
                        auth_type = "admin"
                    else:
                        auth_type = "bearer"
                
                # Create new config
                new_config = {
                    "path_pattern": old_config.get("path_pattern", "*"),
                    "methods": [old_config.get("method", "*")],
                    "auth_type": auth_type,
                    "priority": old_config.get("priority", 50),
                    "description": old_config.get("description", "Migrated from old system"),
                    "enabled": old_config.get("enabled", True),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "created_by": "migration"
                }
                
                # Add OAuth settings if applicable
                if auth_type == "oauth":
                    new_config["oauth_scopes"] = old_config.get("oauth_scopes", [])
                    new_config["oauth_allowed_users"] = old_config.get("oauth_allowed_users", [])
                    new_config["oauth_resource"] = old_config.get("oauth_resource")
                
                # Add ownership settings if applicable
                if old_config.get("owner_validation"):
                    new_config["bearer_check_owner"] = True
                    new_config["owner_param"] = old_config.get("owner_param")
                
                # Generate config ID
                import hashlib
                config_id = hashlib.md5(
                    f"{new_config['path_pattern']}:migrated:{migrated_count}".encode()
                ).hexdigest()[:16]
                
                new_config["config_id"] = config_id
                
                # Store new config
                await storage.redis_client.set(
                    f"auth:endpoint:{config_id}",
                    json.dumps(new_config)
                )
                
                migrated_count += 1
                logger.info(f"Migrated config for {new_config['path_pattern']}")
                
            except Exception as e:
                logger.error(f"Failed to migrate config: {e}")
        
        # Optionally delete old configs after successful migration
        # for key in old_config_keys:
        #     await storage.redis_client.delete(key)
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
    
    logger.info(f"Migrated {migrated_count} auth configurations")
    return migrated_count


async def initialize_auth_system(storage, load_defaults=True, migrate=True):
    """Initialize the flexible auth system.
    
    Args:
        storage: AsyncRedisStorage instance
        load_defaults: Whether to load default configurations
        migrate: Whether to migrate from old system
    """
    logger.info("Initializing flexible auth system")
    
    # Check if already initialized
    initialized = await storage.redis_client.get("auth:system:initialized")
    if initialized:
        logger.info("Auth system already initialized")
        return
    
    results = {
        "defaults_loaded": 0,
        "configs_migrated": 0
    }
    
    # Load default configurations
    if load_defaults:
        results["defaults_loaded"] = await load_default_configs(storage)
    
    # Migrate from old system
    if migrate:
        results["configs_migrated"] = await migrate_from_old_auth(storage)
    
    # Mark as initialized
    await storage.redis_client.set(
        "auth:system:initialized",
        json.dumps({
            "initialized_at": datetime.now(timezone.utc).isoformat(),
            "defaults_loaded": results["defaults_loaded"],
            "configs_migrated": results["configs_migrated"]
        })
    )
    
    logger.info(f"Auth system initialized: {results}")
    return results