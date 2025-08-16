"""Async DNS resolver with caching for reverse DNS lookups.

DNS Resolution Order:
1. Check cache for previous results
2. Perform system lookup via socket.gethostbyaddr():
   - Checks /etc/hosts first (as per /etc/nsswitch.conf)
   - Falls back to DNS if not found in hosts file
3. Cache the result for performance

This ensures local /etc/hosts entries take priority over DNS.
"""

import asyncio
import socket
import logging
import time
from typing import Dict, Optional, List
from ipaddress import ip_address, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)


class AsyncDNSResolver:
    """Async DNS resolver with caching for performance.
    
    Note: Respects system name resolution order, typically checking
    /etc/hosts before DNS as configured in /etc/nsswitch.conf.
    """
    
    def __init__(self, cache_ttl: int = 3600, skip_private_ips: bool = False):
        """Initialize the DNS resolver.
        
        Args:
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
            skip_private_ips: Whether to skip lookups for private IPs (default: False)
                             Set to True for backward compatibility or to avoid
                             lookups for RFC1918 addresses that won't resolve.
        """
        self.cache_ttl = cache_ttl
        self.skip_private_ips = skip_private_ips
        self._cache: Dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()
    
    async def resolve_ptr(self, ip: str) -> str:
        """Perform reverse DNS lookup for an IP address.
        
        This method respects the system's name resolution order, typically
        checking /etc/hosts before DNS as configured in /etc/nsswitch.conf.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            FQDN if found, otherwise the original IP address
        """
        # Validate IP address
        try:
            ip_obj = ip_address(ip)
        except ValueError:
            logger.debug(f"Invalid IP address: {ip}")
            return ip
        
        # Optionally skip private IPs (for backward compatibility)
        if self.skip_private_ips and (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
            logger.debug(f"Skipping lookup for private/local IP: {ip} (skip_private_ips=True)")
            return ip
        
        # Check cache
        async with self._lock:
            if ip in self._cache:
                fqdn, timestamp = self._cache[ip]
                if time.time() - timestamp < self.cache_ttl:
                    logger.debug(f"Cache hit for {ip}: {fqdn}")
                    return fqdn
                else:
                    # Remove expired entry
                    del self._cache[ip]
        
        # Perform lookup (checks /etc/hosts first, then DNS)
        try:
            logger.debug(f"Performing reverse lookup for {ip} (checks /etc/hosts then DNS)")
            
            # socket.gethostbyaddr respects system resolution order:
            # typically /etc/hosts first, then DNS
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                socket.gethostbyaddr,
                ip
            )
            
            fqdn = result[0] if result else ip
            
            # Cache the result
            async with self._lock:
                self._cache[ip] = (fqdn, time.time())
            
            logger.debug(f"Resolved {ip} to {fqdn}")
            return fqdn
            
        except (socket.herror, socket.gaierror, socket.timeout) as e:
            # Lookup failed - this is expected for many IPs without PTR records
            logger.debug(f"Lookup failed for {ip}: {e}")
            
            # Cache the failure to avoid repeated lookups
            async with self._lock:
                self._cache[ip] = (ip, time.time())
            
            return ip
        except Exception as e:
            # Unexpected error
            logger.warning(f"Unexpected error during DNS lookup for {ip}: {e}")
            return ip
    
    async def batch_resolve(self, ips: List[str]) -> Dict[str, str]:
        """Resolve multiple IP addresses concurrently.
        
        Args:
            ips: List of IP addresses to resolve
            
        Returns:
            Dictionary mapping IP addresses to FQDNs
        """
        # Create tasks for all IPs
        tasks = [self.resolve_ptr(ip) for ip in ips]
        
        # Run concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build result dictionary
        resolved = {}
        for ip, result in zip(ips, results):
            if isinstance(result, Exception):
                logger.warning(f"Failed to resolve {ip}: {result}")
                resolved[ip] = ip
            else:
                resolved[ip] = result
        
        return resolved
    
    def clear_cache(self):
        """Clear the DNS cache."""
        self._cache.clear()
        logger.info("DNS cache cleared")
    
    async def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        async with self._lock:
            total_entries = len(self._cache)
            
            # Count valid vs expired entries
            current_time = time.time()
            valid_entries = sum(
                1 for _, (_, timestamp) in self._cache.items()
                if current_time - timestamp < self.cache_ttl
            )
            expired_entries = total_entries - valid_entries
            
            return {
                "total_entries": total_entries,
                "valid_entries": valid_entries,
                "expired_entries": expired_entries,
                "cache_ttl": self.cache_ttl
            }


# Global resolver instance
_resolver: Optional[AsyncDNSResolver] = None


def get_dns_resolver() -> AsyncDNSResolver:
    """Get the global DNS resolver instance.
    
    Returns:
        The global AsyncDNSResolver instance
    """
    global _resolver
    if _resolver is None:
        _resolver = AsyncDNSResolver()
    return _resolver


async def resolve_ip_to_fqdn(ip: str) -> str:
    """Convenience function to resolve an IP to FQDN.
    
    Args:
        ip: IP address to resolve
        
    Returns:
        FQDN if found, otherwise the original IP address
    """
    resolver = get_dns_resolver()
    return await resolver.resolve_ptr(ip)