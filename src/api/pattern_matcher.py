"""Pattern matching engine for authentication configuration."""

import re
import fnmatch
import logging
from typing import List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """Result of a pattern match operation."""
    matched: bool
    pattern: str
    priority: int
    params: dict = None
    
    def __lt__(self, other):
        """Compare by priority (higher is better)."""
        return self.priority < other.priority


class PathPatternMatcher:
    """Pattern matching engine for URL paths.
    
    Supports various pattern types:
    - Exact match: /api/v1/tokens/
    - Wildcard: /api/v1/tokens/*
    - Recursive: /api/v1/**
    - Parameter: /api/v1/tokens/{name}
    """
    
    def __init__(self):
        self._pattern_cache = {}
        
    def match(self, pattern: str, path: str, method: str = "*") -> Tuple[bool, dict]:
        """Check if a path matches a pattern.
        
        Args:
            pattern: The pattern to match against
            path: The actual request path
            method: The HTTP method (for method-specific patterns)
            
        Returns:
            Tuple of (matched, params) where params contains extracted parameters
        """
        # Check if pattern is method-specific
        if ":" in pattern:
            pattern_method, pattern_path = pattern.split(":", 1)
            if pattern_method != "*" and pattern_method != method:
                return False, {}
        else:
            pattern_path = pattern
        
        # Normalize paths
        pattern_path = self._normalize(pattern_path)
        path = self._normalize(path)
        
        # Try different matching strategies
        params = {}
        
        # 1. Exact match
        if pattern_path == path:
            return True, params
        
        # 2. Wildcard match (using fnmatch)
        if "*" in pattern_path:
            # Convert to fnmatch pattern
            if "**" in pattern_path:
                # Recursive wildcard - match any number of path segments
                regex_pattern = pattern_path.replace("**", ".*")
                if re.match(f"^{regex_pattern}$", path):
                    return True, params
            elif fnmatch.fnmatch(path, pattern_path):
                return True, params
        
        # 3. Parameter extraction (e.g., /api/v1/tokens/{name})
        if "{" in pattern_path and "}" in pattern_path:
            regex_pattern, param_names = self._pattern_to_regex(pattern_path)
            match = re.match(regex_pattern, path)
            if match:
                params = dict(zip(param_names, match.groups()))
                return True, params
        
        return False, {}
    
    def find_best_match(self, patterns: List[dict], path: str, method: str) -> Optional[dict]:
        """Find the best matching pattern for a given path and method.
        
        Args:
            patterns: List of pattern configurations
            path: The request path
            method: The HTTP method
            
        Returns:
            The best matching pattern configuration, or None
        """
        matches = []
        
        for pattern_config in patterns:
            # Skip disabled patterns
            if not pattern_config.get("enabled", True):
                continue
            
            pattern = pattern_config.get("path_pattern", "")
            pattern_method = pattern_config.get("method", "*")
            
            # Check method match
            if pattern_method != "*" and pattern_method != method:
                continue
            
            # Check path match
            matched, params = self.match(pattern, path, method)
            if matched:
                match = PatternMatch(
                    matched=True,
                    pattern=pattern,
                    priority=pattern_config.get("priority", 50),
                    params=params
                )
                matches.append((match, pattern_config))
        
        if not matches:
            return None
        
        # Sort by priority (highest first)
        matches.sort(key=lambda x: x[0].priority, reverse=True)
        
        # Return the configuration of the best match
        best_match, config = matches[0]
        
        # Add extracted parameters to the config
        if best_match.params:
            config = config.copy()
            config["extracted_params"] = best_match.params
        
        logger.debug(
            f"Pattern matching result",
            extra={
                "path": path,
                "method": method,
                "matched_pattern": best_match.pattern,
                "priority": best_match.priority,
                "params": best_match.params
            }
        )
        
        return config
    
    def _normalize(self, path: str) -> str:
        """Normalize a path for matching.
        
        Args:
            path: The path to normalize
            
        Returns:
            Normalized path
        """
        # Remove duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")
        
        # Ensure it starts with /
        if not path.startswith("/"):
            path = "/" + path
        
        return path
    
    def _pattern_to_regex(self, pattern: str) -> Tuple[str, List[str]]:
        """Convert a pattern with {param} placeholders to regex.
        
        Args:
            pattern: Pattern with placeholders
            
        Returns:
            Tuple of (regex_pattern, param_names)
        """
        cache_key = pattern
        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]
        
        param_names = []
        regex_parts = []
        
        # Split pattern into parts
        parts = pattern.split("/")
        
        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                # This is a parameter
                param_name = part[1:-1]
                param_names.append(param_name)
                # Match anything except /
                regex_parts.append("([^/]+)")
            elif part == "*":
                # Single wildcard - match one segment
                regex_parts.append("[^/]+")
            elif part == "**":
                # Recursive wildcard - match any number of segments
                regex_parts.append(".*")
            else:
                # Literal part - escape special regex characters
                regex_parts.append(re.escape(part))
        
        regex_pattern = "^" + "/".join(regex_parts) + "$"
        
        result = (regex_pattern, param_names)
        self._pattern_cache[cache_key] = result
        
        return result
    
    def test_patterns(self, patterns: List[dict], path: str, method: str = "GET") -> dict:
        """Test which patterns match a given path.
        
        Args:
            patterns: List of pattern configurations
            path: The path to test
            method: The HTTP method to test
            
        Returns:
            Test results including all matches and the effective pattern
        """
        all_matches = []
        
        for pattern_config in patterns:
            pattern = pattern_config.get("path_pattern", "")
            pattern_method = pattern_config.get("method", "*")
            
            # Check if this pattern could match this method
            method_match = pattern_method == "*" or pattern_method == method
            
            # Check path match
            path_match, params = self.match(pattern, path, method)
            
            if method_match and path_match:
                all_matches.append({
                    "pattern": pattern,
                    "method": pattern_method,
                    "priority": pattern_config.get("priority", 50),
                    "auth_type": pattern_config.get("auth_type"),
                    "description": pattern_config.get("description", ""),
                    "params": params
                })
        
        # Sort by priority
        all_matches.sort(key=lambda x: x["priority"], reverse=True)
        
        effective = all_matches[0] if all_matches else None
        
        return {
            "path": path,
            "method": method,
            "all_matches": all_matches,
            "effective": effective,
            "match_count": len(all_matches)
        }