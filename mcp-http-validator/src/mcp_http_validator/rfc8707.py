"""RFC 8707 Resource Indicators for OAuth 2.0 validation."""

from typing import Dict, List, Optional, Tuple
import jwt


class RFC8707Validator:
    """Validates OAuth 2.0 Resource Indicators implementation per RFC 8707."""
    
    @staticmethod
    def validate_authorization_request(
        auth_url: str,
        expected_resources: List[str]
    ) -> Tuple[bool, List[str]]:
        """Validate that authorization request includes resource parameters.
        
        Args:
            auth_url: Full authorization URL with parameters
            expected_resources: Resources that should be requested
            
        Returns:
            Tuple of (has_resources, found_resources)
        """
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)
        
        # RFC 8707: Multiple resource parameters allowed
        resources = params.get('resource', [])
        
        return len(resources) > 0, resources
    
    @staticmethod
    def validate_token_response(
        token: str,
        requested_resources: List[str],
        verify_signature: bool = False
    ) -> Tuple[bool, Dict[str, any]]:
        """Validate token response for RFC 8707 compliance.
        
        Args:
            token: JWT access token
            requested_resources: Resources that were requested
            verify_signature: Whether to verify JWT signature
            
        Returns:
            Tuple of (is_compliant, validation_details)
        """
        validation = {
            "rfc8707_compliant": False,
            "requested_resources": requested_resources,
            "token_audience": None,
            "missing_resources": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # Decode token without verification (signature check is separate concern)
            claims = jwt.decode(token, options={"verify_signature": False})
            
            # Get audience claim
            aud = claims.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            validation["token_audience"] = aud
            
            # RFC 8707 Section 3: Token MUST contain requested resources in audience
            missing = [r for r in requested_resources if r not in aud]
            validation["missing_resources"] = missing
            
            if missing:
                validation["errors"].append(
                    f"RFC 8707 violation: Token audience missing requested resources: {missing}"
                )
                validation["errors"].append(
                    "OAuth server accepted 'resource' parameter but did not include it in token audience claim"
                )
            else:
                validation["rfc8707_compliant"] = True
                
            # Additional checks
            if not aud:
                validation["warnings"].append("Token has no audience claim at all")
            
            # Check for resource_indicators_supported in metadata
            if 'iss' in claims:
                validation["warnings"].append(
                    f"Verify that {claims['iss']} advertises 'resource_indicators_supported: true'"
                )
                
        except Exception as e:
            validation["errors"].append(f"Failed to decode token: {str(e)}")
            
        return validation["rfc8707_compliant"], validation
    
    @staticmethod
    def validate_resource_server_check(
        server_url: str,
        token_accepted: bool,
        token_audience: List[str]
    ) -> Tuple[bool, Dict[str, any]]:
        """Validate resource server's audience validation.
        
        Args:
            server_url: The MCP server URL
            token_accepted: Whether server accepted the token
            token_audience: Audience claims in the token
            
        Returns:
            Tuple of (is_compliant, validation_details)
        """
        validation = {
            "server_compliant": False,
            "server_url": server_url,
            "token_audience": token_audience,
            "errors": [],
            "security_risk": None
        }
        
        # Check if server URL is in audience
        server_in_audience = server_url in token_audience
        
        if token_accepted and not server_in_audience:
            validation["errors"].append(
                f"RFC 8707 violation: Server accepted token without its URL in audience"
            )
            validation["errors"].append(
                f"Expected '{server_url}' in token audience but found: {token_audience}"
            )
            validation["security_risk"] = (
                "CRITICAL: Token confusion attack possible - server accepts tokens "
                "intended for other services"
            )
        elif not token_accepted and server_in_audience:
            # Server correctly rejected - but for wrong reason?
            validation["server_compliant"] = True
            validation["warnings"] = ["Server rejected valid token - check other validation"]
        elif token_accepted and server_in_audience:
            validation["server_compliant"] = True
        else:
            # Not accepted and not in audience - correct behavior
            validation["server_compliant"] = True
            
        return validation["server_compliant"], validation
    
    @staticmethod
    def generate_report(
        auth_request_valid: bool,
        auth_resources: List[str],
        token_validation: Dict[str, any],
        server_validation: Dict[str, any]
    ) -> str:
        """Generate human-readable RFC 8707 compliance report.
        
        Returns:
            Formatted compliance report
        """
        lines = []
        lines.append("RFC 8707 Resource Indicators Compliance Report")
        lines.append("=" * 50)
        
        # Authorization Request
        lines.append("\n1. Authorization Request:")
        if auth_request_valid:
            lines.append(f"   ✓ Includes 'resource' parameter(s): {auth_resources}")
        else:
            lines.append("   ✗ Missing 'resource' parameter")
            
        # Token Response
        lines.append("\n2. OAuth Server Token Response:")
        if token_validation["rfc8707_compliant"]:
            lines.append("   ✓ RFC 8707 compliant - resources in token audience")
        else:
            lines.append("   ✗ RFC 8707 VIOLATION")
            for error in token_validation["errors"]:
                lines.append(f"      • {error}")
                
        lines.append(f"\n   Token audience: {token_validation['token_audience']}")
        lines.append(f"   Requested resources: {token_validation['requested_resources']}")
        
        # Resource Server
        lines.append("\n3. MCP Resource Server Validation:")
        if server_validation["server_compliant"]:
            lines.append("   ✓ Server audience validation working")
        else:
            lines.append("   ✗ RFC 8707 VIOLATION") 
            for error in server_validation["errors"]:
                lines.append(f"      • {error}")
                
        if server_validation.get("security_risk"):
            lines.append(f"\n   ⚠️  {server_validation['security_risk']}")
            
        # Summary
        lines.append("\n" + "=" * 50)
        if not token_validation["rfc8707_compliant"] and not server_validation["server_compliant"]:
            lines.append("RESULT: Both OAuth server and MCP server violate RFC 8707")
            lines.append("        This creates a critical security vulnerability!")
        elif not token_validation["rfc8707_compliant"]:
            lines.append("RESULT: OAuth server violates RFC 8707 (missing audience restriction)")
        elif not server_validation["server_compliant"]:
            lines.append("RESULT: MCP server violates RFC 8707 (no audience validation)")
        else:
            lines.append("RESULT: Full RFC 8707 compliance ✓")
            
        return "\n".join(lines)