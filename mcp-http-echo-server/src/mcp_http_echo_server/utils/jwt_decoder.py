"""JWT token decoder utility (no signature verification)."""

import base64
import json
import logging
from typing import Any, Dict, Optional
import binascii

logger = logging.getLogger(__name__)

JWT_PARTS_COUNT = 3


def decode_jwt_token(
    token: str,
    verify_signature: bool = False
) -> Optional[Dict[str, Any]]:
    """Decode a JWT token without signature verification.
    
    Args:
        token: JWT token string
        verify_signature: Whether to verify signature (not implemented)
        
    Returns:
        Decoded token data or None if invalid
    """
    if not token:
        return None
    
    # Remove Bearer prefix if present
    if token.lower().startswith("bearer "):
        token = token[7:]
    
    try:
        # Split JWT parts
        parts = token.split(".")
        if len(parts) != JWT_PARTS_COUNT:
            logger.debug(f"Invalid JWT format: expected {JWT_PARTS_COUNT} parts, got {len(parts)}")
            return None
        
        # Decode header
        header_data = parts[0]
        header_padded = header_data + "=" * (4 - len(header_data) % 4)
        header_json = json.loads(base64.urlsafe_b64decode(header_padded))
        
        # Decode payload
        payload_data = parts[1]
        payload_padded = payload_data + "=" * (4 - len(payload_data) % 4)
        payload_json = json.loads(base64.urlsafe_b64decode(payload_padded))
        
        # Note: We don't verify the signature (parts[2])
        # This is intentional for debugging purposes
        
        return {
            "header": header_json,
            "payload": payload_json,
            "signature_present": bool(parts[2]),
            "raw": {
                "header": parts[0],
                "payload": parts[1],
                "signature": parts[2][:50] + "..." if len(parts[2]) > 50 else parts[2]
            }
        }
        
    except (json.JSONDecodeError, ValueError, binascii.Error, IndexError) as e:
        logger.debug(f"Error decoding JWT: {e}")
        return None


def format_jwt_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Format JWT claims for display.
    
    Args:
        payload: JWT payload
        
    Returns:
        Formatted claims
    """
    import time
    from datetime import datetime, UTC
    
    formatted = {}
    current_time = int(time.time())
    
    # Standard claims
    if "iss" in payload:
        formatted["issuer"] = payload["iss"]
    if "sub" in payload:
        formatted["subject"] = payload["sub"]
    if "aud" in payload:
        formatted["audience"] = payload["aud"]
    if "jti" in payload:
        formatted["jwt_id"] = payload["jti"]
    
    # Time claims with human-readable format
    if "iat" in payload:
        iat = payload["iat"]
        formatted["issued_at"] = {
            "timestamp": iat,
            "iso": datetime.fromtimestamp(iat, tz=UTC).isoformat(),
            "age_seconds": current_time - iat
        }
    
    if "exp" in payload:
        exp = payload["exp"]
        is_expired = exp < current_time
        formatted["expires"] = {
            "timestamp": exp,
            "iso": datetime.fromtimestamp(exp, tz=UTC).isoformat(),
            "is_expired": is_expired,
            "seconds_until_expiry": exp - current_time if not is_expired else None,
            "seconds_since_expiry": current_time - exp if is_expired else None
        }
    
    if "nbf" in payload:
        nbf = payload["nbf"]
        is_valid = nbf <= current_time
        formatted["not_before"] = {
            "timestamp": nbf,
            "iso": datetime.fromtimestamp(nbf, tz=UTC).isoformat(),
            "is_valid": is_valid,
            "seconds_until_valid": nbf - current_time if not is_valid else None
        }
    
    # Custom claims
    standard_claims = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}
    custom_claims = {k: v for k, v in payload.items() if k not in standard_claims}
    if custom_claims:
        formatted["custom_claims"] = custom_claims
    
    return formatted