"""Debug router to check app state."""

from fastapi import APIRouter, Request

def create_debug_router() -> APIRouter:
    """Create debug router."""
    router = APIRouter(tags=["debug"])
    
    @router.get("/app-state")
    async def check_app_state(request: Request):
        """Check what's in app.state."""
        state_info = {}
        
        # List all attributes
        for attr in dir(request.app.state):
            if not attr.startswith('_'):
                try:
                    value = getattr(request.app.state, attr, None)
                    if value is not None:
                        state_info[attr] = type(value).__name__
                except Exception as e:
                    state_info[attr] = f"error: {e}"
        
        # Check admin token safely
        admin_token_configured = None
        if hasattr(request.app.state, "auth_service"):
            try:
                auth_service = request.app.state.auth_service
                if hasattr(auth_service, "admin_token"):
                    admin_token_configured = bool(auth_service.admin_token)
            except:
                pass
        
        return {
            "app_state_attributes": state_info,
            "has_auth_service": hasattr(request.app.state, "auth_service"),
            "admin_token_configured": admin_token_configured
        }
    
    @router.post("/test-auth")
    async def test_auth(request: Request, token: str):
        """Test auth validation directly."""
        if not hasattr(request.app.state, "auth_service"):
            return {"error": "No auth_service in app.state"}
        
        auth_service = request.app.state.auth_service
        
        # Test validation
        validation = await auth_service.validate_bearer_token(token)
        
        return {
            "token_preview": token[:20] + "..." if len(token) > 20 else token,
            "valid": validation.valid,
            "is_admin": validation.is_admin,
            "token_name": validation.token_name,
            "error": validation.error,
            "auth_service_type": type(auth_service).__name__,
            "auth_service_has_storage": hasattr(auth_service, "storage") and auth_service.storage is not None,
            "admin_token_configured": bool(auth_service.admin_token) if hasattr(auth_service, "admin_token") else None
        }
    
    return router