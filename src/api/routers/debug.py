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
        
        # OAuth is the only authentication method now
        
        return {
            "app_state_attributes": state_info,
            "has_oauth_components": hasattr(request.app.state, "oauth_components")
        }
    
    @router.get("/routes")
    async def list_routes(request: Request):
        """List all registered routes including mounted apps."""
        routes = []
        for route in request.app.routes:
            if hasattr(route, 'path'):
                routes.append({
                    "path": route.path,
                    "name": getattr(route, 'name', None),
                    "methods": list(getattr(route, 'methods', [])) if hasattr(route, 'methods') else None,
                    "type": type(route).__name__
                })
        return {"routes": routes, "total": len(routes)}
    
    return router