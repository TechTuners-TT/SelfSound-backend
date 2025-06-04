from fastapi import Request, HTTPException
from supabase_client import supabase
from jwt_handler import decode_jwt
import logging

logger = logging.getLogger(__name__)

async def get_verified_user(request: Request) -> dict:
    """
    Enhanced user verification supporting both mobile and web authentication
    """
    token = None
    
    # Mobile first: Authorization header
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        logger.info("Using mobile auth (Authorization header)")
    else:
        # Web fallback: cookies
        token = request.cookies.get("access_token")
        if token:
            logger.info("Using web auth (cookies)")
    
    if not token:
        logger.warning("No authentication token found")
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode JWT
        payload = decode_jwt(token)
        email = payload.get("email")
        
        if not email:
            logger.error("No email in token payload")
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Extract login for user_profiles table
        login = email.split("@")[0]
        
        # Query user_profiles table
        user_resp = supabase.from_("user_profiles").select("*").eq("login", login).single().execute()
        
        if not user_resp.data:
            logger.error(f"User not found: {login}")
            raise HTTPException(status_code=404, detail="User not found")
        
        user_data = user_resp.data
        logger.info(f"User authenticated: {login}")
        
        return user_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")
