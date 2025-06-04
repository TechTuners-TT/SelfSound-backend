from fastapi import Request, HTTPException
from supabase_client import supabase
from jwt_handler import decode_jwt
import logging

logger = logging.getLogger(__name__)

async def get_verified_user(request: Request) -> dict:
    """
    QUICK FIX: Enhanced token detection for mobile deployment
    """
    token = None
    
    # Check ALL possible token locations
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        logger.info("✅ Token found in Authorization header")
    elif request.cookies.get("access_token"):
        token = request.cookies.get("access_token")
        logger.info("✅ Token found in cookies")
    elif request.query_params.get("token"):
        token = request.query_params.get("token")
        logger.info("✅ Token found in query params")
    elif request.headers.get("x-access-token"):
        token = request.headers.get("x-access-token")
        logger.info("✅ Token found in X-Access-Token header")
    elif request.headers.get("access-token"):
        token = request.headers.get("access-token")
        logger.info("✅ Token found in Access-Token header")
    
    # DEBUGGING: Log what we actually receive
    logger.info(f"🔍 Available headers: {list(request.headers.keys())}")
    logger.info(f"🔍 Available cookies: {list(request.cookies.keys())}")
    logger.info(f"🔍 Query params: {dict(request.query_params)}")
    logger.info(f"🔍 User-Agent: {request.headers.get('user-agent', 'Unknown')}")
    
    if not token:
        logger.error("❌ [get_verified_user] No token found in any location")
        # For debugging - log everything we can see
        logger.error(f"Headers: {dict(request.headers)}")
        logger.error(f"Cookies: {dict(request.cookies)}")
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
        logger.info(f"✅ User authenticated: {login}")
        
        return user_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Auth failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")
