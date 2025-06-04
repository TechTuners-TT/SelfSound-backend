from fastapi import APIRouter, HTTPException, Request
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase
from typing import Optional
from pydantic import BaseModel
import logging

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/profile", tags=["Profile"])

def get_token_from_request(request: Request) -> Optional[str]:
    """
    Enhanced token extraction that supports both mobile (Authorization header) 
    and web (cookies) authentication methods
    """
    # Method 1: Check Authorization header (for mobile apps)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer " prefix
        logger.info("🔑 Token found in Authorization header")
        return token
    
    # Method 2: Check cookies (for web browsers)
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        logger.info("🍪 Token found in cookies")
        return cookie_token
    
    logger.warning("❌ No token found in Authorization header or cookies")
    return None

def get_verified_user(request: Request):
    """
    Enhanced user verification that supports both mobile and web authentication
    """
    # Detect device type from User-Agent
    user_agent = request.headers.get("user-agent", "").lower()
    is_mobile = any(keyword in user_agent for keyword in ['mobile', 'android', 'iphone', 'ipad'])
    is_ios = any(keyword in user_agent for keyword in ['iphone', 'ipad', 'ipod'])
    is_safari = 'safari' in user_agent and 'chrome' not in user_agent
    
    logger.info(f"📱 Device detection - Mobile: {is_mobile}, iOS: {is_ios}, Safari: {is_safari}")
    
    # Get token using enhanced method
    token = get_token_from_request(request)
    if not token:
        logger.error(f"❌ [get_verified_user] No token found (Mobile: {is_mobile}, iOS Safari: {is_ios and is_safari})")
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode and verify the JWT token
        payload = decode_jwt(token)
        email = payload.get("email")
        if not email:
            logger.error("❌ No email found in token payload")
            raise HTTPException(status_code=401, detail="Invalid token format")
        
        login = email.split("@")[0]
        logger.info(f"✅ Token decoded successfully for user: {login}")
        
        # Fetch user profile from database
        user = supabase.from_("user_profiles").select("*").eq("login", login).single().execute()
        if not user.data:
            logger.error(f"❌ User profile not found for login: {login}")
            raise HTTPException(status_code=404, detail="User profile not found")
        
        logger.info(f"✅ User verified: {login} (Mobile: {is_mobile})")
        return user.data
        
    except Exception as e:
        logger.error(f"❌ Token verification failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token or user not found")

@router.get("/me/profile")
def get_current_user(request: Request):
    """Get current user profile - supports both mobile and web authentication"""
    try:
        user_data = get_verified_user(request)
        logger.info(f"✅ Profile fetched for user: {user_data.get('login')}")
        return user_data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error fetching profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch profile")

# Request body schema
class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    login: Optional[str] = None

@router.patch("/me")
def update_user_profile(request: Request, body: UpdateProfileRequest):
    """Update user profile - supports both mobile and web authentication"""
    try:
        # Get current user using enhanced verification
        current_user = get_verified_user(request)
        current_login = current_user.get("login")
        
        logger.info(f"🔄 Updating profile for user: {current_login}")

        # Prepare only provided fields
        update_data = {}
        if body.name is not None:
            update_data["name"] = body.name

        if body.avatar_url is not None:
            update_data["avatar_url"] = body.avatar_url

        if body.login is not None:
            update_data["login"] = body.login

        # Prevent updating to a login that already exists
        if body.login and body.login != current_login:
            duplicate = supabase.from_("user_profiles").select("id").eq("login", body.login).execute()
            if duplicate.data:
                logger.warning(f"❌ Login already taken: {body.login}")
                raise HTTPException(status_code=409, detail="Login already taken")

        if not update_data:
            raise HTTPException(status_code=400, detail="No fields provided to update")

        # Update in Supabase
        response = supabase \
            .from_("user_profiles") \
            .update(update_data) \
            .eq("login", current_login) \
            .execute()

        logger.info(f"✅ Profile updated for user: {current_login}")
        return {"message": "Profile updated", "data": response.data}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Profile update failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

class UpdateDescriptionRequest(BaseModel):
    description: str

@router.patch("/me/description")
async def update_description(request: Request, body: UpdateDescriptionRequest):
    """Update user description - supports both mobile and web authentication"""
    try:
        # Get current user using enhanced verification
        current_user = get_verified_user(request)
        login = current_user.get("login")
        
        logger.info(f"🔄 Updating description for user: {login}")

        # Update the description in user_profiles
        update_data = {"description": body.description}

        # Update the description
        response = supabase.from_("user_profiles").update(update_data).eq("login", login).execute()

        logger.info(f"✅ Description updated for user: {login}")
        return {"message": "Description updated", "data": response.data}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Description update failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update description: {str(e)}")

@router.get("/me/description")
async def get_description(request: Request):
    """Get user description - supports both mobile and web authentication"""
    try:
        # Get current user using enhanced verification
        current_user = get_verified_user(request)
        login = current_user.get("login")

        logger.info(f"🔍 Fetching description for user: {login}")
        
        # Return description from already fetched user data
        description = current_user.get("description", "")
        
        logger.info(f"✅ Description fetched for user: {login}")
        return {"description": description}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to fetch description: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch description: {str(e)}")

# New endpoint to get user stats that matches your frontend
@router.get("/{user_id}/stats")
async def get_user_stats(user_id: str, request: Request):
    """Get user statistics - supports both mobile and web authentication"""
    try:
        # Verify the requesting user (but don't require it to be the same user for public stats)
        try:
            get_verified_user(request)
            logger.info(f"📊 Authenticated request for user stats: {user_id}")
        except HTTPException:
            logger.info(f"📊 Unauthenticated request for user stats: {user_id}")
            # Allow unauthenticated requests for public stats
            pass

        # Fetch user posts count
        posts_response = supabase.from_("posts").select("id", count="exact").eq("user_id", user_id).execute()
        posts_count = posts_response.count if posts_response.count is not None else 0

        # For now, return mock data for listeners and listenedTo
        # You can implement these based on your actual relationships
        listeners_count = 0  # TODO: Implement based on your follow/subscriber system
        listened_to_count = 0  # TODO: Implement based on your follow/following system

        stats = {
            "posts": posts_count,
            "listeners": listeners_count,
            "listenedTo": listened_to_count
        }

        logger.info(f"✅ Stats fetched for user {user_id}: {stats}")
        return stats

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to fetch user stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch user stats: {str(e)}")

# Additional endpoint for debugging mobile authentication
@router.get("/debug/auth-info")
async def debug_auth_info(request: Request):
    """Debug endpoint to check authentication status"""
    try:
        # Device detection
        user_agent = request.headers.get("user-agent", "").lower()
        is_mobile = any(keyword in user_agent for keyword in ['mobile', 'android', 'iphone', 'ipad'])
        is_ios = any(keyword in user_agent for keyword in ['iphone', 'ipad', 'ipod'])
        is_safari = 'safari' in user_agent and 'chrome' not in user_agent
        
        # Token detection
        auth_header = request.headers.get("authorization", "")
        has_auth_header = bool(auth_header.startswith("Bearer "))
        has_cookie = bool(request.cookies.get("access_token"))
        
        token = get_token_from_request(request)
        
        # User verification
        user_info = None
        auth_status = "unauthenticated"
        try:
            user_info = get_verified_user(request)
            auth_status = "authenticated"
        except HTTPException as e:
            auth_status = f"failed: {e.detail}"
        
        return {
            "device_info": {
                "is_mobile": is_mobile,
                "is_ios": is_ios,
                "is_safari": is_safari,
                "user_agent": user_agent
            },
            "auth_info": {
                "has_auth_header": has_auth_header,
                "has_cookie": has_cookie,
                "token_found": bool(token),
                "auth_status": auth_status,
                "user_login": user_info.get("login") if user_info else None
            },
            "headers": dict(request.headers),
            "cookies": dict(request.cookies)
        }
    except Exception as e:
        return {"error": str(e)}
