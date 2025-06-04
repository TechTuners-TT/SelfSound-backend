from fastapi import Request, HTTPException
from supabase_client import supabase
from jwt_handler import decode_jwt
import logging

logger = logging.getLogger(__name__)


def detect_mobile_browser(request: Request) -> tuple[bool, bool, bool]:
    """
    Enhanced mobile detection for better token handling
    Returns: (is_mobile, is_ios, is_safari)
    """
    user_agent = request.headers.get("user-agent", "").lower()
    
    # Mobile detection
    mobile_keywords = ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone']
    is_mobile = any(keyword in user_agent for keyword in mobile_keywords)
    
    # iOS detection
    is_ios = any(keyword in user_agent for keyword in ['iphone', 'ipad', 'ipod'])
    
    # Safari detection (but not Chrome on iOS)
    is_safari = 'safari' in user_agent and 'chrome' not in user_agent and 'crios' not in user_agent
    
    return is_mobile, is_ios, is_safari


async def get_verified_user(request: Request):
    """
    🔥 ENHANCED: Mobile-compatible authentication with improved error handling
    Supports both Authorization headers (mobile) AND cookies (web)
    """
    token = None
    auth_source = None
    
    # Enhanced mobile detection
    is_mobile, is_ios, is_safari = detect_mobile_browser(request)
    
    logger.info(f"📱 Auth request - Mobile: {is_mobile}, iOS: {is_ios}, Safari: {is_safari}")

    # PRIORITY 1: Authorization header (mobile-first approach)
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        auth_source = "header"
        logger.info(f"📱 MOBILE AUTH: Found Bearer token in Authorization header")

    # PRIORITY 2: Fallback to cookies (web browsers)
    if not token:
        token = request.cookies.get("access_token")
        if token:
            auth_source = "cookie"
            logger.info(f"🍪 WEB AUTH: Access token from cookies")

    # PRIORITY 3: Check for token in query parameters (mobile OAuth callback)
    if not token:
        token = request.query_params.get("token")
        if token:
            auth_source = "query_param"
            logger.info(f"🔗 OAUTH AUTH: Token from query parameter")

    if not token:
        logger.warning(f"❌ [get_verified_user] No token found (Mobile: {is_mobile}, iOS Safari: {is_ios and is_safari})")
        
        # Enhanced error message for mobile debugging
        if is_mobile:
            raise HTTPException(
                status_code=401, 
                detail="No authentication token provided (mobile device detected - ensure Authorization header is set)"
            )
        else:
            raise HTTPException(status_code=401, detail="No authentication token provided")

    logger.info(f"✅ [get_verified_user] Using token from: {auth_source} (Mobile: {is_mobile})")

    try:
        # Enhanced JWT decoding with better error handling
        payload = decode_jwt(token)
        logger.info(f"🔓 [get_verified_user] Decoded JWT payload successfully")

        user_sub = payload.get("sub")
        user_email = payload.get("email")
        logger.info(f"👤 [get_verified_user] Extracted sub: {user_sub}, email: {user_email}")

        if not user_sub and not user_email:
            logger.error("❌ [get_verified_user] No user identifier found in token")
            raise HTTPException(status_code=401, detail="Invalid token: missing user identifier")

        user_resp = None

        # 🔥 STRATEGY 1: Try user_profiles table first (your current structure)
        if user_email:
            try:
                # Extract login from email for user_profiles lookup
                login = user_email.split("@")[0]
                user_resp = supabase.from_("user_profiles").select("*").eq("login", login).single().execute()
                logger.info(f"🔍 [get_verified_user] Found user in user_profiles table: {login}")
                
                if user_resp.data:
                    # Convert user_profiles format to expected format
                    profile_data = user_resp.data
                    return {
                        "id": profile_data.get("id"),
                        "sub": user_sub,
                        "email": user_email,
                        "name": profile_data.get("name", ""),
                        "login": profile_data.get("login", login),
                        "verified": True,  # OAuth users are verified
                        "provider": "google" if "google" in str(payload) else "email",
                        "email_confirmed": True,
                        "auth_source": auth_source,
                        "mobile_detected": is_mobile,
                        # Include profile-specific fields
                        "avatar_url": profile_data.get("avatar_url"),
                        "description": profile_data.get("description"),
                        "tag_id": profile_data.get("tag_id"),
                    }
            except Exception as e:
                logger.warning(f"⚠️ [get_verified_user] user_profiles lookup failed: {str(e)}")
                user_resp = None

        # 🔥 STRATEGY 2: Fallback to users table (if exists)
        if user_resp is None or user_resp.data is None:
            if user_sub:
                try:
                    user_resp = supabase.table("users").select("*").eq("sub", user_sub).single().execute()
                    logger.info(f"🔍 [get_verified_user] Found user in users table by sub")
                except Exception as e:
                    logger.warning(f"⚠️ [get_verified_user] Sub lookup failed: {str(e)}")
                    user_resp = None

            # Try by email if sub failed
            if (user_resp is None or user_resp.data is None) and user_email:
                try:
                    user_resp = supabase.table("users").select("*").eq("email", user_email).single().execute()
                    logger.info(f"🔍 [get_verified_user] Found user in users table by email")
                except Exception as e:
                    logger.warning(f"⚠️ [get_verified_user] Email lookup failed: {str(e)}")
                    user_resp = None

        if user_resp is None or user_resp.data is None:
            logger.error("❌ [get_verified_user] User not found in any table")
            
            # Enhanced error for mobile debugging
            if is_mobile:
                raise HTTPException(
                    status_code=401, 
                    detail=f"User not found (mobile device detected, token source: {auth_source})"
                )
            else:
                raise HTTPException(status_code=401, detail="User not found")

        user_data = user_resp.data
        provider = user_data.get("provider", "email")
        is_verified = user_data.get("verified", False)

        # Enhanced verification check
        if provider == "email" and not is_verified:
            logger.warning("⚠️ [get_verified_user] Email user is not verified")
            raise HTTPException(status_code=403, detail="Email not verified")

        # OAuth users (Google, etc.) are automatically verified
        if provider in ["google", "oauth"]:
            is_verified = True

        logger.info(f"🎉 [get_verified_user] Successfully verified user: {user_data.get('email')} via {auth_source} (Mobile: {is_mobile})")

        return {
            "id": user_data.get("id"),
            "sub": user_data.get("sub"),
            "email": user_data.get("email"),
            "name": user_data.get("name", ""),
            "login": user_data.get("login"),
            "verified": is_verified,
            "provider": provider,
            "email_confirmed": is_verified or provider != "email",
            "auth_source": auth_source,
            "mobile_detected": is_mobile,
            # Include any additional fields from user_profiles
            "avatar_url": user_data.get("avatar_url"),
            "description": user_data.get("description"),
            "tag_id": user_data.get("tag_id"),
        }

    except ValueError as ve:
        error_msg = str(ve).lower()
        logger.error(f"❌ [get_verified_user] JWT decode error: {str(ve)}")
        
        if "expired" in error_msg:
            if is_mobile:
                raise HTTPException(
                    status_code=401, 
                    detail=f"Token has expired (mobile device detected, clear local storage and re-login)"
                )
            else:
                raise HTTPException(status_code=401, detail="Token has expired")
        elif "signature" in error_msg:
            raise HTTPException(status_code=401, detail="Invalid token signature")
        elif "invalid" in error_msg:
            raise HTTPException(status_code=401, detail="Invalid token format")
        else:
            raise HTTPException(status_code=401, detail="Token validation failed")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 [get_verified_user] Unexpected error: {str(e)}")
        
        # Enhanced error reporting for mobile
        if is_mobile:
            raise HTTPException(
                status_code=401, 
                detail=f"Authentication failed on mobile device (source: {auth_source}): {str(e)}"
            )
        else:
            raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


async def get_verified_user_debug(request: Request):
    """
    DEBUG VERSION: Enhanced debugging for mobile authentication issues
    This should be used temporarily for debugging and removed in production
    """
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    query_params = dict(request.query_params)
    
    is_mobile, is_ios, is_safari = detect_mobile_browser(request)
    user_agent = headers.get("user-agent", "")

    # Check all possible token sources
    auth_header = headers.get("authorization", "")
    bearer_token = auth_header[7:] if auth_header.startswith("Bearer ") else None
    cookie_token = cookies.get("access_token")
    query_token = query_params.get("token")

    debug_info = {
        "device_info": {
            "user_agent": user_agent,
            "is_mobile": is_mobile,
            "is_ios": is_ios,
            "is_safari": is_safari
        },
        "token_sources": {
            "authorization_header": {
                "present": bool(auth_header),
                "valid_format": auth_header.startswith("Bearer ") if auth_header else False,
                "token_preview": bearer_token[:50] + "..." if bearer_token else None
            },
            "cookie": {
                "present": bool(cookie_token),
                "token_preview": cookie_token[:50] + "..." if cookie_token else None
            },
            "query_param": {
                "present": bool(query_token),
                "token_preview": query_token[:50] + "..." if query_token else None
            }
        },
        "all_headers": {k: v for k, v in headers.items() if k.lower() in ['authorization', 'cookie', 'user-agent']},
        "all_cookies": list(cookies.keys()),
        "all_query_params": list(query_params.keys())
    }

    try:
        # Try normal authentication flow
        user = await get_verified_user(request)
        debug_info["auth_result"] = {
            "success": True,
            "user_id": user.get("id"),
            "email": user.get("email"),
            "auth_source": user.get("auth_source"),
            "mobile_detected": user.get("mobile_detected")
        }
        return debug_info
    except HTTPException as e:
        debug_info["auth_result"] = {
            "success": False,
            "error_code": e.status_code,
            "error_detail": e.detail
        }
        return debug_info
    except Exception as e:
        debug_info["auth_result"] = {
            "success": False,
            "error": str(e)
        }
        return debug_info


# 🔥 OPTIONAL: Non-async version for backward compatibility
def get_verified_user_sync(request: Request) -> dict:
    """
    Synchronous version of get_verified_user for backward compatibility
    """
    import asyncio
    
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(get_verified_user(request))
        return loop.run_until_complete(task)
    except RuntimeError:
        return asyncio.run(get_verified_user(request))


# Export functions for use in other modules
__all__ = ["get_verified_user", "get_verified_user_sync", "get_verified_user_debug", "detect_mobile_browser"]
