import os
import uuid
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import GOOGLE_CLIENT_ID, GOOGLE_AUTH_URL, GOOGLE_REDIRECT_URI, GOOGLE_CLIENT_SECRET
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase
from typing import Optional
import httpx
import urllib.parse

logger = logging.getLogger(__name__)
router = APIRouter()


def detect_mobile_browser(request: Request) -> tuple[bool, bool, bool]:
    """
    Enhanced mobile detection for better cookie handling
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


def get_mobile_compatible_cookie_settings(request: Request):
    """
    MOBILE-COMPATIBLE: Dynamic cookie security settings based on device
    """
    environment = os.getenv("ENVIRONMENT", "production")
    is_mobile, is_ios, is_safari = detect_mobile_browser(request)
    
    logger.info(f"🔍 Cookie settings - Mobile: {is_mobile}, iOS: {is_ios}, Safari: {is_safari}")
    
    if environment == "production":
        if is_ios and is_safari:
            # iOS Safari has issues with SameSite=None
            return {
                "httponly": True,
                "secure": True,  # Still need HTTPS
                "samesite": "lax",  # Better for iOS Safari
                "max_age": 24 * 3600,
                "path": "/",
            }
        elif is_mobile:
            # Other mobile browsers
            return {
                "httponly": True,
                "secure": True,
                "samesite": "none",  # Cross-origin support
                "max_age": 24 * 3600,
                "path": "/",
            }
        else:
            # Desktop browsers
            return {
                "httponly": True,
                "secure": True,
                "samesite": "none",
                "max_age": 24 * 3600,
                "path": "/",
            }
    else:
        # Development settings
        return {
            "httponly": True,
            "secure": False,
            "samesite": "lax",
            "max_age": 24 * 3600,
            "path": "/",
        }


def add_mobile_cors_headers(response: Response, request: Request):
    """
    Add mobile-specific CORS headers for better cookie support
    """
    is_mobile, is_ios, is_safari = detect_mobile_browser(request)
    
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Origin"] = "https://techtuners-tt.github.io"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Cookie"
    response.headers["Access-Control-Expose-Headers"] = "Set-Cookie"
    
    # iOS Safari specific headers
    if is_ios and is_safari:
        response.headers["Vary"] = "Cookie, Authorization"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    
    return response


@router.get("/login")
def login(request: Request, redirect_to: Optional[str] = None, mobile: Optional[str] = None):
    """
    MOBILE-COMPATIBLE: OAuth initiation with enhanced mobile support
    """
    try:
        is_mobile_device, is_ios, is_safari = detect_mobile_browser(request)
        
        # Override mobile detection if explicitly specified
        if mobile == "true":
            is_mobile_device = True
        
        logger.info(f"🔍 OAuth initiation - Mobile: {is_mobile_device}, iOS: {is_ios}, Safari: {is_safari}")
        
        # Default redirect for mobile compatibility
        default_redirect = "https://techtuners-tt.github.io/SelfSound/#/home"

        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent",
            # Enhanced mobile compatibility
            "include_granted_scopes": "true"
        }

        # Enhanced state parameter with mobile info
        state_data = {
            "redirect_to": redirect_to or default_redirect,
            "mobile": "1" if is_mobile_device else "0",
            "ios": "1" if is_ios else "0",
            "safari": "1" if is_safari else "0"
        }
        
        # Encode state as URL parameters
        state_params = urllib.parse.urlencode(state_data)
        params["state"] = state_params

        url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"

        logger.info(f"OAuth redirect URL: {url}")
        return RedirectResponse(url)

    except Exception as e:
        logger.error(f"OAuth login error: {str(e)}")
        # Fallback redirect for mobile
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=oauth_error")


@router.get("/callback")
async def auth_callback(request: Request):
    """
    MOBILE-COMPATIBLE: Enhanced callback with device-specific handling
    """
    error = request.query_params.get("error")
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    # Default safe redirect
    default_redirect = "https://techtuners-tt.github.io/SelfSound/#/home"

    # Parse state parameters
    state_data = {}
    if state:
        try:
            state_data = dict(urllib.parse.parse_qsl(state))
        except Exception as e:
            logger.error(f"Failed to parse state: {e}")

    redirect_to = state_data.get("redirect_to", default_redirect)
    is_mobile_callback = state_data.get("mobile") == "1"
    is_ios_callback = state_data.get("ios") == "1"
    is_safari_callback = state_data.get("safari") == "1"
    
    logger.info(f"📱 OAuth callback - Mobile: {is_mobile_callback}, iOS: {is_ios_callback}, Safari: {is_safari_callback}")

    # Ensure redirect is to your domain (security)
    if not redirect_to.startswith("https://techtuners-tt.github.io"):
        redirect_to = default_redirect

    # Handle OAuth errors
    if error == "access_denied":
        logger.warning("User denied OAuth access")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=access_denied")

    if not code:
        logger.error("Authorization code missing from OAuth callback")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=no_code")

    try:
        # Exchange code for tokens
        google_response = await exchange_code_for_token(code)
        id_token_str = google_response.get('id_token')

        if not id_token_str:
            logger.error("ID token missing from Google response")
            return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=no_token")

        # Verify the ID token
        id_info = id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        email = id_info.get("email")
        login = email.split("@")[0] if email else "user"
        name = id_info.get("name", "Unknown User")
        avatar_url = id_info.get("picture", "")
        sub = id_info.get("sub")

        if not email or not sub:
            logger.error("Essential user info missing from Google token")
            return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=invalid_user_info")

        user_id = str(uuid.uuid4())

        # Create user record
        user_record = {
            "id": user_id,
            "email": email,
            "name": name,
            "picture": avatar_url,
            "sub": sub,
            "provider": "google",
            "verified": True,
            "created_at": datetime.utcnow().isoformat()
        }

        # Check if user exists
        existing_user = supabase.from_("users").select("*").eq("sub", sub).execute()
        if not existing_user.data:
            # Create new user
            supabase.from_("users").insert(user_record).execute()
            logger.info(f"Created new user: {email}")
        else:
            # Update existing user info
            user_id = existing_user.data[0]["id"]
            supabase.from_("users").update({
                "name": name,
                "picture": avatar_url,
                "email": email
            }).eq("sub", sub).execute()
            logger.info(f"Updated existing user: {email}")

        # Create/update user profile
        user_profile = {
            "id": user_id,
            "name": name,
            "login": login,
            "avatar_url": avatar_url,
            "sub": sub,
            "email": email
        }

        existing_profile = supabase.from_("user_profiles").select("id").eq("sub", sub).execute()
        if not existing_profile.data:
            supabase.from_("user_profiles").insert(user_profile).execute()
        else:
            supabase.from_("user_profiles").update(user_profile).eq("sub", sub).execute()

        # Generate JWT token
        jwt_token = generate_jwt(id_info)

        # Enhanced mobile-compatible cookie settings
        cookie_settings = get_mobile_compatible_cookie_settings(request)

        # Enhanced mobile handling
        if is_mobile_callback:
            # For mobile, always add token to URL
            separator = "&" if "?" in redirect_to else "?"
            redirect_to = f"{redirect_to}{separator}token={jwt_token}"
            logger.info(f"📱 Mobile OAuth: Adding token to redirect URL")

        response = RedirectResponse(url=redirect_to, status_code=302)
        response = add_mobile_cors_headers(response, request)

        # Set cookie with device-appropriate settings
        response.set_cookie(
            key="access_token",
            value=jwt_token,
            **cookie_settings
        )

        logger.info(f"✅ Google authentication successful for {email} (Mobile: {is_mobile_callback})")
        return response

    except ValueError as ve:
        logger.error(f"Token verification failed: {str(ve)}")
        return RedirectResponse(
            url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=token_verification_failed")
    except httpx.HTTPStatusError as http_error:
        logger.error(f"HTTP error during OAuth: {http_error}")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=http_error")
    except Exception as e:
        logger.error(f"Unexpected OAuth error: {str(e)}")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=unexpected_error")


async def exchange_code_for_token(code: str):
    """
    MOBILE-COMPATIBLE: Enhanced token exchange with better error handling
    """
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            logger.info("Exchanging OAuth code for tokens")
            response = await client.post(token_url, data=data)
            response.raise_for_status()

            token_data = response.json()
            logger.info("Successfully exchanged code for tokens")
            return token_data

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during token exchange: {e.response.status_code} - {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail="Error exchanging code for tokens")
        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Token exchange failed: {str(e)}")


@router.get("/me/raw")
def get_current_user_raw(request: Request):
    """
    MOBILE-COMPATIBLE: Enhanced user info endpoint
    """
    # Check Authorization header first (mobile preference)
    token = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        logger.info("📱 Using Authorization header token")
    
    # Fallback to cookie
    if not token:
        token = request.cookies.get("access_token")
        logger.info("🍪 Using cookie token")

    if not token:
        logger.warning("No access token found in request")
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        user_info = decode_jwt(token, verify_aud_iss=False)
        logger.info("Successfully retrieved user info from token")

        # Create response with mobile-compatible headers
        response = JSONResponse(content={"user": user_info})
        response = add_mobile_cors_headers(response, request)
        return response

    except Exception as e:
        logger.error(f"Token validation failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post("/logout")
async def logout(request: Request):
    """
    MOBILE-COMPATIBLE: Enhanced logout with comprehensive cookie cleanup
    """
    try:
        is_mobile, is_ios, is_safari = detect_mobile_browser(request)
        logger.info(f"📱 Logout - Mobile: {is_mobile}, iOS: {is_ios}, Safari: {is_safari}")
        
        cookie_settings = get_mobile_compatible_cookie_settings(request)

        response = JSONResponse(content={
            "message": "Logged out successfully",
            "mobile_detected": is_mobile
        })
        response = add_mobile_cors_headers(response, request)

        # Primary cookie deletion with current settings
        response.delete_cookie(
            key="access_token",
            path="/",
            secure=cookie_settings["secure"],
            samesite=cookie_settings["samesite"]
        )

        # Enhanced cleanup with multiple configurations
        cleanup_configs = [
            {"path": "/", "secure": True, "samesite": "none"},  # Production HTTPS
            {"path": "/", "secure": True, "samesite": "lax"},   # iOS Safari friendly
            {"path": "/", "secure": False, "samesite": "lax"},  # Development HTTP
            {"path": "/", "secure": False, "samesite": "none"}, # Edge case
            {"path": "/"},  # Basic cleanup
        ]

        for config in cleanup_configs:
            try:
                response.delete_cookie(key="access_token", **config)
            except Exception:
                pass  # Ignore cleanup errors

        logger.info("Google logout successful with comprehensive cleanup")
        return response

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return JSONResponse(content={"message": "Logged out"})


@router.get("/debug/mobile-oauth")
def debug_mobile_oauth(request: Request):
    """
    DEBUG: Check mobile OAuth compatibility
    """
    is_mobile, is_ios, is_safari = detect_mobile_browser(request)
    user_agent = request.headers.get("user-agent", "")
    
    cookie_settings = get_mobile_compatible_cookie_settings(request)

    return {
        "device_detection": {
            "user_agent": user_agent,
            "is_mobile": is_mobile,
            "is_ios": is_ios,
            "is_safari": is_safari
        },
        "oauth_config": {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "frontend_origin": "https://techtuners-tt.github.io"
        },
        "cookie_config": {
            "recommended_settings": cookie_settings,
            "https_required": cookie_settings.get("secure", False),
            "samesite_setting": cookie_settings.get("samesite"),
            "mobile_optimized": is_mobile
        },
        "cors_headers": {
            "access_control_allow_credentials": "true",
            "access_control_allow_origin": "https://techtuners-tt.github.io",
            "mobile_specific_headers": is_ios and is_safari
        }
    }
