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

def get_safari_compatible_cookie_settings():
    """
    SAFARI-COMPATIBLE: Enhanced cookie settings that work across all browsers
    Especially important for Safari's strict cookie policies
    """
    environment = os.getenv("ENVIRONMENT", "production")
    
    # For production (HTTPS required)
    if environment == "production":
        return {
            "httponly": True,           # 🔒 Security: Prevent XSS attacks  
            "secure": True,             # 🔒 CRITICAL: Safari requires HTTPS for cross-origin
            "samesite": "none",         # 🌐 ESSENTIAL: Safari cross-origin requirement
            "max_age": 24 * 3600,       # ⏰ 24 hours expiry
            "path": "/",                # 🌍 Available across entire backend
            # REMOVED "domain" - let browser handle it (better Safari compatibility)
        }
    else:
        # For development (localhost)
        return {
            "httponly": True,
            "secure": False,            # HTTP for localhost
            "samesite": "lax",          # Safer for localhost
            "max_age": 24 * 3600,
            "path": "/",
        }

def add_safari_cors_headers(response: Response):
    """
    Add Safari-specific CORS headers for better cookie support
    """
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Origin"] = "https://techtuners-tt.github.io"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Cookie"
    response.headers["Access-Control-Expose-Headers"] = "Set-Cookie"
    return response

@router.get("/login")
def login(redirect_to: Optional[str] = None):
    """
    SAFARI-COMPATIBLE: OAuth initiation with better error handling
    """
    try:
        # Default redirect for Safari compatibility
        default_redirect = "https://techtuners-tt.github.io/SelfSound/#/home"
        
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "consent",
            # Add include_granted_scopes for better Safari compatibility
            "include_granted_scopes": "true"
        }
        
        if redirect_to:
            # Ensure the redirect URL is safe and from your domain
            if redirect_to.startswith("https://techtuners-tt.github.io"):
                params["state"] = urllib.parse.quote(redirect_to)
            else:
                params["state"] = urllib.parse.quote(default_redirect)
        else:
            params["state"] = urllib.parse.quote(default_redirect)

        url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"
        
        logger.info(f"OAuth redirect URL: {url}")
        return RedirectResponse(url)
        
    except Exception as e:
        logger.error(f"OAuth login error: {str(e)}")
        # Fallback redirect for Safari
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=oauth_error")

@router.get("/callback")
async def auth_callback(request: Request):
    """
    SAFARI-COMPATIBLE: Enhanced callback with better error handling and cookie settings
    """
    error = request.query_params.get("error")
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    
    # Default safe redirect
    default_redirect = "https://techtuners-tt.github.io/SelfSound/#/home"
    
    # Decode the state parameter safely
    try:
        redirect_to = urllib.parse.unquote(state) if state else default_redirect
        # Ensure redirect is to your domain (security)
        if not redirect_to.startswith("https://techtuners-tt.github.io"):
            redirect_to = default_redirect
    except Exception:
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
            "created_at": datetime.utcnow().isoformat()  # Add timestamp
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

        # SAFARI FIX: Use Safari-compatible cookie settings
        cookie_settings = get_safari_compatible_cookie_settings()

        # Create response with Safari-compatible headers
        response = RedirectResponse(url=redirect_to, status_code=302)
        
        # SAFARI FIX: Add CORS headers before setting cookies
        response = add_safari_cors_headers(response)
        
        # Set the cookie with Safari-compatible settings
        response.set_cookie(
            key="access_token", 
            value=jwt_token,
            **cookie_settings
        )

        logger.info(f"Google authentication successful for {email}")
        return response

    except ValueError as ve:
        logger.error(f"Token verification failed: {str(ve)}")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=token_verification_failed")
    except httpx.HTTPStatusError as http_error:
        logger.error(f"HTTP error during OAuth: {http_error}")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=http_error")
    except Exception as e:
        logger.error(f"Unexpected OAuth error: {str(e)}")
        return RedirectResponse(url="https://techtuners-tt.github.io/SelfSound/#/sign-in?error=unexpected_error")

async def exchange_code_for_token(code: str):
    """
    SAFARI-COMPATIBLE: Enhanced token exchange with better error handling
    """
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient(timeout=30.0) as client:  # Add timeout
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
    SAFARI-COMPATIBLE: Enhanced user info endpoint
    """
    token = request.cookies.get("access_token")
    if not token:
        logger.warning("No access token found in request")
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        user_info = decode_jwt(token, verify_aud_iss=False)
        logger.info("Successfully retrieved user info from token")
        
        # Create response with Safari-compatible headers
        response = JSONResponse(content={"user": user_info})
        response = add_safari_cors_headers(response)
        return response
        
    except Exception as e:
        logger.error(f"Token validation failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/logout")
async def logout():
    """
    SAFARI-COMPATIBLE: Enhanced logout with comprehensive cookie cleanup
    """
    try:
        cookie_settings = get_safari_compatible_cookie_settings()

        response = JSONResponse(content={"message": "Logged out successfully"})
        response = add_safari_cors_headers(response)

        # Primary cookie deletion with current settings
        response.delete_cookie(
            key="access_token",
            path="/",
            secure=cookie_settings["secure"],
            samesite=cookie_settings["samesite"]
        )

        # SAFARI FIX: Comprehensive cleanup with multiple configurations
        # This ensures cookies are removed regardless of how they were set
        cleanup_configs = [
            {"path": "/", "secure": True, "samesite": "none"},      # Production HTTPS
            {"path": "/", "secure": False, "samesite": "lax"},     # Development HTTP
            {"path": "/", "secure": True, "samesite": "lax"},      # Mixed scenario
            {"path": "/", "secure": False, "samesite": "none"},    # Edge case
            {"path": "/"},                                          # Basic cleanup
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

# ADDITIONAL SAFARI DEBUGGING ENDPOINT (REMOVE IN PRODUCTION)
@router.get("/debug/safari")
def debug_safari_compatibility(request: Request):
    """
    DEBUG: Check Safari compatibility (remove in production)
    """
    user_agent = request.headers.get("user-agent", "")
    is_safari = "Safari" in user_agent and "Chrome" not in user_agent
    
    cookie_settings = get_safari_compatible_cookie_settings()
    
    return {
        "user_agent": user_agent,
        "is_safari": is_safari,
        "cookie_settings": cookie_settings,
        "cors_headers_needed": True,
        "https_required": cookie_settings.get("secure", False),
        "samesite_setting": cookie_settings.get("samesite"),
        "oauth_redirect_uri": GOOGLE_REDIRECT_URI,
        "frontend_origin": "https://techtuners-tt.github.io"
    }
