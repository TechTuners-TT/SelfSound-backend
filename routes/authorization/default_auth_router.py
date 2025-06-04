import re
import logging
import uuid
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status, Depends, BackgroundTasks
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from passlib.context import CryptContext
from email_validator import validate_email, EmailNotValidError
import secrets
from utils.email_utils import send_verification_email
import hashlib
import jwt
import requests
from supabase import create_client, Client

from jwt_handler import decode_jwt
from routes.dependencies import get_verified_user
from models.schemas.default_auth import UserCreate, UserLogin

from config import (
    SUPABASE_URL,
    SUPABASE_KEY,
    VERIFICATION_TOKEN_EXP_HOURS,
    JWT_SECRET,
    JWT_ALGORITHM,
    FRONTEND_REDIRECT_URL,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/authorization", tags=["authorization"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "abc123"}


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
    is_safari = 'safari' in user_agent and 'chrome' not in user_agent
    
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


def generate_verification_token():
    """Generate a secure verification token"""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash the token for database storage"""
    return hashlib.sha256(token.encode()).hexdigest()


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get("access_token")
        if token:
            try:
                payload = decode_jwt(token, verify_aud_iss=True)
                request.state.user = payload
            except Exception:
                request.state.user = None
        else:
            request.state.user = None

        return await call_next(request)


def generate_uuid_sub() -> str:
    return str(uuid.uuid4())


def validate_password(password: str):
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters long")
    if len(password) > 64:
        errors.append("no more than 64 characters long")
    if not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("at least one lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("at least one number")
    if not re.search(r"[^a-zA-Z0-9]", password):
        errors.append("at least one special character")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("password is too common")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"Password must include: {', '.join(errors)}"
        )


def generate_unique_login(email: str) -> str:
    base = email.split("@")[0]
    login = base
    counter = 1
    while True:
        check = supabase.table("user_profiles").select("id").eq("login", login).execute()
        if not check.data:
            return login
        login = f"{base}{counter}"
        counter += 1


@router.post("/signup")
async def sign_up(user: UserCreate, background_tasks: BackgroundTasks):
    logger.info("User signup attempt")

    try:
        # Validate email
        try:
            validate_email(user.email)
        except EmailNotValidError as e:
            raise HTTPException(400, str(e))

        # Validate name
        if not user.name or not user.name.strip():
            raise HTTPException(400, "Name cannot be empty")

        # Validate password
        validate_password(user.password)

        # Convert email to string for consistency
        email_str = str(user.email)

        # Check if user already exists
        existing_user = supabase.table("users").select("id, email, verified").eq("email", email_str).execute()

        if existing_user.data:
            existing_user_data = existing_user.data[0]
            if existing_user_data.get("verified"):
                raise HTTPException(400, "User already exists and is verified")
            else:
                # User exists but not verified - resend verification
                user_id = existing_user_data["id"]
                return await resend_verification_for_user(user_id, email_str, background_tasks)

        # Generate user ID and hash password
        user_id = generate_uuid_sub()
        hashed_password = pwd_context.hash(user.password)

        # Create user record
        created_user = supabase.table("users").insert({
            "id": user_id,
            "email": email_str,
            "name": user.name,
            "password": hashed_password,
            "provider": "email",
            "verified": False,
            "sub": user_id,
            "created_at": datetime.utcnow().isoformat(),
        }).execute()

        if not created_user.data:
            raise HTTPException(500, "Failed to create user record")

        # Generate unique login
        login = generate_unique_login(email_str)

        # Create user profile
        profile_data = {
            "id": user_id,
            "name": user.name,
            "login": login,
            "avatar_url": "https://cdn.builder.io/api/v1/image/assets/TEMP/3922534bd59dfe0deae8bd149c0b3cba46e3eb47?placeholderIfAbsent=true&apiKey=04fef95365634cc5973c2029f1fc78f5",
            "description": "",
            "email": email_str,
            "sub": user_id,
        }

        profile_result = supabase.table("user_profiles").insert(profile_data).execute()

        if not profile_result.data:
            # If profile creation fails, clean up the user record
            supabase.table("users").delete().eq("id", user_id).execute()
            raise HTTPException(500, "Failed to create user profile")

        # Generate verification token
        verification_token = generate_verification_token()
        hashed_token = hash_token(verification_token)

        # Store verification token
        token_insert = {
            "user_id": user_id,
            "token": hashed_token,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }

        token_result = supabase.table("email_verification_tokens").insert(token_insert).execute()

        if not token_result.data:
            # Clean up user and profile if token creation fails
            supabase.table("user_profiles").delete().eq("id", user_id).execute()
            supabase.table("users").delete().eq("id", user_id).execute()
            raise HTTPException(500, "Failed to create verification token")

        # Send verification email in background
        background_tasks.add_task(send_verification_email, email_str, verification_token)

        logger.info("Signup completed successfully")

        return {
            "message": "User created successfully. Please check your email for verification link.",
            "email": email_str
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        raise HTTPException(500, f"Failed to create user: {str(e)}")


async def resend_verification_for_user(user_id: str, email: str, background_tasks: BackgroundTasks):
    """Resend verification email for existing unverified user"""
    try:
        # Delete any existing verification tokens for this user
        supabase.table("email_verification_tokens").delete().eq("user_id", user_id).execute()

        # Generate new verification token
        verification_token = generate_verification_token()
        hashed_token = hash_token(verification_token)

        # Store new verification token
        token_insert = {
            "user_id": user_id,
            "token": hashed_token,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }

        supabase.table("email_verification_tokens").insert(token_insert).execute()

        # Send verification email
        background_tasks.add_task(send_verification_email, email, verification_token)

        return {
            "message": "Verification email sent successfully. Please check your email.",
            "email": email
        }

    except Exception as e:
        logger.error(f"Failed to resend verification: {e}")
        raise HTTPException(500, f"Failed to resend verification: {str(e)}")


@router.get("/verify-email")
async def verify_email_simple(token: str):
    """Simple email verification that redirects to sign-in page"""
    try:
        # Hash the provided token
        hashed_token = hash_token(token)

        # Find verification token
        token_result = supabase.table("email_verification_tokens").select("*").eq("token", hashed_token).execute()

        if not token_result.data:
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=invalid_token",
                status_code=302
            )

        token_data = token_result.data[0]
        user_id = token_data["user_id"]

        # Check if token has expired
        expires_at_str = token_data["expires_at"]

        # Handle both timezone-aware and timezone-naive datetimes
        if expires_at_str.endswith('+00:00') or 'T' in expires_at_str:
            expires_at_str = expires_at_str.replace('+00:00', '').replace('Z', '')
            expires_at = datetime.fromisoformat(expires_at_str)
        else:
            expires_at = datetime.fromisoformat(expires_at_str)

        current_time = datetime.utcnow()

        if current_time > expires_at:
            # Delete expired token
            supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=token_expired",
                status_code=302
            )

        # Check if user is already verified
        user_result = supabase.table("users").select("verified, email").eq("id", user_id).execute()

        if not user_result.data:
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=user_not_found",
                status_code=302
            )

        user_data = user_result.data[0]

        if user_data.get("verified"):
            # Delete used token
            supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?success=already_verified",
                status_code=302
            )

        # Update user as verified
        update_data = {
            "verified": True,
            "verified_at": datetime.utcnow().isoformat()
        }

        update_result = supabase.table("users").update(update_data).eq("id", user_id).execute()

        if not update_result.data:
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=verification_failed",
                status_code=302
            )

        # Delete used verification token
        supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()

        logger.info("Email verification completed successfully")

        # Redirect to sign-in page with success message
        return RedirectResponse(
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?verified=true",
            status_code=302
        )

    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}")
        return RedirectResponse(
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=verification_error",
            status_code=302
        )


@router.post("/resend-verification")
async def resend_verification(email_data: dict, background_tasks: BackgroundTasks):
    try:
        email = email_data.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")

        # Find unverified user
        user_result = supabase.table("users").select("id, verified").eq("email", email).execute()

        if not user_result.data:
            raise HTTPException(status_code=400, detail="User not found")

        user = user_result.data[0]

        if user.get("verified"):
            raise HTTPException(status_code=400, detail="Email already verified")

        return await resend_verification_for_user(user["id"], email, background_tasks)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resend verification: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resend verification: {str(e)}")


@router.post("/logindefault")
def login(user: UserLogin, request: Request, response: Response):
    try:
        is_mobile, is_ios, is_safari = detect_mobile_browser(request)
        logger.info(f"📱 Login attempt - Mobile: {is_mobile}, iOS: {is_ios}, Safari: {is_safari}")
        
        user_record = supabase.table("users").select("*").eq("email", user.email).single().execute()

        if not user_record.data:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        user_data = user_record.data

        if not pwd_context.verify(user.password, user_data["password"]):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        if not user_data.get("verified", False):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Email not verified")

        payload = {
            "sub": user_data["id"],
            "email": user_data["email"],
            "name": user_data["name"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # Enhanced mobile-compatible cookie settings
        cookie_settings = get_mobile_compatible_cookie_settings(request)
        
        logger.info(f"🍪 Setting cookie with settings: {cookie_settings}")

        response.set_cookie(
            key="access_token",
            value=access_token,
            **cookie_settings
        )

        # Enhanced mobile response
        response_data = {
            "message": "Login successful",
            "access_token": access_token,  # Always return token for mobile fallback
            "user": {
                "id": user_data["id"],
                "email": user_data["email"],
                "name": user_data["name"],
                "verified": user_data.get("verified", False)
            },
            "expires_in": 24 * 3600,
            "mobile_detected": is_mobile,  # Help frontend understand device type
            "ios_safari": is_ios and is_safari
        }

        logger.info(f"✅ Login successful for {user_data['email']} (Mobile: {is_mobile})")
        return response_data

    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")


def create_email_verification_token(id: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=int(VERIFICATION_TOKEN_EXP_HOURS))
    payload = {
        "sub": id,
        "exp": expire.timestamp(),
        "type": "email_verification"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


@router.get("/me")
def get_me(user: dict = Depends(get_verified_user)):
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {"id": user["id"], "name": user.get("name")}


def delete_user_from_supabase_auth(user_id: str) -> bool:
    url = f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }
    response = requests.delete(url, headers=headers)
    if response.status_code in (200, 204):
        return True
    else:
        logger.error(f"Failed to delete user {user_id}. Status: {response.status_code}, Response: {response.text}")
        return False


@router.delete("/me", status_code=204)
def delete_user_account(
        request: Request,
        response: Response,
        user: dict = Depends(get_verified_user)
):
    user_id = user["id"]

    profile_res = supabase.table("user_profiles").delete().eq("id", user_id).execute()
    user_res = supabase.table("users").delete().eq("id", user_id).execute()

    if not delete_user_from_supabase_auth(user_id):
        raise HTTPException(status_code=500, detail="Failed to delete user from Supabase Auth")

    # Enhanced mobile-compatible cookie cleanup
    cookie_settings = get_mobile_compatible_cookie_settings(request)
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=cookie_settings["secure"],
        samesite=cookie_settings["samesite"]
    )

    return Response(status_code=200)


@router.post("/logout")
async def logout(request: Request, response: Response):
    try:
        is_mobile, is_ios, is_safari = detect_mobile_browser(request)
        logger.info(f"📱 Logout attempt - Mobile: {is_mobile}, iOS: {is_ios}, Safari: {is_safari}")
        
        # Enhanced mobile-compatible cookie cleanup
        cookie_settings = get_mobile_compatible_cookie_settings(request)

        response.delete_cookie(
            key="access_token",
            path="/",
            secure=cookie_settings["secure"],
            samesite=cookie_settings["samesite"]
        )

        # Enhanced cleanup for different cookie configurations
        backup_configs = [
            {"path": "/", "secure": True, "samesite": "none"},
            {"path": "/", "secure": True, "samesite": "lax"},
            {"path": "/", "secure": False, "samesite": "lax"},
            {"path": "/"},
        ]

        for config in backup_configs:
            try:
                response.delete_cookie(key="access_token", **config)
            except:
                pass  # Ignore cleanup errors

        logger.info("User logged out successfully")
        return {
            "message": "Logged out successfully",
            "mobile_detected": is_mobile
        }
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"message": "Logged out"}


@router.get("/debug/mobile-auth")
async def debug_mobile_auth(request: Request):
    """Enhanced debug mobile authentication issues"""
    
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    
    is_mobile, is_ios, is_safari = detect_mobile_browser(request)
    user_agent = headers.get("user-agent", "")

    auth_token = None
    auth_source = None

    auth_header = headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        auth_token = auth_header[7:]
        auth_source = "authorization_header"

    cookie_token = cookies.get("access_token")
    if cookie_token and not auth_token:
        auth_token = cookie_token
        auth_source = "cookie"

    token_valid = False
    token_error = None
    user_info = None

    if auth_token:
        try:
            payload = decode_jwt(auth_token)
            token_valid = True
            user_info = {
                "sub": payload.get("sub"),
                "email": payload.get("email"),
                "name": payload.get("name")
            }
        except Exception as e:
            token_error = str(e)

    # Get current cookie settings for this device
    cookie_settings = get_mobile_compatible_cookie_settings(request)

    return {
        "device_info": {
            "user_agent": user_agent,
            "is_mobile": is_mobile,
            "is_ios": is_ios,
            "is_safari": is_safari,
            "recommended_cookie_settings": cookie_settings
        },
        "authentication": {
            "has_auth_header": "authorization" in headers,
            "has_cookie": "access_token" in cookies,
            "auth_token_found": auth_token is not None,
            "auth_source": auth_source,
            "token_valid": token_valid,
            "token_error": token_error,
            "user_info": user_info
        },
        "cookies": {
            "access_token_present": "access_token" in cookies,
            "cookie_count": len(cookies),
            "all_cookies": list(cookies.keys())
        },
        "headers": {
            "relevant_headers": {
                "authorization": headers.get("authorization", "Not present"),
                "cookie": headers.get("cookie", "Not present"),
                "user-agent": headers.get("user-agent", "Not present")
            }
        }
    }


@router.get("/debug/test-auth")
async def test_auth_endpoint(current_user: dict = Depends(get_verified_user)):
    """Test if authentication works"""
    return {
        "success": True,
        "message": "Authentication working correctly",
        "user": {
            "id": current_user.get("id"),
            "email": current_user.get("email"),
            "name": current_user.get("name")
        }
    }
    # Add this to your default_auth_router.py for debugging iOS Safari issues

@router.get("/debug/ios-safari-auth")
async def debug_ios_safari_auth(request: Request):
    """
    Special debug endpoint for iOS Safari authentication issues
    """
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    query_params = dict(request.query_params)
    
    # Enhanced mobile detection
    user_agent = headers.get("user-agent", "").lower()
    is_mobile = any(keyword in user_agent for keyword in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])
    is_ios = any(keyword in user_agent for keyword in ['iphone', 'ipad', 'ipod'])
    is_safari = 'safari' in user_agent and 'chrome' not in user_agent and 'crios' not in user_agent
    is_ios_safari = is_ios and is_safari

    # Check all possible auth sources
    auth_sources = {}
    
    # 1. Authorization header
    auth_header = headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        auth_sources["authorization_header"] = {
            "present": True,
            "token_length": len(token),
            "token_preview": token[:50] + "..." if len(token) > 50 else token,
            "valid_format": True
        }
        
        # Try to decode this token
        try:
            payload = decode_jwt(token)
            auth_sources["authorization_header"]["valid_token"] = True
            auth_sources["authorization_header"]["user_id"] = payload.get("sub")
            auth_sources["authorization_header"]["email"] = payload.get("email")
        except Exception as e:
            auth_sources["authorization_header"]["valid_token"] = False
            auth_sources["authorization_header"]["decode_error"] = str(e)
    else:
        auth_sources["authorization_header"] = {
            "present": bool(auth_header),
            "valid_format": False,
            "raw_value": auth_header
        }

    # 2. Cookies
    access_token_cookie = cookies.get("access_token")
    if access_token_cookie:
        auth_sources["cookie"] = {
            "present": True,
            "token_length": len(access_token_cookie),
            "token_preview": access_token_cookie[:50] + "..." if len(access_token_cookie) > 50 else access_token_cookie
        }
        
        try:
            payload = decode_jwt(access_token_cookie)
            auth_sources["cookie"]["valid_token"] = True
            auth_sources["cookie"]["user_id"] = payload.get("sub")
            auth_sources["cookie"]["email"] = payload.get("email")
        except Exception as e:
            auth_sources["cookie"]["valid_token"] = False
            auth_sources["cookie"]["decode_error"] = str(e)
    else:
        auth_sources["cookie"] = {"present": False}

    # 3. Query parameters
    query_token = query_params.get("token")
    if query_token:
        auth_sources["query_param"] = {
            "present": True,
            "token_length": len(query_token),
            "token_preview": query_token[:50] + "..." if len(query_token) > 50 else query_token
        }
        
        try:
            payload = decode_jwt(query_token)
            auth_sources["query_param"]["valid_token"] = True
            auth_sources["query_param"]["user_id"] = payload.get("sub")
            auth_sources["query_param"]["email"] = payload.get("email")
        except Exception as e:
            auth_sources["query_param"]["valid_token"] = False
            auth_sources["query_param"]["decode_error"] = str(e)
    else:
        auth_sources["query_param"] = {"present": False}

    # Get recommended cookie settings for this device
    cookie_settings = get_mobile_compatible_cookie_settings(request)

    # Test authentication with current setup
    auth_test_result = None
    try:
        user = await get_verified_user(request)
        auth_test_result = {
            "success": True,
            "user_id": user.get("id"),
            "email": user.get("email"),
            "auth_source": user.get("auth_source")
        }
    except HTTPException as e:
        auth_test_result = {
            "success": False,
            "error_code": e.status_code,
            "error_detail": e.detail
        }
    except Exception as e:
        auth_test_result = {
            "success": False,
            "error": str(e)
        }

    return {
        "device_detection": {
            "user_agent": headers.get("user-agent", ""),
            "is_mobile": is_mobile,
            "is_ios": is_ios,
            "is_safari": is_safari,
            "is_ios_safari": is_ios_safari,
            "problematic_combination": is_ios_safari
        },
        "authentication_sources": auth_sources,
        "cookie_configuration": {
            "recommended_settings": cookie_settings,
            "ios_safari_optimized": is_ios_safari,
            "samesite_setting": cookie_settings.get("samesite"),
            "secure_setting": cookie_settings.get("secure"),
            "httponly_setting": cookie_settings.get("httponly")
        },
        "current_auth_test": auth_test_result,
        "headers_received": {
            "authorization": headers.get("authorization", "Not present"),
            "cookie": headers.get("cookie", "Not present"),
            "user_agent": headers.get("user-agent", "Not present"),
            "cache_control": headers.get("cache-control", "Not present"),
            "pragma": headers.get("pragma", "Not present")
        },
        "all_cookies": list(cookies.keys()),
        "all_query_params": list(query_params.keys()),
        "recommendations": {
            "ios_safari_issues": [
                "iOS Safari has strict cookie policies",
                "Use Authorization header instead of cookies",
                "SameSite=Lax works better than SameSite=None",
                "Store tokens in localStorage/sessionStorage",
                "Add cache-control headers to prevent caching"
            ] if is_ios_safari else [],
            "general_mobile": [
                "Prefer Authorization header over cookies",
                "Use multiple token storage strategies",
                "Implement token recovery mechanisms"
            ] if is_mobile else []
        }
    }
