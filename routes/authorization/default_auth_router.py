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


def get_cookie_security_settings():
    """
    PRODUCTION: Cookie security settings for cross-origin deployment
    GitHub Pages (Frontend) -> Render (Backend)
    """
    environment = os.getenv("ENVIRONMENT", "production")

    if environment == "production":
        return {
            "httponly": True,  # 🔒 Security: Prevent XSS attacks
            "secure": True,  # 🔒 HTTPS only - CRITICAL for production
            "samesite": "none",  # 🌐 CRUCIAL: Cross-origin requests (GitHub Pages -> Render)
            "max_age": 24 * 3600,  # ⏰ 24 hours expiry
            "path": "/",  # 🌍 Available across entire backend
        }
    else:
        return {
            "httponly": True,  # 🔒 Security even in development
            "secure": False,  # 🏠 HTTP for localhost
            "samesite": "lax",  # 🏠 Same-site for development
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
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?success=email_verified",
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
def login(user: UserLogin, response: Response):
    try:
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
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # 🍪 PRODUCTION COOKIE: Use dynamic cookie settings
        cookie_settings = get_cookie_security_settings()

        response.set_cookie(
            key="access_token",
            value=access_token,
            **cookie_settings
        )

        logger.info("User login successful")

        return {
            "message": "Login successful",
            "user": {
                "id": user_data["id"],
                "email": user_data["email"],
                "name": user_data["name"],
                "verified": user_data.get("verified", False)
            },
            "expires_in": 24 * 3600
        }

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
        response: Response,
        user: dict = Depends(get_verified_user)
):
    user_id = user["id"]

    profile_res = supabase.table("user_profiles").delete().eq("id", user_id).execute()
    user_res = supabase.table("users").delete().eq("id", user_id).execute()

    if not delete_user_from_supabase_auth(user_id):
        raise HTTPException(status_code=500, detail="Failed to delete user from Supabase Auth")

    # 🍪 PRODUCTION COOKIE: Clean up cookies properly
    cookie_settings = get_cookie_security_settings()
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=cookie_settings["secure"],
        samesite=cookie_settings["samesite"]
    )

    return Response(status_code=200)


@router.post("/logout")
async def logout(response: Response):
    try:
        # 🍪 PRODUCTION COOKIE: Clean up cookies properly
        cookie_settings = get_cookie_security_settings()

        response.delete_cookie(
            key="access_token",
            path="/",
            secure=cookie_settings["secure"],
            samesite=cookie_settings["samesite"]
        )

        # 🧹 Backup cleanup with different settings to ensure removal
        backup_configs = [
            {"path": "/", "secure": True, "samesite": "none"},
            {"path": "/", "secure": False, "samesite": "lax"},
            {"path": "/"},
        ]

        for config in backup_configs:
            try:
                response.delete_cookie(key="access_token", **config)
            except:
                pass  # Ignore cleanup errors

        logger.info("User logged out successfully")
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"message": "Logged out"}