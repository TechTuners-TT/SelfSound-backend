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

logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/authorization", tags=["authorization"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "abc123"}


def get_cookie_security_settings():
    """Get cookie security settings based on environment"""
    environment = os.getenv("ENVIRONMENT", "development")

    if environment == "production":
        return {
            "httponly": True,
            "secure": True,  # HTTPS required for production
            "samesite": "none",  # Cross-site requests (GitHub Pages to Render)
            "max_age": 24 * 3600,
            "path": "/",
        }
    else:
        return {
            "httponly": True,
            "secure": False,  # HTTP for localhost development
            "samesite": "lax",  # Same-site for development
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
    print(f"🔍 Signup attempt for email: {user.email}")

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
        print(f"🔍 Processing signup for: {email_str}")

        # Check if user already exists
        existing_user = supabase.table("users").select("id, email, verified").eq("email", email_str).execute()
        print(f"🔍 Existing user check result: {existing_user}")

        if existing_user.data:
            existing_user_data = existing_user.data[0]
            if existing_user_data.get("verified"):
                raise HTTPException(400, "User already exists and is verified")
            else:
                # User exists but not verified - resend verification
                user_id = existing_user_data["id"]
                print(f"🔍 Resending verification for existing user: {user_id}")
                return await resend_verification_for_user(user_id, email_str, background_tasks)

        # Generate user ID and hash password
        user_id = generate_uuid_sub()
        hashed_password = pwd_context.hash(user.password)
        print(f"🔍 Generated user ID: {user_id}")

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
        print(f"🔍 User creation result: {created_user}")

        if not created_user.data:
            raise HTTPException(500, "Failed to create user record")

        # Generate unique login
        login = generate_unique_login(email_str)
        print(f"🔍 Generated unique login: {login}")

        # Create user profile (REMOVED created_at field)
        profile_data = {
            "id": user_id,
            "name": user.name,
            "login": login,
            "avatar_url": "https://cdn.builder.io/api/v1/image/assets/TEMP/3922534bd59dfe0deae8bd149c0b3cba46e3eb47?placeholderIfAbsent=true&apiKey=04fef95365634cc5973c2029f1fc78f5",
            "description": "",
            "email": email_str,
            "sub": user_id,
            # Removed created_at - let the database handle it if it has a default
        }

        print(f"🔍 Profile data to insert: {profile_data}")

        profile_result = supabase.table("user_profiles").insert(profile_data).execute()
        print(f"🔍 Profile creation result: {profile_result}")

        if not profile_result.data:
            # If profile creation fails, clean up the user record
            print("❌ Profile creation failed, cleaning up user record")
            supabase.table("users").delete().eq("id", user_id).execute()
            raise HTTPException(500, "Failed to create user profile")

        # Generate verification token
        verification_token = generate_verification_token()
        hashed_token = hash_token(verification_token)
        print(f"🔍 Generated verification token (first 10 chars): {verification_token[:10]}...")

        # Store verification token
        token_insert = {
            "user_id": user_id,
            "token": hashed_token,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        print(f"🔍 Token insert data: {token_insert}")

        token_result = supabase.table("email_verification_tokens").insert(token_insert).execute()
        print(f"🔍 Token insert result: {token_result}")

        if not token_result.data:
            # Clean up user and profile if token creation fails
            print("❌ Token creation failed, cleaning up user and profile")
            supabase.table("user_profiles").delete().eq("id", user_id).execute()
            supabase.table("users").delete().eq("id", user_id).execute()
            raise HTTPException(500, "Failed to create verification token")

        # Send verification email in background
        print("🔍 Scheduling verification email...")
        background_tasks.add_task(send_verification_email, email_str, verification_token)

        print("✅ Signup completed successfully")
        return {
            "message": "User created successfully. Please check your email for verification link.",
            "email": email_str
        }

    except HTTPException as he:
        print(f"❌ HTTPException: {he.detail}")
        raise
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        print(f"❌ Error type: {type(e)}")
        import traceback
        print(f"❌ Full traceback: {traceback.format_exc()}")
        logger.error(f"Signup error: {e}")
        raise HTTPException(500, f"Failed to create user: {str(e)}")


# Helper function for resending verification to existing unverified users
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


# SIMPLIFIED EMAIL VERIFICATION - GET route that redirects to sign-in WITH TIMEZONE FIX
@router.get("/verify-email")
async def verify_email_simple(token: str):
    """Simple email verification that redirects to sign-in page"""
    try:
        print(f"🔍 Verifying token: {token}")

        # Hash the provided token
        hashed_token = hash_token(token)
        print(f"🔍 Hashed token: {hashed_token}")

        # Find verification token
        token_result = supabase.table("email_verification_tokens").select("*").eq("token", hashed_token).execute()
        print(f"🔍 Token search result: {token_result}")

        if not token_result.data:
            print("❌ No token found in database")
            # Redirect to sign-in with error message
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=invalid_token",
                status_code=302
            )

        token_data = token_result.data[0]
        user_id = token_data["user_id"]
        print(f"🔍 Found user_id: {user_id}")

        # Check if token has expired - TIMEZONE FIX
        expires_at_str = token_data["expires_at"]
        print(f"🔍 Token expires at (string): {expires_at_str}")

        # Handle both timezone-aware and timezone-naive datetimes
        if expires_at_str.endswith('+00:00') or 'T' in expires_at_str:
            # Remove timezone info to make it naive for comparison
            expires_at_str = expires_at_str.replace('+00:00', '').replace('Z', '')
            expires_at = datetime.fromisoformat(expires_at_str)
        else:
            expires_at = datetime.fromisoformat(expires_at_str)

        current_time = datetime.utcnow()
        print(f"🔍 Token expires at: {expires_at}")
        print(f"🔍 Current time: {current_time}")
        print(f"🔍 Token expired? {current_time > expires_at}")

        if current_time > expires_at:
            print("❌ Token expired")
            # Delete expired token
            supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
            # Redirect to sign-in with error message
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=token_expired",
                status_code=302
            )

        # Check if user is already verified
        user_result = supabase.table("users").select("verified, email").eq("id", user_id).execute()
        print(f"🔍 User lookup result: {user_result}")

        if not user_result.data:
            print("❌ User not found")
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=user_not_found",
                status_code=302
            )

        user_data = user_result.data[0]
        print(f"🔍 Current user verified status: {user_data.get('verified')}")

        if user_data.get("verified"):
            print("✅ User already verified")
            # Delete used token
            supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
            # Redirect to sign-in with success message
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?success=already_verified",
                status_code=302
            )

        # Update user as verified
        print("🔍 Updating user verification status...")
        print(f"🔍 Attempting to update user_id: {user_id}")

        update_data = {
            "verified": True,
            "verified_at": datetime.utcnow().isoformat()
        }
        print(f"🔍 Update data: {update_data}")

        update_result = supabase.table("users").update(update_data).eq("id", user_id).execute()
        print(f"🔍 Update result: {update_result}")
        print(f"🔍 Update result data: {update_result.data}")
        print(f"🔍 Update result count: {getattr(update_result, 'count', 'No count')}")

        if not update_result.data:
            print("❌ Failed to update user - no data returned")
            return RedirectResponse(
                url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=verification_failed",
                status_code=302
            )

        # Verify the update worked by checking the user again
        verify_result = supabase.table("users").select("verified, verified_at").eq("id", user_id).execute()
        print(f"🔍 Verification check result: {verify_result}")

        # Delete used verification token
        delete_result = supabase.table("email_verification_tokens").delete().eq("token", hashed_token).execute()
        print(f"🔍 Token deletion result: {delete_result}")

        print("✅ Verification process completed")

        # Redirect to sign-in page with success message
        return RedirectResponse(
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?success=email_verified",
            status_code=302
        )

    except Exception as e:
        print(f"❌ Verification error: {str(e)}")
        import traceback
        print(f"❌ Full traceback: {traceback.format_exc()}")
        logger.error(f"Email verification failed: {e}")
        # Redirect to sign-in with error message
        return RedirectResponse(
            url=f"{FRONTEND_REDIRECT_URL}/#/sign-in?error=verification_error",
            status_code=302
        )


# Resend verification endpoint
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

        # ✅ USE DYNAMIC COOKIE SETTINGS INSTEAD OF HARDCODED
        cookie_settings = get_cookie_security_settings()

        # Add debug logging
        print(f"🔍 Environment: {os.getenv('ENVIRONMENT', 'development')}")
        print(f"🔍 Cookie settings: {cookie_settings}")
        print(f"🔍 Generated token: {access_token[:50]}...")

        response.set_cookie(
            key="access_token",
            value=access_token,
            **cookie_settings  # ✅ Use dynamic settings
        )

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
        cookie_settings = get_cookie_security_settings()

        response.delete_cookie(
            key="access_token",
            path="/",
            secure=cookie_settings["secure"],
            samesite=cookie_settings["samesite"]
        )

        logger.info("User logged out successfully")
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"message": "Logged out"}


# DEBUG ENDPOINTS FOR TESTING
@router.get("/debug-environment")
def debug_environment():
    """Check what environment variables are set"""
    return {
        "ENVIRONMENT": os.getenv("ENVIRONMENT", "NOT_SET"),
        "NODE_ENV": os.getenv("NODE_ENV", "NOT_SET"),
        "JWT_SECRET_SET": bool(os.getenv("JWT_SECRET")),
        "SUPABASE_URL_SET": bool(os.getenv("SUPABASE_URL")),
        "All_ENV_VARS": list(os.environ.keys())
    }


@router.get("/debug-cookies")
def debug_cookies(request: Request):
    """Debug what cookies are being received"""
    cookies = request.cookies
    environment = os.getenv("ENVIRONMENT", "development")
    cookie_settings = get_cookie_security_settings()

    return {
        "received_cookies": dict(cookies),
        "access_token_present": "access_token" in cookies,
        "access_token_value": cookies.get("access_token", "NOT_FOUND")[:50] if cookies.get(
            "access_token") else "NOT_FOUND",
        "environment": environment,
        "cookie_settings": cookie_settings,
        "all_headers": dict(request.headers)
    }


@router.post("/debug-email-send")
async def debug_email_send(email_data: dict):
    """Debug email sending without background task"""
    try:
        email = email_data.get("email", "steedslvu@gmail.com")

        # Generate a test token
        test_token = "test_token_12345"

        print(f"🔍 Starting direct email send to: {email}")

        # Try to send email DIRECTLY (not as background task)
        await send_verification_email(email, test_token)

        print(f"✅ Direct email send completed")

        return {"message": f"Direct email test completed for {email}"}

    except Exception as e:
        print(f"❌ Direct email send failed: {str(e)}")
        import traceback
        print(f"❌ Traceback: {traceback.format_exc()}")
        return {"error": f"Direct email send failed: {str(e)}"}


@router.get("/check-email-config")
async def check_email_config():
    """Check email configuration"""
    try:
        from config import EMAIL_SENDER, EMAIL_PASSWORD, SMTP_HOST, SMTP_PORT, FRONTEND_REDIRECT_URL

        return {
            "EMAIL_SENDER": EMAIL_SENDER[:5] + "***" if EMAIL_SENDER else "❌ Missing",
            "EMAIL_PASSWORD": "***" + EMAIL_PASSWORD[-4:] if EMAIL_PASSWORD else "❌ Missing",
            "SMTP_HOST": SMTP_HOST,
            "SMTP_PORT": SMTP_PORT,
            "SMTP_PORT_TYPE": str(type(SMTP_PORT)),
            "FRONTEND_REDIRECT_URL": FRONTEND_REDIRECT_URL
        }
    except ImportError as e:
        return {"error": f"Config import error: {str(e)}"}
    except Exception as e:
        return {"error": f"Config error: {str(e)}"}


@router.get("/get-user-token/{user_id}")
async def get_user_token(user_id: str):
    """Get the latest verification token for a user - for testing only"""
    try:
        # Get the latest token for this user
        token_result = supabase.table("email_verification_tokens").select("*").eq("user_id", user_id).execute()

        if not token_result.data:
            return {"error": "No tokens found for this user"}

        # Generate a new token for testing
        verification_token = generate_verification_token()
        hashed_token = hash_token(verification_token)

        # Update the database with the new token
        update_result = supabase.table("email_verification_tokens").update({
            "token": hashed_token,
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
        }).eq("user_id", user_id).execute()

        if update_result.data:
            verification_url = f"https://techtuners-tt.github.io/SelfSound/#/authorization/verify-email?token={verification_token}"
            return {
                "user_id": user_id,
                "token": verification_token,
                "verification_url": verification_url,
                "message": "New token generated successfully"
            }
        else:
            return {"error": "Failed to update token"}

    except Exception as e:
        return {"error": f"Failed to get token: {str(e)}"}


@router.post("/test-email-simple")
async def test_email_simple(email_data: dict):
    """Simple email test with better error handling"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from config import EMAIL_SENDER, EMAIL_PASSWORD, SMTP_HOST, SMTP_PORT

        recipient = email_data.get("email", "steedslvu@gmail.com")

        print(f"🔍 Testing email to: {recipient}")
        print(f"🔍 SMTP Config: {EMAIL_SENDER} -> {SMTP_HOST}:{SMTP_PORT} (type: {type(SMTP_PORT)})")

        # Create simple message
        msg = MIMEText("Test email from your app")
        msg['Subject'] = 'Test Email'
        msg['From'] = EMAIL_SENDER
        msg['To'] = recipient

        # Try different SMTP configurations
        configs = [
            {"port": 587, "use_tls": True, "name": "TLS 587"},
            {"port": 465, "use_ssl": True, "name": "SSL 465"}
        ]

        for config in configs:
            try:
                print(f"🔍 Trying {config['name']}")

                if config.get("use_ssl"):
                    server = smtplib.SMTP_SSL(SMTP_HOST, config["port"], timeout=10)
                else:
                    server = smtplib.SMTP(SMTP_HOST, config["port"], timeout=10)
                    if config.get("use_tls"):
                        server.starttls()

                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
                server.quit()

                return {
                    "status": "✅ SUCCESS",
                    "message": f"Email sent successfully using {config['name']}",
                    "recipient": recipient
                }

            except Exception as e:
                print(f"❌ {config['name']} failed: {str(e)}")
                continue

        return {"status": "❌ FAILED", "error": "All SMTP configurations failed"}

    except Exception as e:
        return {"error": f"Email test failed: {str(e)}"}


@router.get("/check-user-status/{user_id}")
async def check_user_status(user_id: str):
    """Check current user verification status"""
    try:
        user_result = supabase.table("users").select("id, email, verified, verified_at, created_at").eq("id",
                                                                                                        user_id).execute()

        if not user_result.data:
            return {"error": "User not found"}

        user_data = user_result.data[0]
        return {
            "user_id": user_data["id"],
            "email": user_data["email"],
            "verified": user_data.get("verified"),
            "verified_at": user_data.get("verified_at"),
            "created_at": user_data.get("created_at")
        }

    except Exception as e:
        return {"error": f"Failed to check user status: {str(e)}"}