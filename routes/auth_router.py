from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import GOOGLE_CLIENT_ID, GOOGLE_AUTH_URL, GOOGLE_REDIRECT_URI, GOOGLE_CLIENT_SECRET
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase
from typing import Optional
from pydantic import BaseModel
import httpx
import urllib.parse

router = APIRouter()



# Redirect to Google Authorization URL
@router.get("/login")
def login(redirect_to: Optional[str] = None):
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    if redirect_to:
        # Закодувати redirect_to як параметр, щоб потім отримати його в /callback
        params["state"] = urllib.parse.quote(redirect_to)

    url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

# Step 2: Callback from Google after successful authorization
@router.get("/callback")
async def auth_callback(request: Request):
    code = request.query_params.get("code")
    redirect_to = request.query_params.get("state", "https://techtuners-tt.github.io/frontend/#/home")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code is missing")

    try:
        # Exchange the authorization code for tokens
        google_response = await exchange_code_for_token(code)

        id_token_str = google_response.get('id_token')
        if not id_token_str:
            raise HTTPException(status_code=400, detail="ID token is missing")

        # Verify the ID token with Google's API
        id_info = id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        email = id_info.get("email")
        login = email.split("@")[0]  # extract login
        name = id_info.get("name")
        avatar_url = id_info.get("picture")
        sub = id_info.get("sub")

        # Prepare user profile
        user_profile = {
            "id": sub,  # Optional, or Supabase can auto-generate UUID
            "name": name,
            "login": login,
            "avatar_url": avatar_url
        }

        existing = supabase.from_("user_profiles").select("id").eq("login", login).execute()

        if not existing.data:
            supabase.from_("user_profiles").insert(user_profile).execute()

        # Extract user data from the token
        user_data = {
            "sub": id_info.get("sub"),
            "email": id_info.get("email"),
            "name": id_info.get("name"),
            "picture": id_info.get("picture"),
        }

        # Check if user exists in Supabase, if not, create new user
        existing_user = supabase.from_("users").select("*").eq("sub", user_data["sub"]).execute()
        if not existing_user.data:
            supabase.from_("users").insert(user_data).execute()

        # Generate a custom JWT for the user
        jwt_token = generate_jwt(id_info)

        # Redirect back to frontend with the JWT in a cookie
        response = RedirectResponse(url=redirect_to, status_code=302)
        response.set_cookie(
            key="access_token",
            value=jwt_token,
            httponly=True,
            secure=True,  # Ensure your backend uses HTTPS
            samesite="Lax",  # Use "Strict" or "Lax" depending on your needs
            max_age=60 * 60 * 24 * 7,  # Cookie expiration (7 days)
            path="/"  # Cookie is available for all paths
        )
        return response

    except ValueError:
        raise HTTPException(status_code=401, detail="Token verification failed")
    except httpx.HTTPStatusError as http_error:
        raise HTTPException(status_code=http_error.response.status_code, detail=f"HTTP error occurred: {http_error}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

# Helper function to exchange code for token
async def exchange_code_for_token(code: str):
    """
    This function exchanges the authorization code for an access token
    and ID token from Google.
    """
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail="Error exchanging code for tokens")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An error occurred during token exchange: {str(e)}")

# Endpoint to get the current authenticated user
@router.get("/me/raw")
def get_current_user_raw(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the JWT token to get user information
        user_info = decode_jwt(token)
        return JSONResponse(content={"user": user_info})
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")




