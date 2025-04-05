from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import GOOGLE_CLIENT_ID, GOOGLE_AUTH_URL, GOOGLE_REDIRECT_URI, GOOGLE_CLIENT_SECRET
from jwt_handler import generate_jwt
from models.token_request import TokenRequest
from supabase_client import supabase
import httpx
import urllib.parse

router = APIRouter()

# Step 1: Redirect to Google Authorization URL
@router.get("/login")
def login():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    url = f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

# Step 2: Callback from Google after successful authorization
@router.get("/callback")
async def auth_callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code is missing")

    try:
        # Exchange the authorization code for tokens
        google_response = await exchange_code_for_token(code)

        # Extract the ID token from the response
        id_token_str = google_response.get('id_token')

        if not id_token_str:
            raise HTTPException(status_code=400, detail="ID token is missing")

        # 3. Verify ID token with Google
        id_info = id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        user_data = {
            "sub": id_info.get("sub"),
            "email": id_info.get("email"),
            "name": id_info.get("name"),
            "picture": id_info.get("picture"),
        }

        # 4. Check if the user already exists in Supabase
        existing_user = supabase.from_("users").select("*").eq("sub", user_data["sub"]).execute()

        if not existing_user.data:
            # 5. Insert new user into Supabase
            supabase.from_("users").insert(user_data).execute()

        # 6. Generate a custom JWT
        jwt_token = generate_jwt(id_info)

        # Return response with the JWT and user info
        return JSONResponse(content={
            "message": "Login successful!",
            "jwt": jwt_token,
            "user_info": {
                **user_data,
                "exp": id_info.get("exp")
            }
        })

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
    and id token from Google.
    """
    # Prepare the data to request the tokens
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,  # Make sure this is in your config file
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    # Make a POST request to exchange the code for tokens
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(token_url, data=data)
            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
            return response.json()  # Return the token data
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail="Error exchanging code for tokens")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An error occurred during token exchange: {str(e)}")
