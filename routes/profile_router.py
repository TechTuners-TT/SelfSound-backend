from fastapi import APIRouter, HTTPException, Request
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase
from typing import Optional
from pydantic import BaseModel


router = APIRouter(prefix="/profile", tags=["Profile"])

@router.get("/me/profile")
def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = decode_jwt(token)
        login = payload.get("email").split("@")[0]
        user = supabase.from_("user_profiles").select("*").eq("login", login).single().execute()
        return user.data
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token or user not found")

    # Request body schema
class UpdateProfileRequest(BaseModel):
        name: Optional[str] = None
        avatar_url: Optional[str] = None
        login: Optional[str] = None


@router.patch("/me")
def update_user_profile(request: Request, body: UpdateProfileRequest):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode token to get current login
        payload = decode_jwt(token)
        current_login = payload.get("email").split("@")[0]

        # Prepare only provided fields
        update_data = {}
        if body.name:
            update_data["name"] = body.name

        if body.avatar_url:
            update_data["avatar_url"] = body.avatar_url

        if body.login:
            update_data["login"] = body.login
        # Preventing updating a login that already exists
        if body.login and body.login != current_login:
            duplicate = supabase.from_("user_profiles").select("id").eq("login", body.login).execute()
            if duplicate.data:
                raise HTTPException(status_code=409, detail="Login already taken")

        if not update_data:
            raise HTTPException(status_code=400, detail="No fields provided to update")

        # Update in Supabase
        response = supabase \
            .from_("user_profiles") \
            .update(update_data) \
            .eq("login", current_login) \
            .execute()

        return {"message": "Profile updated", "data": response.data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

class UpdateDescriptionRequest(BaseModel):
    description: str

@router.patch("/me/description")
async def update_description(request: Request, body: UpdateDescriptionRequest):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the token to get the user info
        payload = decode_jwt(token)
        login = payload.get("email").split("@")[0]  # Use email part as login

        # Update the description in user_profiles
        update_data = {"description": body.description}

        # Check if the user profile exists
        user_profile = supabase.from_("user_profiles").select("*").eq("login", login).single().execute()
        if not user_profile.data:
            raise HTTPException(status_code=404, detail="User profile not found")

        # Update the description
        response = supabase.from_("user_profiles").update(update_data).eq("login", login).execute()

        return {"message": "Description updated", "data": response.data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update description: {str(e)}")


# Endpoint to get the current description
@router.get("/me/description")
async def get_description(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the token to get the user info
        payload = decode_jwt(token)
        login = payload.get("email").split("@")[0]  # Use email part as login

        # Fetch the user profile from user_profiles
        user_profile = supabase.from_("user_profiles").select("description").eq("login", login).single().execute()

        if not user_profile.data:
            raise HTTPException(status_code=404, detail="User profile not found")

        return {"description": user_profile.data.get("description", "")}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch description: {str(e)}")
