from fastapi import APIRouter, HTTPException
from typing import List
from supabase_client import supabase
from models.schemas.post import PostOut
from models.schemas.user_profile import UserProfileResponse

guest_router = APIRouter(tags=["Guest Posts"])

@guest_router.get("/posts", response_model=List[PostOut])
async def list_posts_for_guests():
    """
    Public route to list posts along with author profile information.
    Accessible without authentication.
    """
    try:
        response = (
            supabase
            .table("posts")
            .select("*, user_profiles!author_id(*)")
            .order("created_at", desc=True)
            .execute()
        )
        if response.get("error"):
            raise HTTPException(status_code=500, detail="Failed to fetch posts")
        return response["data"]
    except Exception as e:
        print("Error fetching posts:", e)
        raise HTTPException(status_code=500, detail="Something went wrong while fetching posts")


@guest_router.get("/profile/{login}", response_model=UserProfileResponse)
async def get_profile_for_guest(login: str):
    """
    Public route for guests to view user profile information by login.
    Accessible without authentication.
    """
    try:
        # Fetch the user profile by login (unique identifier)
        user_profile_resp = supabase.from_("user_profiles").select("*").eq("login", login).single().execute()

        # If no profile is found, raise a 404 error
        if user_profile_resp.get("error"):
            raise HTTPException(status_code=404, detail="User profile not found")

        return user_profile_resp["data"]

    except Exception as e:
        print("Error fetching user profile:", e)
        raise HTTPException(status_code=500, detail="Something went wrong while fetching profile")
