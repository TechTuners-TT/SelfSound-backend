from fastapi import APIRouter, HTTPException, Request
from jwt_handler import decode_jwt
from supabase_client import supabase
from typing import List
from models.schemas.post import PostOut

feed_router = APIRouter(prefix="/feed", tags=["Feed"])


@feed_router.get("/following", response_model=List[PostOut])
async def get_following_feed(request: Request, page: int = 0, page_size: int = 10):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the JWT to get the current user
        payload = decode_jwt(token)
        current_user_id = payload.get("sub")

        # Fetch the list of users the current user is following (subscribed_id)
        followed_resp = supabase.from_("listeners") \
            .select("subscribed_id") \
            .eq("subscriber_id", current_user_id) \
            .execute()

        if followed_resp.get("error"):
            raise HTTPException(status_code=500, detail="Failed to fetch followed users")

        followed_ids = [item["subscribed_id"] for item in followed_resp.data]
        if not followed_ids:
            return []  # If no one is being followed, return an empty list

        # Pagination setup: Range the posts
        start = page * page_size
        end = start + page_size - 1

        # Fetch posts from followed users
        posts_resp = supabase.from_("posts") \
            .select("*") \
            .in_("author_id", followed_ids) \
            .order("created_at", desc=True) \
            .range(start, end) \
            .execute()

        if posts_resp.get("error"):
            raise HTTPException(status_code=500, detail="Failed to fetch feed posts")

        # Step 2: For each post, get the author's profile info (name and avatar_url)
        posts = posts_resp.data
        for post in posts:
            # Fetch the author's profile data using author_id
            author_resp = supabase.from_("user_profiles") \
                .select("name, avatar_url") \
                .eq("id", post["author_id"]) \
                .single() \
                .execute()

            if author_resp.get("error"):
                raise HTTPException(status_code=500, detail="Failed to fetch author profile")

            # Add the author's name and avatar_url to the post data
            post["author_name"] = author_resp.data["name"]
            post["author_avatar_url"] = author_resp.data["avatar_url"]

        return posts

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not get feed: {str(e)}")
