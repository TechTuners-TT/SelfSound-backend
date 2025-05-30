from fastapi import APIRouter, HTTPException
from supabase_client import supabase
router = APIRouter()

@router.get("/profiles/{user_id}/posts")
async def get_user_posts(user_id: str):
    response = supabase.table("posts") \
        .select("*") \
        .eq("author_id", user_id) \
        .order("created_at", desc=True) \
        .execute()

    if response.error:
        raise HTTPException(status_code=500, detail="Failed to fetch posts")

    return response.data
