from fastapi import APIRouter, HTTPException, Request
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase


router = APIRouter(prefix="/tags", tags=["Tags"])


@router.get("/tags")
async def get_tags():
    try:
        response = supabase.from_("tags").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/me/set_tag")
async def set_user_tag(request: Request, tag_id: str):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_jwt(token)
    user_sub = payload.get("sub")

    try:
        # Update user's profile with new tag
        supabase.from_("user_profiles") \
            .update({"tag_id": tag_id}) \
            .eq("user_id", user_sub) \
            .execute()

        return {"message": "Tag updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/me/tag")
async def get_user_tag(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_jwt(token)
    user_sub = payload.get("sub")

    try:
        profile = supabase.from_("user_profiles") \
            .select("tag_id, tags(name)") \
            .eq("user_id", user_sub) \
            .single() \
            .execute()

        return profile.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))