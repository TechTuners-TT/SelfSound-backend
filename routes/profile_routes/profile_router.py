import hashlib
import uuid
from pydantic import ValidationError
from fastapi import APIRouter, HTTPException, Depends, Request, UploadFile, File
from pydantic import BaseModel
from config import SUPABASE_URL, BUCKET_NAME
from jwt_handler import decode_jwt
from fastapi.responses import JSONResponse, RedirectResponse
from supabase_client import supabase
from models.token_request import decode_refresh_token, create_refresh_token, create_access_token
from models.schemas.user_profile import UserProfileResponse, UpdateProfileRequest, UpdateDescriptionRequest
from routes.dependencies import get_verified_user

router = APIRouter(prefix="/profile", tags=["Profile"])


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}
ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpg",
    "image/jpeg",
}


@router.patch("/me/avatar")
async def update_avatar(

        avatar: UploadFile = File(...),
        user=Depends(get_verified_user),
):
    user_sub = user.get("sub")
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid user data")
    import os

    # Validate file extension
    ext = os.path.splitext(avatar.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400,
                            detail=f"File extension '{ext}' is not allowed. Allowed: {ALLOWED_EXTENSIONS}")

    # Validate MIME type
    if avatar.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=400,
                            detail=f"File type '{avatar.content_type}' is not allowed. Allowed: {ALLOWED_MIME_TYPES}")

    try:
        content = await avatar.read()

        unique_filename = f"{uuid.uuid4()}{ext}"
        file_path = f"avatars/{user_sub}/{unique_filename}"

        # Upload to Supabase storage
        upload_response = supabase.storage.from_("avatars").upload(
            file_path,
            content,
            {"content-type": avatar.content_type}
        )

        # Check for upload errors
        if hasattr(upload_response, "error") and upload_response.error:
            raise HTTPException(status_code=500, detail=f"Failed to upload avatar: {upload_response.error}")

        # Construct public URL manually (more reliable)
        # You need to replace this with your actual Supabase project URL
        Format : f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET_NAME}/{file_path}"

        # Option 1: Get URL from supabase client (try different methods)
        try:
            if hasattr(supabase, 'supabase_url'):
                supabase_url = supabase.supabase_url.rstrip('/')
            elif hasattr(supabase, '_supabase_url'):
                supabase_url = supabase._supabase_url.rstrip('/')
            elif hasattr(supabase, 'url'):
                supabase_url = supabase.url.rstrip('/')
            else:
                # Fallback: use environment variable or hardcode your URL
                import os
                supabase_url = os.getenv('SUPABASE_URL', 'https://your-project-id.supabase.co').rstrip('/')
        except:
            # Last resort: use environment variable or hardcode
            import os
            supabase_url = os.getenv('SUPABASE_URL', 'https://your-project-id.supabase.co').rstrip('/')

        avatar_url = f"{supabase_url}/storage/v1/object/public/avatars/{file_path}"

        print(f"Generated avatar URL: {avatar_url}")

        # Update user profile with new avatar URL
        update_response = supabase.from_("user_profiles").update(
            {"avatar_url": avatar_url}
        ).eq("sub", user_sub).execute()

        if hasattr(update_response, "error") and update_response.error:
            raise HTTPException(status_code=500,
                                detail=f"Failed to update avatar URL in profile: {update_response.error}")

        return {
            "message": "Avatar updated successfully",
            "avatar_url": avatar_url,
            "data": update_response.data,
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in avatar upload: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
@router.get("/me/profile", response_model=UserProfileResponse)
def get_profile(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        user_info = decode_jwt(token)
        user_sub = user_info.get("sub")
        if not user_sub:
            raise HTTPException(status_code=401, detail="Invalid token payload: 'sub' not found")

        response = (
            supabase.from_("user_profiles")
            .select("*")
            .eq("sub", user_sub)
            .maybe_single()
            .execute()
        )

        if response is None:
            raise HTTPException(status_code=500, detail="Supabase returned None")

        if hasattr(response, "error") and response.error:
            raise HTTPException(status_code=500, detail=f"Database error: {response.error}")

        if not response.data:
            raise HTTPException(status_code=404, detail="User profile not found")

        return response.data

    except Exception as e:
        print(f"JWT decode or Supabase error: {e}")
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.patch("/me")
async def update_user_profile(request: Request, user=Depends(get_verified_user)):
    # 1) Read & log raw body for debugging
    raw = await request.body()
    print("RAW BODY:", raw.decode())

    # 2) Parse & report validation errors
    try:
        body = UpdateProfileRequest.parse_raw(raw)
    except ValidationError as ve:
        print("Pydantic validation errors:", ve.errors())
        raise HTTPException(status_code=422, detail=ve.errors())

    user_sub = user.get("sub")
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid user data")

    # Fetch current profile
    current = (
        supabase.from_("user_profiles")
        .select("*")
        .eq("sub", user_sub)
        .maybe_single()
        .execute()
    )
    if current is None or getattr(current, "error", None):
        raise HTTPException(status_code=500, detail="Error fetching profile")
    if not current.data:
        raise HTTPException(status_code=404, detail="Profile not found")

    update_data = {}

    # 3) Check login uniqueness
    if body.login and body.login != current.data["login"]:
        dup = supabase.from_("user_profiles").select("id").eq("login", body.login).execute()
        if dup is None or getattr(dup, "error", None):
            raise HTTPException(status_code=500, detail="Error checking login")
        if dup.data:
            raise HTTPException(status_code=409, detail="Login already taken")
        update_data["login"] = body.login

    # 4) Other optional text fields
    if body.name is not None:
        update_data["name"] = body.name
    if body.description is not None:
        update_data["description"] = body.description

    # 5) Tag handling
    if body.tag_id is not None:
        tag_val = body.tag_id

        # Clear tag
        if tag_val in ("Add tag", ""):
            update_data["tag_id"] = None

        # Predefined tags → lookup or create
        elif tag_val in ("Listener", "Musician", "Learner"):
            tag_resp = (
                supabase.from_("tags")
                .select("id")
                .eq("name", tag_val)
                .maybe_single()
                .execute()
            )
            if tag_resp is None or getattr(tag_resp, "error", None):
                raise HTTPException(status_code=500, detail=f"Error fetching tag '{tag_val}'")
            if tag_resp.data:
                update_data["tag_id"] = tag_resp.data["id"]
            else:
                new_tag = supabase.from_("tags").insert({"name": tag_val}).execute()
                if new_tag is None or getattr(new_tag, "error", None):
                    raise HTTPException(status_code=500, detail=f"Error creating tag '{tag_val}'")
                update_data["tag_id"] = new_tag.data[0]["id"]

        # Raw UUID string
        else:
            try:
                update_data["tag_id"] = uuid(str(tag_val))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid tag_id: {tag_val!r}")

    # 6) Nothing to update?
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    print(f"Updating profile for sub={user_sub} with", update_data)

    # 7) Perform the update
    upd = (
        supabase.from_("user_profiles")
        .update(update_data)
        .eq("sub", user_sub)
        .execute()
    )
    if upd is None or getattr(upd, "error", None):
        raise HTTPException(status_code=500, detail="Error updating profile")

    return {"message": "Profile updated", "data": upd.data}

@router.patch("/me/description")
async def update_description(body: UpdateDescriptionRequest, user=Depends(get_verified_user)):
    login = user.get("email").split("@")[0]

    user_profile = supabase.from_("user_profiles").select("*").eq("login", login).maybe_single().execute()
    if hasattr(user_profile, "error") and user_profile.error:
        print(f"Supabase error: {user_profile.error}")
        raise HTTPException(status_code=500, detail="Database error")

    if not user_profile.data:
        raise HTTPException(status_code=404, detail="User profile not found")

    response = (
        supabase.from_("user_profiles")
        .update({"description": body.description})
        .eq("login", login)
        .execute()
    )

    if hasattr(response, "error") and response.error:
        print(f"Supabase error: {response.error}")
        raise HTTPException(status_code=500, detail="Failed to update description")

    return {"message": "Description updated", "data": response.data}


@router.get("/me/description")
async def get_description(user=Depends(get_verified_user)):
    login = user.get("email").split("@")[0]

    user_profile = supabase.from_("user_profiles").select("description").eq("login", login).maybe_single().execute()
    if hasattr(user_profile, "error") and user_profile.error:
        print(f"Supabase error: {user_profile.error}")
        raise HTTPException(status_code=500, detail="Database error")

    if not user_profile.data:
        raise HTTPException(status_code=404, detail="User profile not found")

    return {"description": user_profile.data.get("description", "")}