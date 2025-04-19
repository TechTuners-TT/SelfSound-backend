from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from enum import Enum
import uuid
from supabase_client import supabase
from routes.profile_router import get_current_user
from fastapi import Path


router = APIRouter(prefix="/posts", tags=["Posts"])

class PostType(str, Enum):
    media = "media"
    audio = "audio"
    note = "note"
    lyrics = "lyrics"

class PostOut(BaseModel):
    id: str
    author_id: str
    description: Optional[str]
    post_type: PostType
    files: List[str]
    created_at: datetime

def upload_file_to_supabase(file: UploadFile, folder: str, user_id: str) -> str:
    from supabase_client import supabase

    file_ext = file.filename.split('.')[-1]
    filename = f"{user_id}_{uuid.uuid4()}.{file_ext}"
    path = f"{folder}/{filename}"
    file_content = file.file.read()

    result = supabase.storage.from_("post-files").upload(path, file_content, {
        "content-type": file.content_type
    })

    if result.get("error"):
        raise HTTPException(status_code=500, detail="Upload failed")

    return supabase.storage.from_("post-files").get_public_url(path)

@router.post("/", response_model=PostOut)
async def create_post(
    post_type: PostType = Form(...),
    description: str = Form(""),
    media_files: Optional[List[UploadFile]] = File(None),
    note_file: Optional[UploadFile] = File(None),
    current_user=Depends(get_current_user)
):
    user_id = current_user["sub"]
    uploaded_urls = []

    if post_type in [PostType.media, PostType.audio]:
        if not media_files or len(media_files) > 5:
            raise HTTPException(status_code=400, detail="Upload 1-5 files")
        folder = "media" if post_type == PostType.media else "audio"
        for file in media_files:
            uploaded_urls.append(upload_file_to_supabase(file, folder, user_id))

    elif post_type == PostType.note:
        if not note_file:
            raise HTTPException(status_code=400, detail="Note requires one file")
        uploaded_urls.append(upload_file_to_supabase(note_file, "note", user_id))

    response = supabase.table("posts").insert({
        "author_id": user_id,
        "description": description,
        "post_type": post_type.value,
        "files": uploaded_urls
    }).execute()

    if response.get("error"):
        raise HTTPException(status_code=500, detail="Post not saved")

    return response["data"][0]

@router.get("/", response_model=List[PostOut])
async def list_posts():
    response = supabase.table("posts").select("*").order("created_at", desc=True).execute()
    return response["data"]

@router.patch("/{post_id}", response_model=PostOut)
async def update_post(
    post_id: str = Path(...),
    description: Optional[str] = Form(None),
    media_files: Optional[List[UploadFile]] = File(None),
    note_file: Optional[UploadFile] = File(None),
    current_user=Depends(get_current_user)
):
    user_id = current_user["sub"]

    # 1. Fetch post and check if user owns it
    existing_post_resp = supabase.table("posts").select("*").eq("id", post_id).single().execute()
    if existing_post_resp.get("error"):
        raise HTTPException(status_code=404, detail="Post not found")

    post = existing_post_resp["data"]
    if post["author_id"] != user_id:
        raise HTTPException(status_code=403, detail="You can only edit your own posts")

    # 2. File replacement (if new files uploaded)
    uploaded_urls = post["files"]  # default: keep old files
    if media_files or note_file:
        post_type = post["post_type"]
        uploaded_urls = []

        if post_type in ["media", "audio"]:
            if not media_files or len(media_files) > 5:
                raise HTTPException(status_code=400, detail="Upload 1-5 files")
            folder = "media" if post_type == "media" else "audio"
            for file in media_files:
                uploaded_urls.append(upload_file_to_supabase(file, folder, user_id))

        elif post_type == "note":
            if not note_file:
                raise HTTPException(status_code=400, detail="Note requires one file")
            uploaded_urls.append(upload_file_to_supabase(note_file, "note", user_id))

    # 3. Update fields
    update_data = {
        "files": uploaded_urls
    }
    if description is not None:
        update_data["description"] = description

    updated_post_resp = supabase.table("posts").update(update_data).eq("id", post_id).execute()
    if updated_post_resp.get("error"):
        raise HTTPException(status_code=500, detail="Update failed")

    return updated_post_resp["data"][0]
