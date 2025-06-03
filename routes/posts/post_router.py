from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from typing import Annotated, List, Optional
import uuid
import os
import logging
from datetime import datetime, timezone
from routes.dependencies import get_verified_user
from supabase_client import supabase
import mimetypes

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/posts", tags=["Posts"])

# Supabase storage bucket names
STORAGE_BUCKET = "post-media"
AUDIO_STORAGE_BUCKET = "post-audio"

# Allowed file types
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"}
ALLOWED_VIDEO_TYPES = {"video/mp4", "video/mov", "video/avi", "video/mkv", "video/webm"}
ALLOWED_AUDIO_TYPES = {
    "audio/mpeg", "audio/mp3", "audio/wav", "audio/aac",
    "audio/ogg", "audio/flac", "audio/m4a", "audio/wma"
}
ALLOWED_TYPES = ALLOWED_IMAGE_TYPES | ALLOWED_VIDEO_TYPES

# File size limits (in bytes)
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_VIDEO_SIZE = 100 * 1024 * 1024  # 100MB
MAX_AUDIO_SIZE = 50 * 1024 * 1024  # 50MB


async def get_optional_user(request: Request) -> Optional[dict]:
    """Get current user if authenticated, None if not"""
    try:
        return await get_verified_user(request)
    except Exception as e:
        logger.debug(f"User not authenticated: {e}")
        return None


def get_file_type(content_type: str) -> str:
    """Determine if file is image or video"""
    if content_type in ALLOWED_IMAGE_TYPES:
        return "image"
    elif content_type in ALLOWED_VIDEO_TYPES:
        return "video"
    else:
        raise ValueError(f"Unsupported file type: {content_type}")


def validate_file(file: UploadFile) -> tuple[str, int]:
    """Validate uploaded file and return file type and size limit"""
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type. Allowed: {', '.join(ALLOWED_TYPES)}"
        )

    file_type = get_file_type(file.content_type)
    max_size = MAX_IMAGE_SIZE if file_type == "image" else MAX_VIDEO_SIZE

    return file_type, max_size


def validate_audio_file(file: UploadFile) -> None:
    """Validate uploaded audio file"""
    if file.content_type not in ALLOWED_AUDIO_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported audio file type. Allowed: {', '.join(ALLOWED_AUDIO_TYPES)}"
        )


async def upload_file_to_storage(file: UploadFile, file_path: str) -> str:
    """Upload file to Supabase storage and return public URL"""
    try:
        # Read file content
        file_content = await file.read()

        # Upload to Supabase storage
        response = supabase.storage.from_(STORAGE_BUCKET).upload(
            path=file_path,
            file=file_content,
            file_options={
                "content-type": file.content_type,
                "upsert": False
            }
        )

        # Check if upload was successful (newer Supabase client handling)
        if hasattr(response, 'error') and response.error:
            logger.error(f"Storage upload error: {response.error}")
            raise HTTPException(status_code=500, detail="Failed to upload file to storage")

        # Get public URL
        public_url = supabase.storage.from_(STORAGE_BUCKET).get_public_url(file_path)

        if not public_url:
            raise HTTPException(status_code=500, detail="Failed to get public URL for uploaded file")

        return public_url

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")


async def upload_audio_to_storage(file: UploadFile, file_path: str) -> str:
    """Upload audio file to Supabase storage and return public URL"""
    try:
        # Read file content
        file_content = await file.read()

        # Check file size
        if len(file_content) > MAX_AUDIO_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Audio file exceeds size limit of {MAX_AUDIO_SIZE // (1024 * 1024)}MB"
            )

        # Upload to Supabase storage
        response = supabase.storage.from_(AUDIO_STORAGE_BUCKET).upload(
            path=file_path,
            file=file_content,
            file_options={
                "content-type": file.content_type,
                "upsert": False
            }
        )

        # Check if upload was successful
        if hasattr(response, 'error') and response.error:
            logger.error(f"Audio storage upload error: {response.error}")
            raise HTTPException(status_code=500, detail="Failed to upload audio file to storage")

        # Get public URL
        public_url = supabase.storage.from_(AUDIO_STORAGE_BUCKET).get_public_url(file_path)

        if not public_url:
            raise HTTPException(status_code=500, detail="Failed to get public URL for uploaded audio file")

        return public_url

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audio file upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Audio file upload failed: {str(e)}")


def cleanup_uploaded_files(file_paths: List[str], bucket: str = STORAGE_BUCKET):
    """Helper function to clean up uploaded files on error"""
    for file_path in file_paths:
        try:
            supabase.storage.from_(bucket).remove([file_path])
            logger.info(f"Cleaned up file: {file_path}")
        except Exception as e:
            logger.warning(f"Failed to cleanup file {file_path}: {e}")


# IMPORTANT: Put specific routes BEFORE parameterized routes

@router.post("/media")
async def create_media_post(
    current_user: Annotated[dict, Depends(get_verified_user)],
    files: List[UploadFile] = File(...),
    caption: Optional[str] = Form(None)
):
    """Create a new media post with uploaded files"""
    if not files or len(files) == 0:
        raise HTTPException(status_code=400, detail="At least one file is required")

    if len(files) > 10:  # Limit number of files
        raise HTTPException(status_code=400, detail="Maximum 10 files allowed per post")

    try:
        user_id = current_user["id"]

        # Validate all files first
        validated_files = []
        total_size = 0

        for file in files:
            if not file.filename:
                raise HTTPException(status_code=400, detail="All files must have filenames")

            file_type, max_size = validate_file(file)

            # Read file content to get actual size
            file_content = await file.read()
            actual_size = len(file_content)

            if actual_size > max_size:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {file.filename} exceeds size limit of {max_size // (1024 * 1024)}MB"
                )

            total_size += actual_size
            # Reset file position for later use
            await file.seek(0)

            validated_files.append((file, file_type, actual_size))

        # Check total size limit (200MB for all files combined)
        if total_size > 200 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Total file size exceeds 200MB limit")

        # Create post record
        post_data = {
            "user_id": user_id,
            "type": "media",
            "caption": caption or "",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            post_response = supabase.table("posts").insert(post_data).execute()
            post_id = post_response.data[0]["id"]
            logger.info(f"Created post with ID: {post_id}")
        except Exception as e:
            logger.error(f"Error creating post: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create post")

        # Upload files and create media records
        media_records = []
        uploaded_files = []

        for index, (file, file_type, file_size) in enumerate(validated_files):
            try:
                # Generate unique filename
                file_extension = os.path.splitext(file.filename)[1]
                unique_filename = f"{post_id}_{index}_{uuid.uuid4().hex[:8]}{file_extension}"
                file_path = f"posts/{user_id}/{unique_filename}"

                # Upload file to storage
                public_url = await upload_file_to_storage(file, file_path)

                # Create media record
                media_data = {
                    "post_id": post_id,
                    "file_url": public_url,
                    "file_type": file_type,
                    "file_name": file.filename,
                    "file_size": file_size,
                    "order_index": index
                }

                media_records.append(media_data)
                uploaded_files.append(file_path)

            except Exception as e:
                logger.error(f"Error uploading file {file.filename}: {str(e)}")
                # Clean up any already uploaded files
                cleanup_uploaded_files(uploaded_files)
                raise HTTPException(status_code=500, detail=f"Failed to upload {file.filename}")

        # Insert all media records
        if media_records:
            try:
                media_response = supabase.table("post_media").insert(media_records).execute()
            except Exception as e:
                logger.error(f"Error creating media records: {str(e)}")
                # Clean up uploaded files
                cleanup_uploaded_files(uploaded_files)
                raise HTTPException(status_code=500, detail="Failed to create media records")

        logger.info(f"Successfully created media post with {len(media_records)} files")

        # Get user profile for complete response
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq("id", user_id).single().execute()
            user_data = user_response.data
        except Exception as e:
            logger.error(f"Error fetching user profile: {str(e)}")
            user_data = {"id": user_id, "name": "Unknown User", "login": "unknown", "avatar_url": "", "tag_id": None}

        # Return complete post data for immediate display
        return {
            "message": "Media post created successfully",
            "post_id": post_id,
            "post": {
                "id": post_id,
                "type": "media",
                "caption": caption or "",
                "created_at": post_data["created_at"],
                "likes_count": 0,
                "comments_count": 0,
                "user": user_data,
                "user_liked": False,
                "media": [
                    {
                        "id": None,  # Media IDs aren't returned from insert
                        "file_url": media["file_url"],
                        "file_type": media["file_type"],
                        "file_name": media["file_name"],
                        "order_index": media["order_index"]
                    }
                    for media in media_records
                ]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating media post: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create media post")


@router.post("/audio")
async def create_audio_post(
    current_user: Annotated[dict, Depends(get_verified_user)],
    audio_files: List[UploadFile] = File(...),
    cover_image: Optional[UploadFile] = File(None),
    titles: List[str] = Form(...),
    artists: List[str] = Form(...),
    caption: Optional[str] = Form(None)
):
    """Create a new audio post with uploaded audio files"""

    if not audio_files or len(audio_files) == 0:
        raise HTTPException(status_code=400, detail="At least one audio file is required")

    if len(audio_files) > 10:  # Limit number of audio files
        raise HTTPException(status_code=400, detail="Maximum 10 audio files allowed per post")

    if len(titles) != len(audio_files) or len(artists) != len(audio_files):
        raise HTTPException(status_code=400, detail="Each audio file must have a title and artist")

    try:
        user_id = current_user["id"]

        # Validate all audio files first
        validated_audio_files = []
        total_size = 0

        for i, file in enumerate(audio_files):
            if not file.filename:
                raise HTTPException(status_code=400, detail="All audio files must have filenames")

            validate_audio_file(file)

            # Read file content to get actual size
            file_content = await file.read()
            actual_size = len(file_content)

            if actual_size > MAX_AUDIO_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail=f"Audio file {file.filename} exceeds size limit of {MAX_AUDIO_SIZE // (1024 * 1024)}MB"
                )

            total_size += actual_size
            # Reset file position for later use
            await file.seek(0)

            validated_audio_files.append((file, actual_size, titles[i], artists[i]))

        # Check total size limit (200MB for all files combined)
        if total_size > 200 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Total audio file size exceeds 200MB limit")

        # Handle cover image if provided
        cover_url = None
        cover_path = None
        if cover_image and cover_image.filename:
            # Validate cover image (reuse media validation)
            if cover_image.content_type not in ALLOWED_IMAGE_TYPES:
                raise HTTPException(status_code=400, detail="Cover image must be JPEG, PNG, GIF, or WebP")

            cover_content = await cover_image.read()
            if len(cover_content) > 10 * 1024 * 1024:  # 10MB limit for cover
                raise HTTPException(status_code=400, detail="Cover image exceeds 10MB limit")

            await cover_image.seek(0)

        # Create post record
        post_data = {
            "user_id": user_id,
            "type": "audio",
            "caption": caption or "",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            post_response = supabase.table("posts").insert(post_data).execute()
            post_id = post_response.data[0]["id"]
            logger.info(f"Created audio post with ID: {post_id}")
        except Exception as e:
            logger.error(f"Error creating audio post: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create audio post")

        # Upload cover image if provided
        if cover_image and cover_image.filename:
            try:
                cover_extension = os.path.splitext(cover_image.filename)[1]
                cover_filename = f"{post_id}_cover_{uuid.uuid4().hex[:8]}{cover_extension}"
                cover_path = f"posts/{user_id}/covers/{cover_filename}"

                # Upload to media bucket (reuse existing media bucket for covers)
                cover_url = await upload_file_to_storage(cover_image, cover_path)
                logger.info(f"Uploaded cover image: {cover_path}")
            except Exception as e:
                logger.error(f"Error uploading cover image: {str(e)}")
                # Continue without cover - not critical for audio posts

        # Upload audio files and create audio records
        audio_records = []
        uploaded_files = []

        for index, (file, file_size, title, artist) in enumerate(validated_audio_files):
            try:
                # Generate unique filename
                file_extension = os.path.splitext(file.filename)[1]
                unique_filename = f"{post_id}_{index}_{uuid.uuid4().hex[:8]}{file_extension}"
                file_path = f"posts/{user_id}/{unique_filename}"

                # Upload audio file to storage
                public_url = await upload_audio_to_storage(file, file_path)

                # Create audio record
                audio_data = {
                    "post_id": post_id,
                    "title": title.strip(),
                    "artist": artist.strip(),
                    "file_url": public_url,
                    "file_name": file.filename,
                    "file_size": file_size,
                    "cover_url": cover_url,  # Same cover for all tracks in this post
                    "duration": "0:00",  # Will be updated by frontend after loading
                    "order_index": index
                }

                audio_records.append(audio_data)
                uploaded_files.append(file_path)

            except Exception as e:
                logger.error(f"Error uploading audio file {file.filename}: {str(e)}")
                # Clean up any already uploaded files
                cleanup_uploaded_files(uploaded_files, AUDIO_STORAGE_BUCKET)
                if cover_path:
                    cleanup_uploaded_files([cover_path])
                raise HTTPException(status_code=500, detail=f"Failed to upload {file.filename}")

        # Insert all audio records
        if audio_records:
            try:
                audio_response = supabase.table("post_audio").insert(audio_records).execute()
            except Exception as e:
                logger.error(f"Error creating audio records: {str(e)}")
                # Clean up uploaded files
                cleanup_uploaded_files(uploaded_files, AUDIO_STORAGE_BUCKET)
                if cover_path:
                    cleanup_uploaded_files([cover_path])
                raise HTTPException(status_code=500, detail="Failed to create audio records")

        logger.info(f"Successfully created audio post with {len(audio_records)} audio files")

        # Get user profile for complete response
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq("id", user_id).single().execute()
            user_data = user_response.data
        except Exception as e:
            logger.error(f"Error fetching user profile: {str(e)}")
            user_data = {"id": user_id, "name": "Unknown User", "login": "unknown", "avatar_url": "", "tag_id": None}

        # Return complete post data for immediate display
        return {
            "message": "Audio post created successfully",
            "post_id": post_id,
            "post": {
                "id": post_id,
                "type": "audio",
                "caption": caption or "",
                "created_at": post_data["created_at"],
                "likes_count": 0,
                "comments_count": 0,
                "user": user_data,
                "user_liked": False,
                "audio": [
                    {
                        "id": None,  # Audio IDs aren't returned from insert
                        "title": audio["title"],
                        "artist": audio["artist"],
                        "file_url": audio["file_url"],
                        "file_name": audio["file_name"],
                        "cover_url": audio["cover_url"],
                        "duration": audio["duration"],
                        "order_index": audio["order_index"]
                    }
                    for audio in audio_records
                ]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating audio post: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create audio post")


@router.get("/feed")
async def get_posts_feed(
    limit: int = 20,
    offset: int = 0,
    current_user: Optional[dict] = Depends(get_optional_user)
):
    """Get all posts from all users (feed)"""
    try:
        # Get all posts ordered by creation date
        try:
            posts_response = (
                supabase.table("posts")
                .select("*")
                .order("created_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )
            posts = posts_response.data or []
        except Exception as e:
            logger.error(f"Error fetching posts: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to fetch posts")

        if not posts:
            return []

        # Get unique user IDs and post IDs
        user_ids = list(set([post["user_id"] for post in posts]))
        post_ids = [post["id"] for post in posts]

        # Get user profiles
        try:
            users_response = (
                supabase.table("user_profiles")
                .select("id, name, login, avatar_url, tag_id")
                .in_("id", user_ids)
                .execute()
            )
            users_data = users_response.data or []
        except Exception as e:
            logger.error(f"Error fetching user profiles: {str(e)}")
            users_data = []

        users_by_id = {user["id"]: user for user in users_data}

        # Get media for all posts
        try:
            media_response = (
                supabase.table("post_media")
                .select("*")
                .in_("post_id", post_ids)
                .order("order_index")
                .execute()
            )
            media_data = media_response.data or []
        except Exception as e:
            logger.error(f"Error fetching media: {str(e)}")
            media_data = []

        # Group media by post_id
        media_by_post = {}
        for media in media_data:
            post_id = media["post_id"]
            if post_id not in media_by_post:
                media_by_post[post_id] = []
            media_by_post[post_id].append(media)

        # Get audio for all posts
        try:
            audio_response = (
                supabase.table("post_audio")
                .select("*")
                .in_("post_id", post_ids)
                .order("order_index")
                .execute()
            )
            audio_data = audio_response.data or []
        except Exception as e:
            logger.error(f"Error fetching audio: {str(e)}")
            audio_data = []

        # Group audio by post_id
        audio_by_post = {}
        for audio in audio_data:
            post_id = audio["post_id"]
            if post_id not in audio_by_post:
                audio_by_post[post_id] = []
            audio_by_post[post_id].append(audio)

        # Get musicxml for all posts
        try:
            musicxml_response = (
                supabase.table("post_musicxml")
                .select("*")
                .in_("post_id", post_ids)
                .order("order_index")
                .execute()
            )
            musicxml_data = musicxml_response.data or []
        except Exception as e:
            logger.error(f"Error fetching musicxml: {str(e)}")
            musicxml_data = []

        # Group musicxml by post_id
        musicxml_by_post = {}
        for musicxml in musicxml_data:
            post_id = musicxml["post_id"]
            if post_id not in musicxml_by_post:
                musicxml_by_post[post_id] = []
            musicxml_by_post[post_id].append(musicxml)

        # Get lyrics for all posts
        try:
            lyrics_response = (
                supabase.table("post_lyrics")
                .select("*")
                .in_("post_id", post_ids)
                .execute()
            )
            lyrics_data = lyrics_response.data or []
        except Exception as e:
            logger.error(f"Error fetching lyrics: {str(e)}")
            lyrics_data = []

        # Group lyrics by post_id (only one lyrics record per post)
        lyrics_by_post = {}
        for lyrics in lyrics_data:
            post_id = lyrics["post_id"]
            lyrics_by_post[post_id] = lyrics

        # Get likes for current user if authenticated
        user_likes = set()
        if current_user:
            try:
                likes_response = (
                    supabase.table("post_likes")
                    .select("post_id")
                    .in_("post_id", post_ids)
                    .eq("user_id", current_user["id"])
                    .execute()
                )
                if likes_response.data:
                    user_likes = {like["post_id"] for like in likes_response.data}
            except Exception as e:
                logger.error(f"Error fetching user likes: {str(e)}")
                # Continue without likes data - not critical for feed display

        # Format response
        formatted_posts = []
        for post in posts:
            post_id = post["id"]
            user_data = users_by_id.get(post["user_id"], {
                "id": post["user_id"],
                "name": "Unknown User",
                "login": "unknown",
                "avatar_url": "",
                "tag_id": None
            })

            formatted_posts.append({
                "id": post_id,
                "type": post["type"],
                "caption": post.get("caption", ""),
                "created_at": post["created_at"],
                "likes_count": post.get("likes_count", 0),
                "comments_count": post.get("comments_count", 0),
                "user": user_data,
                "user_liked": post_id in user_likes,
                "media": [
                    {
                        "id": media["id"],
                        "file_url": media["file_url"],
                        "file_type": media["file_type"],
                        "file_name": media["file_name"],
                        "order_index": media["order_index"]
                    }
                    for media in media_by_post.get(post_id, [])
                ],
                "audio": [
                    {
                        "id": audio["id"],
                        "title": audio["title"],
                        "artist": audio["artist"],
                        "file_url": audio["file_url"],
                        "file_name": audio["file_name"],
                        "cover_url": audio["cover_url"],
                        "duration": audio["duration"],
                        "order_index": audio["order_index"]
                    }
                    for audio in audio_by_post.get(post_id, [])
                ],
                "musicxml": [
                    {
                        "id": musicxml["id"],
                        "title": musicxml["title"],
                        "composer": musicxml["composer"],
                        "file_url": musicxml["file_url"],
                        "file_name": musicxml["file_name"],
                        "order_index": musicxml["order_index"]
                    }
                    for musicxml in musicxml_by_post.get(post_id, [])
                ],
                "lyrics": lyrics_by_post.get(post_id) and {
                    "title": lyrics_by_post[post_id]["title"],
                    "artist": lyrics_by_post[post_id]["artist"],
                    "lyrics_text": lyrics_by_post[post_id]["lyrics_text"],
                    "parts_data": lyrics_by_post[post_id]["parts_data"]
                } or None
            })

        return formatted_posts

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user posts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user posts")


@router.get("/feed/listened-to")
async def get_listened_to_feed(
        request: Request,
        limit: int = 20,
        offset: int = 0
):
    """Get posts from users that the current user is following (listened to)"""
    try:
        # Get current user using your existing auth system
        current_user = await get_verified_user(request)
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        user_id = current_user["id"]

        # First, get the list of users that the current user is following
        try:
            following_response = (
                supabase.table("listened_users")
                .select("listened_id")
                .eq("listener_id", user_id)
                .execute()
            )
            following_data = following_response.data or []
        except Exception as e:
            logger.error(f"Error fetching following list: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to fetch following list")

        # If user is not following anyone, return empty array
        if not following_data:
            return []

        # Extract the user IDs that the current user is following
        following_user_ids = [follow["listened_id"] for follow in following_data]

        # Get posts from followed users
        try:
            posts_response = (
                supabase.table("posts")
                .select("*")
                .in_("user_id", following_user_ids)
                .order("created_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )
            posts = posts_response.data or []
        except Exception as e:
            logger.error(f"Error fetching posts from followed users: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to fetch posts")

        if not posts:
            return []

        # Get unique user IDs and post IDs
        user_ids = list(set([post["user_id"] for post in posts]))
        post_ids = [post["id"] for post in posts]

        # Get user profiles
        try:
            users_response = (
                supabase.table("user_profiles")
                .select("id, name, login, avatar_url, tag_id")
                .in_("id", user_ids)
                .execute()
            )
            users_data = users_response.data or []
        except Exception as e:
            logger.error(f"Error fetching user profiles: {str(e)}")
            users_data = []

        users_by_id = {user["id"]: user for user in users_data}

        # Get media for all posts
        try:
            media_response = (
                supabase.table("post_media")
                .select("*")
                .in_("post_id", post_ids)
                .order("order_index")
                .execute()
            )
            media_data = media_response.data or []
        except Exception as e:
            logger.error(f"Error fetching media: {str(e)}")
            media_data = []

        # Group media by post_id
        media_by_post = {}
        for media in media_data:
            post_id = media["post_id"]
            if post_id not in media_by_post:
                media_by_post[post_id] = []
            media_by_post[post_id].append(media)

        # Get audio for all posts
        try:
            audio_response = (
                supabase.table("post_audio")
                .select("*")
                .in_("post_id", post_ids)
                .order("order_index")
                .execute()
            )
            audio_data = audio_response.data or []
        except Exception as e:
            logger.error(f"Error fetching audio: {str(e)}")
            audio_data = []

        # Group audio by post_id
        audio_by_post = {}
        for audio in audio_data:
            post_id = audio["post_id"]
            if post_id not in audio_by_post:
                audio_by_post[post_id] = []
            audio_by_post[post_id].append(audio)

        # Get musicxml for all posts
        try:
            musicxml_response = (
                supabase.table("post_musicxml")
                .select("*")
                .in_("post_id", post_ids)
                .order("order_index")
                .execute()
            )
            musicxml_data = musicxml_response.data or []
        except Exception as e:
            logger.error(f"Error fetching musicxml: {str(e)}")
            musicxml_data = []

        # Group musicxml by post_id
        musicxml_by_post = {}
        for musicxml in musicxml_data:
            post_id = musicxml["post_id"]
            if post_id not in musicxml_by_post:
                musicxml_by_post[post_id] = []
            musicxml_by_post[post_id].append(musicxml)

        # Get lyrics for all posts
        try:
            lyrics_response = (
                supabase.table("post_lyrics")
                .select("*")
                .in_("post_id", post_ids)
                .execute()
            )
            lyrics_data = lyrics_response.data or []
        except Exception as e:
            logger.error(f"Error fetching lyrics: {str(e)}")
            lyrics_data = []

        # Group lyrics by post_id
        lyrics_by_post = {}
        for lyrics in lyrics_data:
            post_id = lyrics["post_id"]
            lyrics_by_post[post_id] = lyrics

        # Get likes for current user
        user_likes = set()
        try:
            likes_response = (
                supabase.table("post_likes")
                .select("post_id")
                .in_("post_id", post_ids)
                .eq("user_id", user_id)
                .execute()
            )
            if likes_response.data:
                user_likes = {like["post_id"] for like in likes_response.data}
        except Exception as e:
            logger.error(f"Error fetching user likes: {str(e)}")
            # Continue without likes data - not critical

        # Format response (same as regular feed)
        formatted_posts = []
        for post in posts:
            post_id = post["id"]
            user_data = users_by_id.get(post["user_id"], {
                "id": post["user_id"],
                "name": "Unknown User",
                "login": "unknown",
                "avatar_url": "",
                "tag_id": None
            })

            formatted_posts.append({
                "id": post_id,
                "type": post["type"],
                "caption": post.get("caption", ""),
                "created_at": post["created_at"],
                "likes_count": post.get("likes_count", 0),
                "comments_count": post.get("comments_count", 0),
                "user": user_data,
                "user_liked": post_id in user_likes,
                "media": [
                    {
                        "id": media["id"],
                        "file_url": media["file_url"],
                        "file_type": media["file_type"],
                        "file_name": media["file_name"],
                        "order_index": media["order_index"]
                    }
                    for media in media_by_post.get(post_id, [])
                ],
                "audio": [
                    {
                        "id": audio["id"],
                        "title": audio["title"],
                        "artist": audio["artist"],
                        "file_url": audio["file_url"],
                        "file_name": audio["file_name"],
                        "cover_url": audio["cover_url"],
                        "duration": audio["duration"],
                        "order_index": audio["order_index"]
                    }
                    for audio in audio_by_post.get(post_id, [])
                ],
                "musicxml": [
                    {
                        "id": musicxml["id"],
                        "title": musicxml["title"],
                        "composer": musicxml["composer"],
                        "file_url": musicxml["file_url"],
                        "file_name": musicxml["file_name"],
                        "order_index": musicxml["order_index"]
                    }
                    for musicxml in musicxml_by_post.get(post_id, [])
                ],
                "lyrics": lyrics_by_post.get(post_id) and {
                    "title": lyrics_by_post[post_id]["title"],
                    "artist": lyrics_by_post[post_id]["artist"],
                    "lyrics_text": lyrics_by_post[post_id]["lyrics_text"],
                    "parts_data": lyrics_by_post[post_id]["parts_data"]
                } or None
            })

        return formatted_posts

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching listened to posts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch listened to posts")


@router.get("/following/check/{user_id}")
async def check_following_status(
        user_id: str,
        request: Request
):
    """Check if current user is following the specified user"""
    try:
        # Validate user_id is UUID
        try:
            uuid.UUID(user_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid user ID format")

        current_user = await get_verified_user(request)
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        listener_id = current_user["id"]

        # Check if the follow relationship exists in listened_users table
        try:
            follow_response = (
                supabase.table("listened_users")
                .select("id")
                .eq("listener_id", listener_id)
                .eq("listened_id", user_id)
                .execute()
            )

            is_following = len(follow_response.data or []) > 0

            return {"is_following": is_following}

        except Exception as e:
            logger.error(f"Error checking follow status: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to check follow status")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in check_following_status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check follow status")


import logging

logger = logging.getLogger(__name__)

@router.post("/follow/{user_id}")
async def toggle_follow(
        user_id: str,
        request: Request
):
    """Follow or unfollow a user"""
    try:
        # Validate user_id is UUID
        try:
            uuid.UUID(user_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid user ID format")

        current_user = await get_verified_user(request)
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        listener_id = current_user["id"]

        # Can't follow yourself
        if listener_id == user_id:
            raise HTTPException(status_code=400, detail="Cannot follow yourself")

        # Check if user exists
        try:
            user_response = supabase.table("user_profiles").select("id").eq("id", user_id).single().execute()
            if not user_response.data:
                raise HTTPException(status_code=404, detail="User not found")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                raise HTTPException(status_code=404, detail="User not found")
            logger.error(f"Error verifying user existence: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to verify user")

        # Check if already following
        try:
            existing_follow = (
                supabase.table("listened_users")
                .select("id")
                .eq("listener_id", listener_id)
                .eq("listened_id", user_id)
                .execute()
            )

            if existing_follow.data and len(existing_follow.data) > 0:
                # Unfollow - remove the follow relationship
                follow_id = existing_follow.data[0]["id"]
                supabase.table("listened_users").delete().eq("id", follow_id).execute()
                logger.info(f"User {listener_id} unfollowed user {user_id}")
                return {"message": "User unfollowed", "is_following": False}
            else:
                # Follow - create the follow relationship
                follow_data = {
                    "listener_id": listener_id,
                    "listened_id": user_id,
                    "listened_at": datetime.now(timezone.utc).isoformat()
                }
                supabase.table("listened_users").insert(follow_data).execute()
                logger.info(f"User {listener_id} followed user {user_id}")
                return {"message": "User followed", "is_following": True}

        except Exception as e:
            logger.error(f"Error toggling follow: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to toggle follow")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in toggle_follow: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to toggle follow")


@router.get("/{post_id}/comments")
async def get_comments(
    post_id: str,
    current_user: Optional[dict] = Depends(get_optional_user),
    limit: int = 50,
    offset: int = 0
):
    """Get comments for a specific post"""
    try:
        # Validate post ID is UUID
        try:
            uuid.UUID(post_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid post ID format")

        # Get comments for the post
        try:
            comments_response = (
                supabase.table("post_comments")
                .select("*")
                .eq("post_id", post_id)
                .order("created_at", desc=False)  # Oldest first
                .range(offset, offset + limit - 1)
                .execute()
            )
            comments = comments_response.data or []
        except Exception as e:
            logger.error(f"Error fetching comments for post {post_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to fetch comments")

        if not comments:
            return []

        # Get unique user IDs from comments
        user_ids = list(set([comment["user_id"] for comment in comments]))

        # Get user profiles for all commenters
        try:
            users_response = (
                supabase.table("user_profiles")
                .select("id, name, login, avatar_url, tag_id")
                .in_("id", user_ids)
                .execute()
            )
            users_data = users_response.data or []
            users_by_id = {user["id"]: user for user in users_data}
        except Exception as e:
            logger.error(f"Error fetching user profiles for comments: {str(e)}")
            users_by_id = {}

        # Map user roles
        def map_user_role(tag_id):
            role_map = {
                "146fb41a-2f3e-48c7-bef9-01de0279dfd7": "Listener",
                "b361c6f9-9425-4548-8c07-cb408140c304": "Musician",
                "5ee121a6-b467-4ead-b3f7-00e1ce6097d5": "Learner"
            }
            return role_map.get(tag_id, "Listener")

        # Format comments
        formatted_comments = []
        for comment in comments:
            user_data = users_by_id.get(comment["user_id"], {
                "id": comment["user_id"],
                "name": "Unknown User",
                "login": "unknown",
                "avatar_url": "",
                "tag_id": None
            })

            formatted_comments.append({
                "id": comment["id"],
                "text": comment["content"],
                "created_at": comment["created_at"],
                "user": {
                    "id": user_data["id"],
                    "name": user_data["name"],
                    "login": user_data["login"],
                    "avatar_url": user_data["avatar_url"] or "",
                    "role": map_user_role(user_data["tag_id"])
                }
            })

        return formatted_comments

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_comments: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch comments")


@router.post("/{post_id}/comments")
async def create_comment(
        post_id: str,
        comment_data: dict,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Create a new comment on a post with mention notifications"""
    try:
        logger.debug(f"Starting create_comment for post: {post_id}")
        logger.debug(f"Comment data received: {comment_data}")

        # Validate post ID is UUID
        try:
            uuid.UUID(post_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid post ID format")

        # Validate comment content
        content = comment_data.get("content", "").strip()
        logger.debug(f"Comment content: '{content}'")

        if not content:
            raise HTTPException(status_code=400, detail="Comment content is required")

        if len(content) > 1000:
            raise HTTPException(status_code=400, detail="Comment is too long (max 1000 characters)")

        # Check if post exists and get post owner
        try:
            post_response = supabase.table("posts").select("id, user_id").eq("id", post_id).single().execute()
            if not post_response.data:
                raise HTTPException(status_code=404, detail="Post not found")
            post_data = post_response.data
            logger.debug(f"Post found, owner: {post_data['user_id']}")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                raise HTTPException(status_code=404, detail="Post not found")
            logger.error(f"Error verifying post: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to verify post")

        user_id = current_user["id"]
        logger.debug(f"Current user ID: {user_id}")

        # Extract mentions from comment content
        mentioned_usernames = extract_mentions(content)
        logger.debug(f"Extracted mentions: {mentioned_usernames}")

        # Resolve usernames to user IDs
        mentioned_users = await resolve_usernames_to_ids(mentioned_usernames)
        logger.debug(f"Resolved mentions: {mentioned_users}")

        # Create comment
        comment_record = {
            "post_id": post_id,
            "user_id": user_id,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            comment_response = supabase.table("post_comments").insert(comment_record).execute()
            created_comment = comment_response.data[0]
            logger.info(f"Comment created with ID: {created_comment['id']}")
        except Exception as e:
            logger.error(f"Error creating comment: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create comment")

        # Update comments count on post
        try:
            current_post = supabase.table("posts").select("comments_count").eq("id", post_id).single().execute()
            new_count = (current_post.data["comments_count"] or 0) + 1
            supabase.table("posts").update({"comments_count": new_count}).eq("id", post_id).execute()
            logger.debug(f"Updated comments count to: {new_count}")
        except Exception as e:
            logger.error(f"Error updating comments count: {str(e)}")
            # Continue - comment was created successfully

        # Send notifications to mentioned users
        for username, mentioned_user_id in mentioned_users.items():
            try:
                logger.debug(f"Sending mention notification to {username} (ID: {mentioned_user_id})")

                # Try with post_id parameter first, fallback to without if it fails
                try:
                    await create_notification(
                        recipient_id=mentioned_user_id,
                        sender_id=user_id,
                        notification_type="mention",
                        message=f"mentioned you in a comment",
                        post_id=post_id
                    )
                except TypeError as e:
                    logger.warning(f"create_notification doesn't support post_id yet, using old version: {e}")
                    # Fallback to old function signature
                    await create_notification(
                        recipient_id=mentioned_user_id,
                        sender_id=user_id,
                        notification_type="mention",
                        message=f"mentioned you in a comment"
                    )

                logger.debug(f"Sent mention notification to {username}")
            except Exception as e:
                logger.error(f"Error sending mention notification to {username}: {str(e)}")
                # Continue - don't fail comment creation due to notification errors

        # Send notification to post owner (if not the commenter and not already mentioned)
        post_owner_id = post_data["user_id"]
        if post_owner_id != user_id and post_owner_id not in mentioned_users.values():
            try:
                logger.debug(f"Sending comment notification to post owner (ID: {post_owner_id})")

                # Try with post_id parameter first, fallback to without if it fails
                try:
                    await create_notification(
                        recipient_id=post_owner_id,
                        sender_id=user_id,
                        notification_type="comment",
                        message=f"commented on your post",
                        post_id=post_id
                    )
                except TypeError as e:
                    logger.warning(f"create_notification doesn't support post_id yet, using old version: {e}")
                    # Fallback to old function signature
                    await create_notification(
                        recipient_id=post_owner_id,
                        sender_id=user_id,
                        notification_type="comment",
                        message=f"commented on your post"
                    )

                logger.debug(f"Sent comment notification to post owner")
            except Exception as e:
                logger.error(f"Error sending comment notification: {str(e)}")
                # Continue - don't fail comment creation due to notification errors

        # Get user profile for response
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq("id", user_id).single().execute()
            user_data = user_response.data
        except Exception as e:
            logger.error(f"Error fetching user profile: {str(e)}")
            user_data = {"id": user_id, "name": "Unknown User", "login": "unknown", "avatar_url": "", "tag_id": None}

        # Map user role
        def map_user_role(tag_id):
            role_map = {
                "146fb41a-2f3e-48c7-bef9-01de0279dfd7": "Listener",
                "b361c6f9-9425-4548-8c07-cb408140c304": "Musician",
                "5ee121a6-b467-4ead-b3f7-00e1ce6097d5": "Learner"
            }
            return role_map.get(tag_id, "Listener")

        logger.info(f"Comment creation completed successfully for post {post_id}")

        return {
            "message": "Comment created successfully",
            "comment": {
                "id": created_comment["id"],
                "text": created_comment["content"],
                "created_at": created_comment["created_at"],
                "mentions": list(mentioned_users.keys()),
                "user": {
                    "id": user_data["id"],
                    "name": user_data["name"],
                    "login": user_data["login"],
                    "avatar_url": user_data["avatar_url"] or "",
                    "role": map_user_role(user_data["tag_id"])
                }
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in create_comment: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create comment")


@router.post("/{post_id}/like")
async def toggle_like(
    post_id: str,
    current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Toggle like/unlike for a post"""
    try:
        # Validate post ID is UUID
        try:
            uuid.UUID(post_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid post ID format")

        user_id = current_user["id"]

        # Check if post exists
        try:
            post_response = supabase.table("posts").select("id").eq("id", post_id).single().execute()
            if not post_response.data:
                raise HTTPException(status_code=404, detail="Post not found")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                raise HTTPException(status_code=404, detail="Post not found")
            logger.error(f"Error verifying post existence: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to verify post")

        # Check if user already liked this post
        try:
            existing_like = supabase.table("post_likes").select("id").eq("post_id", post_id).eq("user_id", user_id).execute()

            if existing_like.data and len(existing_like.data) > 0:
                # Unlike - remove the like
                like_id = existing_like.data[0]["id"]
                supabase.table("post_likes").delete().eq("id", like_id).execute()

                # Decrement likes count
                try:
                    current_post = supabase.table("posts").select("likes_count").eq("id", post_id).single().execute()
                    current_count = current_post.data["likes_count"] or 0
                    new_count = max(0, current_count - 1)
                    supabase.table("posts").update({"likes_count": new_count}).eq("id", post_id).execute()
                except Exception as e:
                    logger.error(f"Error updating likes count after unlike: {str(e)}")
                    # Continue - the unlike operation succeeded

                logger.info(f"User {user_id} unliked post {post_id}")
                return {"message": "Post unliked", "liked": False}
            else:
                # Like - add the like
                like_data = {
                    "post_id": post_id,
                    "user_id": user_id,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                supabase.table("post_likes").insert(like_data).execute()

                # Increment likes count
                try:
                    current_post = supabase.table("posts").select("likes_count").eq("id", post_id).single().execute()
                    new_count = (current_post.data["likes_count"] or 0) + 1
                    supabase.table("posts").update({"likes_count": new_count}).eq("id", post_id).execute()
                except Exception as e:
                    logger.error(f"Error updating likes count after like: {str(e)}")
                    # Continue - the like operation succeeded

                logger.info(f"User {user_id} liked post {post_id}")
                return {"message": "Post liked", "liked": True}

        except Exception as e:
            logger.error(f"Error toggling like for post {post_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to toggle like")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in toggle_like: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to toggle like")


@router.get("/user/{user_id}")
async def get_user_posts(
        user_id: str,
        limit: int = Query(10, ge=1, le=50),
        offset: int = Query(0, ge=0),
        current_user: Optional[dict] = Depends(get_optional_user)
):
    """Get posts by a specific user with pagination - FIXED to include MusicXML and Lyrics"""
    try:
        # Validate user_id is a valid UUID
        try:
            uuid.UUID(user_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid user ID format")

        # Get posts for the user
        posts_response = supabase.table("posts").select("*").eq("user_id", user_id).order("created_at",
                                                                                          desc=True).range(offset,
                                                                                                           offset + limit - 1).execute()
        posts_data = posts_response.data or []

        if not posts_data:
            return []

        # Get all post IDs for batch queries
        post_ids = [post["id"] for post in posts_data]

        # FIXED: Batch fetch all related data for better performance
        try:
            # Get all media for these posts
            media_response = supabase.table("post_media").select("*").in_("post_id", post_ids).order(
                "order_index").execute()
            media_data = media_response.data or []

            # Get all audio for these posts
            audio_response = supabase.table("post_audio").select("*").in_("post_id", post_ids).order(
                "order_index").execute()
            audio_data = audio_response.data or []

            # FIXED: Get all musicxml for these posts
            musicxml_response = supabase.table("post_musicxml").select("*").in_("post_id", post_ids).order(
                "order_index").execute()
            musicxml_data = musicxml_response.data or []

            # FIXED: Get all lyrics for these posts
            lyrics_response = supabase.table("post_lyrics").select("*").in_("post_id", post_ids).execute()
            lyrics_data = lyrics_response.data or []

        except Exception as e:
            logger.error(f"Error fetching post related data: {str(e)}")
            media_data = []
            audio_data = []
            musicxml_data = []
            lyrics_data = []

        # Get user profiles for all posts (though they should be the same user)
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq("id",
                                                                                                             user_id).single().execute()
            user_data = user_response.data
        except Exception as e:
            logger.error(f"Error fetching user profile: {str(e)}")
            user_data = {"id": user_id, "name": "Unknown User", "login": "unknown", "avatar_url": "", "tag_id": None}

        # FIXED: Group related data by post_id for efficient lookup
        media_by_post = {}
        for media in media_data:
            post_id = media["post_id"]
            if post_id not in media_by_post:
                media_by_post[post_id] = []
            media_by_post[post_id].append(media)

        audio_by_post = {}
        for audio in audio_data:
            post_id = audio["post_id"]
            if post_id not in audio_by_post:
                audio_by_post[post_id] = []
            audio_by_post[post_id].append(audio)

        musicxml_by_post = {}
        for musicxml in musicxml_data:
            post_id = musicxml["post_id"]
            if post_id not in musicxml_by_post:
                musicxml_by_post[post_id] = []
            musicxml_by_post[post_id].append(musicxml)

        lyrics_by_post = {}
        for lyrics in lyrics_data:
            post_id = lyrics["post_id"]
            lyrics_by_post[post_id] = lyrics

        # Check user likes if authenticated
        user_likes = set()
        if current_user:
            try:
                likes_response = supabase.table("post_likes").select("post_id").eq("user_id", current_user["id"]).in_(
                    "post_id", post_ids).execute()
                user_likes = {like["post_id"] for like in likes_response.data or []}
            except Exception as e:
                logger.error(f"Error fetching user likes: {str(e)}")

        # FIXED: Build response with all post types including MusicXML and Lyrics
        result = []
        for post in posts_data:
            post_id = post["id"]

            response_post = {
                "id": post["id"],
                "type": post["type"],
                "caption": post.get("caption", ""),
                "created_at": post["created_at"],
                "likes_count": post.get("likes_count", 0),
                "comments_count": post.get("comments_count", 0),
                "user": user_data,
                "user_liked": post_id in user_likes,
                "media": [
                    {
                        "id": media["id"],
                        "file_url": media["file_url"],
                        "file_type": media["file_type"],
                        "file_name": media["file_name"],
                        "order_index": media["order_index"]
                    }
                    for media in media_by_post.get(post_id, [])
                ],
                "audio": [
                    {
                        "id": audio["id"],
                        "title": audio["title"],
                        "artist": audio["artist"],
                        "file_url": audio["file_url"],
                        "file_name": audio["file_name"],
                        "cover_url": audio["cover_url"],
                        "duration": audio["duration"],
                        "order_index": audio["order_index"]
                    }
                    for audio in audio_by_post.get(post_id, [])
                ],
                "musicxml": [
                    {
                        "id": musicxml["id"],
                        "title": musicxml["title"],
                        "composer": musicxml["composer"],
                        "file_url": musicxml["file_url"],
                        "file_name": musicxml["file_name"],
                        "order_index": musicxml["order_index"]
                    }
                    for musicxml in musicxml_by_post.get(post_id, [])
                ]
            }

            # FIXED: Add lyrics data if it exists for this post
            if post_id in lyrics_by_post:
                lyrics = lyrics_by_post[post_id]
                response_post["lyrics"] = {
                    "title": lyrics["title"],
                    "artist": lyrics["artist"],
                    "lyrics_text": lyrics["lyrics_text"],
                    "parts_data": lyrics.get("parts_data")
                }

            result.append(response_post)

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user posts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user posts")

@router.get("/{post_id}")
async def get_post(
    post_id: str,
    current_user: Optional[dict] = Depends(get_optional_user)
):
    """Get a specific post with its media, audio, musicxml, and lyrics - THIS MUST COME LAST"""
    try:
        # Validate that post_id is actually a UUID
        try:
            uuid.UUID(post_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid post ID format")

        # Get post data
        try:
            post_response = supabase.table("posts").select("*").eq("id", post_id).single().execute()
            post_data = post_response.data
            if not post_data:
                raise HTTPException(status_code=404, detail="Post not found")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                raise HTTPException(status_code=404, detail="Post not found")
            logger.error(f"Error fetching post: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to fetch post")

        # Get post media
        try:
            media_response = supabase.table("post_media").select("*").eq("post_id", post_id).order("order_index").execute()
            media_data = media_response.data or []
        except Exception as e:
            logger.error(f"Error fetching media: {str(e)}")
            media_data = []

        # Get post audio
        try:
            audio_response = supabase.table("post_audio").select("*").eq("post_id", post_id).order("order_index").execute()
            audio_data = audio_response.data or []
        except Exception as e:
            logger.error(f"Error fetching audio: {str(e)}")
            audio_data = []

        # Get post musicxml
        try:
            musicxml_response = supabase.table("post_musicxml").select("*").eq("post_id", post_id).order("order_index").execute()
            musicxml_data = musicxml_response.data or []
        except Exception as e:
            logger.error(f"Error fetching musicxml: {str(e)}")
            musicxml_data = []

        # FIXED: Get post lyrics (this was missing!)
        try:
            lyrics_response = supabase.table("post_lyrics").select("*").eq("post_id", post_id).execute()
            lyrics_data = lyrics_response.data[0] if lyrics_response.data else None
        except Exception as e:
            logger.error(f"Error fetching lyrics: {str(e)}")
            lyrics_data = None

        # Get user profile
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq(
                "id", post_data["user_id"]).single().execute()
            user_data = user_response.data
        except Exception as e:
            logger.error(f"Error fetching user profile: {str(e)}")
            user_data = {"id": post_data["user_id"], "name": "Unknown User", "login": "unknown",
                         "avatar_url": "", "tag_id": None}

        # Check if current user liked this post
        user_liked = False
        if current_user:
            try:
                like_response = supabase.table("post_likes").select("id").eq("post_id", post_id).eq("user_id",
                                                                                                    current_user["id"]).execute()
                user_liked = like_response.data and len(like_response.data) > 0
            except Exception as e:
                logger.error(f"Error checking user likes: {str(e)}")

        # FIXED: Format response with all data types including lyrics and musicxml
        response_data = {
            "id": post_data["id"],
            "type": post_data["type"],
            "caption": post_data.get("caption", ""),
            "created_at": post_data["created_at"],
            "likes_count": post_data.get("likes_count", 0),
            "comments_count": post_data.get("comments_count", 0),
            "user": user_data,
            "user_liked": user_liked,
            "media": [
                {
                    "id": media["id"],
                    "file_url": media["file_url"],
                    "file_type": media["file_type"],
                    "file_name": media["file_name"],
                    "order_index": media["order_index"]
                }
                for media in media_data
            ],
            "audio": [
                {
                    "id": audio["id"],
                    "title": audio["title"],
                    "artist": audio["artist"],
                    "file_url": audio["file_url"],
                    "file_name": audio["file_name"],
                    "cover_url": audio["cover_url"],
                    "duration": audio["duration"],
                    "order_index": audio["order_index"]
                }
                for audio in audio_data
            ],
            "musicxml": [
                {
                    "id": musicxml["id"],
                    "title": musicxml["title"],
                    "composer": musicxml["composer"],
                    "file_url": musicxml["file_url"],
                    "file_name": musicxml["file_name"],
                    "order_index": musicxml["order_index"]
                }
                for musicxml in musicxml_data
            ]
        }

        # FIXED: Add lyrics data if it exists
        if lyrics_data:
            response_data["lyrics"] = {
                "title": lyrics_data["title"],
                "artist": lyrics_data["artist"],
                "lyrics_text": lyrics_data["lyrics_text"],
                "parts_data": lyrics_data.get("parts_data")
            }

        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching post: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch post")

# ADD THIS TO YOUR post_router.py (after your audio endpoint)

@router.post("/musicxml")
async def create_musicxml_post(
    current_user: Annotated[dict, Depends(get_verified_user)],
    musicxml_files: List[UploadFile] = File(...),
    titles: List[str] = Form(...),
    composers: List[str] = Form(...),
    caption: Optional[str] = Form(None)
):
    """Create a new MusicXML post with uploaded XML files"""

    if not musicxml_files or len(musicxml_files) == 0:
        raise HTTPException(status_code=400, detail="At least one MusicXML file is required")

    if len(musicxml_files) > 5:  # Limit number of MusicXML files
        raise HTTPException(status_code=400, detail="Maximum 5 MusicXML files allowed per post")

    if len(titles) != len(musicxml_files) or len(composers) != len(musicxml_files):
        raise HTTPException(status_code=400, detail="Each MusicXML file must have a title and composer")

    # Allowed MusicXML file types and extensions
    ALLOWED_XML_TYPES = {
        "application/xml", "text/xml", "application/musicxml",
        "application/vnd.recordare.musicxml", "application/vnd.recordare.musicxml+xml"
    }
    ALLOWED_XML_EXTENSIONS = {".xml", ".musicxml", ".mxl"}

    try:
        user_id = current_user["id"]

        # Validate all MusicXML files first
        validated_xml_files = []
        total_size = 0

        for i, file in enumerate(musicxml_files):
            if not file.filename:
                raise HTTPException(status_code=400, detail="All MusicXML files must have filenames")

            # Check file extension (more reliable than MIME type for XML files)
            file_extension = os.path.splitext(file.filename.lower())[1]
            if file_extension not in ALLOWED_XML_EXTENSIONS:
                # Also check MIME type as fallback
                if file.content_type not in ALLOWED_XML_TYPES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File {file.filename} is not a valid MusicXML file. Allowed extensions: .xml, .musicxml, .mxl"
                    )

            # Read file content to get actual size
            file_content = await file.read()
            actual_size = len(file_content)

            # MusicXML files are usually small, but set a reasonable limit (10MB)
            if actual_size > 10 * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail=f"MusicXML file {file.filename} exceeds size limit of 10MB"
                )

            total_size += actual_size
            # Reset file position for later use
            await file.seek(0)

            validated_xml_files.append((file, actual_size, titles[i], composers[i]))

        # Check total size limit (50MB for all files combined)
        if total_size > 50 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Total MusicXML file size exceeds 50MB limit")

        # Create post record
        post_data = {
            "user_id": user_id,
            "type": "musicxml",
            "caption": caption or "",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            post_response = supabase.table("posts").insert(post_data).execute()
            post_id = post_response.data[0]["id"]
            print(f"Created MusicXML post with ID: {post_id}")
        except Exception as e:
            print(f"Error creating MusicXML post: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create MusicXML post")

        # Upload MusicXML files and create records
        xml_records = []
        uploaded_files = []

        for index, (file, file_size, title, composer) in enumerate(validated_xml_files):
            try:
                # Generate unique filename
                file_extension = os.path.splitext(file.filename)[1]
                unique_filename = f"{post_id}_{index}_{uuid.uuid4().hex[:8]}{file_extension}"
                file_path = f"posts/{user_id}/musicxml/{unique_filename}"

                # Upload MusicXML file to storage (reuse audio upload function)
                public_url = await upload_audio_to_storage(file, file_path)

                # Create MusicXML record
                xml_data = {
                    "post_id": post_id,
                    "title": title.strip(),
                    "composer": composer.strip(),
                    "file_url": public_url,
                    "file_name": file.filename,
                    "file_size": file_size,
                    "order_index": index
                }

                xml_records.append(xml_data)
                uploaded_files.append(file_path)

            except Exception as e:
                print(f"Error uploading MusicXML file {file.filename}: {str(e)}")
                # Clean up any already uploaded files
                for uploaded_file_path in uploaded_files:
                    try:
                        supabase.storage.from_(AUDIO_STORAGE_BUCKET).remove([uploaded_file_path])
                    except:
                        pass
                raise HTTPException(status_code=500, detail=f"Failed to upload {file.filename}")

        # Insert all MusicXML records
        if xml_records:
            try:
                xml_response = supabase.table("post_musicxml").insert(xml_records).execute()
            except Exception as e:
                print(f"Error creating MusicXML records: {str(e)}")
                # Clean up uploaded files
                for uploaded_file_path in uploaded_files:
                    try:
                        supabase.storage.from_(AUDIO_STORAGE_BUCKET).remove([uploaded_file_path])
                    except:
                        pass
                raise HTTPException(status_code=500, detail="Failed to create MusicXML records")

        print(f"Successfully created MusicXML post with {len(xml_records)} files")

        # Get user profile for complete response
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq("id", user_id).single().execute()
            user_data = user_response.data
        except Exception as e:
            print(f"Error fetching user profile: {str(e)}")
            user_data = {"id": user_id, "name": "Unknown User", "login": "unknown", "avatar_url": "", "tag_id": None}

        # Return complete post data for immediate display
        return {
            "message": "MusicXML post created successfully",
            "post_id": post_id,
            "post": {
                "id": post_id,
                "type": "musicxml",
                "caption": caption or "",
                "created_at": post_data["created_at"],
                "likes_count": 0,
                "comments_count": 0,
                "user": user_data,
                "user_liked": False,
                "musicxml": [
                    {
                        "id": None,  # MusicXML IDs aren't returned from insert
                        "title": xml["title"],
                        "composer": xml["composer"],
                        "file_url": xml["file_url"],
                        "file_name": xml["file_name"],
                        "order_index": xml["order_index"]
                    }
                    for xml in xml_records
                ]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error creating MusicXML post: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create MusicXML post")


from pydantic import BaseModel
from typing import List


# Pydantic models for lyrics
class LyricsPart(BaseModel):
    type: str  # intro, verse, pre-chorus, chorus, bridge, outro
    lyrics: str


class LyricsRequest(BaseModel):
    songTitle: str
    artistName: str
    parts: List[LyricsPart]
    caption: Optional[str] = None


@router.post("/lyrics")
async def create_lyrics_post(
        current_user: Annotated[dict, Depends(get_verified_user)],
        lyrics_data: LyricsRequest
):
    """Create a new lyrics post"""

    if not lyrics_data.songTitle.strip():
        raise HTTPException(status_code=400, detail="Song title is required")

    if not lyrics_data.artistName.strip():
        raise HTTPException(status_code=400, detail="Artist name is required")

    if not lyrics_data.parts or len(lyrics_data.parts) == 0:
        raise HTTPException(status_code=400, detail="At least one lyrics part is required")

    if len(lyrics_data.parts) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 lyrics parts allowed")

    # Validate each part
    for i, part in enumerate(lyrics_data.parts):
        if not part.type.strip():
            raise HTTPException(status_code=400, detail=f"Part {i + 1} type is required")
        if not part.lyrics.strip():
            raise HTTPException(status_code=400, detail=f"Part {i + 1} lyrics text is required")

        # Validate part type
        allowed_types = ["intro", "verse", "pre-chorus", "chorus", "bridge", "outro"]
        if part.type not in allowed_types:
            raise HTTPException(status_code=400,
                                detail=f"Invalid part type: {part.type}. Allowed: {', '.join(allowed_types)}")

    try:
        user_id = current_user["id"]

        # Combine all lyrics parts into a single text
        full_lyrics = []
        for part in lyrics_data.parts:
            # Format: [PART_TYPE]\nlyrics\n
            part_header = f"[{part.type.upper()}]"
            full_lyrics.append(f"{part_header}\n{part.lyrics.strip()}")

        combined_lyrics = "\n\n".join(full_lyrics)

        # Create post record
        post_data = {
            "user_id": user_id,
            "type": "lyrics",
            "caption": lyrics_data.caption or "",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            post_response = supabase.table("posts").insert(post_data).execute()
            post_id = post_response.data[0]["id"]
            print(f"Created lyrics post with ID: {post_id}")
        except Exception as e:
            print(f"Error creating lyrics post: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create lyrics post")

        # Create lyrics record
        lyrics_record = {
            "post_id": post_id,
            "title": lyrics_data.songTitle.strip(),
            "artist": lyrics_data.artistName.strip(),
            "lyrics_text": combined_lyrics,
            "parts_data": [
                {
                    "type": part.type,
                    "lyrics": part.lyrics.strip(),
                    "order": i
                }
                for i, part in enumerate(lyrics_data.parts)
            ]  # Store structured parts as JSON
        }

        try:
            lyrics_response = supabase.table("post_lyrics").insert(lyrics_record).execute()
        except Exception as e:
            print(f"Error creating lyrics record: {str(e)}")
            # Clean up the post if lyrics creation failed
            try:
                supabase.table("posts").delete().eq("id", post_id).execute()
            except:
                pass
            raise HTTPException(status_code=500, detail="Failed to create lyrics record")

        print(f"Successfully created lyrics post: {lyrics_data.songTitle} by {lyrics_data.artistName}")

        # Get user profile for complete response
        try:
            user_response = supabase.table("user_profiles").select("id, name, login, avatar_url, tag_id").eq("id",
                                                                                                             user_id).single().execute()
            user_data = user_response.data
        except Exception as e:
            print(f"Error fetching user profile: {str(e)}")
            user_data = {"id": user_id, "name": "Unknown User", "login": "unknown", "avatar_url": "", "tag_id": None}

        # Return complete post data for immediate display
        return {
            "message": "Lyrics post created successfully",
            "post_id": post_id,
            "post": {
                "id": post_id,
                "type": "lyrics",
                "caption": lyrics_data.caption or "",
                "created_at": post_data["created_at"],
                "likes_count": 0,
                "comments_count": 0,
                "user": user_data,
                "user_liked": False,
                "lyrics": {
                    "title": lyrics_record["title"],
                    "artist": lyrics_record["artist"],
                    "lyrics_text": lyrics_record["lyrics_text"],
                    "parts_data": lyrics_record["parts_data"]
                }
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error creating lyrics post: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create lyrics post")


# Add these functions to your post_router.py

import re
from routes.notifications_router import create_notification  # Import the notification function


# Add this helper function to extract mentions from text
def extract_mentions(text: str) -> list[str]:
    """Extract @mentions from text"""
    mentions = re.findall(r'@(\w+)', text)
    print(f"🔍 DEBUG - extract_mentions found: {mentions}")
    return list(set(mentions))


# Add this function to resolve usernames to user IDs
async def resolve_usernames_to_ids(usernames: list[str]) -> dict[str, str]:
    """Convert list of usernames to dictionary of username -> user_id"""
    if not usernames:
        return {}

    try:
        users_response = (
            supabase.table("user_profiles")
            .select("id, login")
            .in_("login", usernames)
            .execute()
        )

        users_data = users_response.data or []
        return {user["login"]: user["id"] for user in users_data}
    except Exception as e:
        print(f"Error resolving usernames: {str(e)}")
        return {}




# Add an endpoint to search users for tagging autocomplete
@router.get("/users/search")
async def search_users_for_mention(
        q: str,
        limit: int = 10,
        current_user: Optional[dict] = Depends(get_optional_user)
):
    """Search users by login/name for mention autocomplete"""
    try:
        if not q or len(q.strip()) < 2:
            return []

        search_term = q.strip().lower()

        # Search users by login and name
        try:
            users_response = (
                supabase.table("user_profiles")
                .select("id, name, login, avatar_url")
                .or_(f"login.ilike.%{search_term}%,name.ilike.%{search_term}%")
                .limit(limit)
                .execute()
            )
            users_data = users_response.data or []
        except Exception as e:
            print(f"Error searching users: {str(e)}")
            return []

        # Format response for frontend
        formatted_users = []
        for user in users_data:
            formatted_users.append({
                "id": user["id"],
                "login": user["login"],
                "name": user["name"],
                "avatar_url": user["avatar_url"] or ""
            })

        return formatted_users

    except Exception as e:
        print(f"Error in search_users_for_mention: {str(e)}")
        return []
