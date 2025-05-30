from fastapi import APIRouter, Query, HTTPException, Depends, Request
from typing import Annotated, Union, Optional
from routes.dependencies import get_verified_user
from supabase_client import supabase
from jwt_handler import decode_jwt
# FIXED: Correct import path (remove the extra 'r' from notifications_routerr)
from routes.notifications_router import create_notification

router = APIRouter(
    prefix="/profiles",
    tags=["profiles"]
)


async def get_optional_user(request: Request):
    token = None
    auth_header = request.headers.get("Authorization")

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        print(f"[get_optional_user] Access token from Authorization header: {token[:50]}...")
    else:
        token = request.cookies.get("access_token")
        print(f"[get_optional_user] Access token from cookies: {token[:50] if token else None}...")

    if not token:
        print("[get_optional_user] No token found, returning None")
        return None

    try:
        payload = decode_jwt(token)
        print(f"[get_optional_user] Decoded JWT payload: {payload}")

        user_sub = payload.get("sub")
        user_email = payload.get("email")

        if not user_sub and not user_email:
            print("[get_optional_user] Token missing user identifiers (sub/email)")
            return None

        user_resp = None

        # Try to fetch by sub
        if user_sub:
            try:
                user_resp = supabase.table("users").select("*").eq("sub", user_sub).single().execute()
                print(f"[get_optional_user] Supabase response (by sub): {getattr(user_resp, 'data', None)}")
            except Exception as e:
                print(f"[get_optional_user] Error fetching by sub: {e}")
                user_resp = None

        # Fallback to email if sub fails
        if (user_resp is None or user_resp.data is None) and user_email:
            try:
                user_resp = supabase.table("users").select("*").eq("email", user_email).single().execute()
                print(f"[get_optional_user] Supabase response (by email): {getattr(user_resp, 'data', None)}")
            except Exception as e:
                print(f"[get_optional_user] Error fetching by email: {e}")
                user_resp = None

        if user_resp is None or user_resp.data is None:
            print("[get_optional_user] No user found, returning None")
            return None

        user_data = user_resp.data
        provider = user_data.get("provider", "email")
        is_verified = user_data.get("verified", False)

        if provider == "email" and not is_verified:
            print("[get_optional_user] Email user not verified, returning None")
            return None

        print(f"[get_optional_user] Returning authenticated user: {user_data.get('email')}")

        return {
            "id": user_data.get("id"),
            "sub": user_data.get("sub"),
            "email": user_data.get("email"),
            "name": user_data.get("name", ""),
            "verified": is_verified,
            "provider": provider,
            "email_confirmed": is_verified or provider != "email"
        }

    except Exception as e:
        print(f"[get_optional_user] Token error or unknown exception: {str(e)}")
        return None


@router.get("/search")
def search_profiles(
        user: Annotated[Optional[dict], Depends(get_optional_user)],
        query: Union[str, None] = Query(None, min_length=1, description="Search term for name or login"),
        limit: int = Query(10, ge=1, le=100),
        offset: int = Query(0, ge=0),
):
    try:
        current_user_id = user["id"] if user else None
        print(f"Search query: '{query}', current user id: {current_user_id}")

        base_query = supabase.table("user_profiles").select("*")

        if current_user_id:
            base_query = base_query.neq("id", current_user_id)

        if query:
            # Виправлено формат запиту
            base_query = base_query.or_(f"name.ilike.%{query}%,login.ilike.%{query}%")

        response = base_query.range(offset, offset + limit - 1).execute()

        if getattr(response, "error", None):
            raise HTTPException(status_code=400, detail="Error during search query")

        return response.data or []

    except Exception as e:
        print("Error in /profiles/search:", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/listening/{listened_id}")
async def listen_to_user(
        listened_id: str,
        user: Annotated[dict, Depends(get_verified_user)]
):
    listener_id = user["id"]

    if listener_id == listened_id:
        return {"message": "Cannot listen to yourself, no action taken."}

    try:
        print(f"Trying to listen: {listener_id} -> {listened_id}")

        # Check if either user has blocked the other (fixed query)
        # Check if listener blocked the target user
        block_check1 = (
            supabase.table("blocked_users")
            .select("*")
            .eq("blocker_id", listener_id)
            .eq("blocked_id", listened_id)
            .execute()
        )

        # Check if target user blocked the listener
        block_check2 = (
            supabase.table("blocked_users")
            .select("*")
            .eq("blocker_id", listened_id)
            .eq("blocked_id", listener_id)
            .execute()
        )

        if (getattr(block_check1, "error", None) is not None or
            getattr(block_check2, "error", None) is not None):
            print("Error checking block status")
            raise HTTPException(status_code=400, detail="Error checking block status")

        # If either query returned results, there's a block relationship
        if ((block_check1.data and len(block_check1.data) > 0) or
            (block_check2.data and len(block_check2.data) > 0)):
            raise HTTPException(status_code=403, detail="Cannot listen to a blocked user or a user who has blocked you")

        # Check if already listening
        existing = (
            supabase.table("listened_users")
            .select("*")
            .eq("listener_id", listener_id)
            .eq("listened_id", listened_id)
            .execute()
        )

        if getattr(existing, "error", None) is not None:
            print("Error checking existing listen:", existing.error)
            raise HTTPException(status_code=400, detail="Error checking existing listening record")

        if existing.data and len(existing.data) > 0:
            return {"message": "Already listening to this user."}

        # Insert listening record
        insert_resp = (
            supabase.table("listened_users")
            .insert({
                "listener_id": listener_id,
                "listened_id": listened_id
            })
            .execute()
        )

        if getattr(insert_resp, "error", None) is not None:
            print("Insert error:", insert_resp.error)
            raise HTTPException(status_code=400, detail="Error inserting listening record")

        # Create notification for the listened user
        try:
            await create_notification(
                recipient_id=listened_id,
                sender_id=listener_id,
                notification_type="listening",
                message="now listens you"
            )
            print(f"Created notification: {listener_id} started listening to {listened_id}")
        except Exception as e:
            print(f"Warning: Could not create notification: {e}")
            # Don't fail the listening operation if notification fails

        return {"message": "User listened."}

    except HTTPException:
        raise
    except Exception as e:
        print("Unexpected error:", repr(e))
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")


@router.delete("/listening/{listened_id}")
async def unlisten_to_user(
        listened_id: str,
        user: Annotated[dict, Depends(get_verified_user)]
):
    listener_id = user["id"]

    if listener_id == listened_id:
        return {"message": "Cannot unlisten yourself, no action taken."}

    try:
        delete_resp = (
            supabase.table("listened_users")
            .delete()
            .eq("listener_id", listener_id)
            .eq("listened_id", listened_id)
            .execute()
        )

        if getattr(delete_resp, "error", None) is not None:
            print("Delete error:", delete_resp.error)
            raise HTTPException(status_code=400, detail="Error deleting listening record")

        return {"message": "User unlistened."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error unlistening user: {str(e)}")


@router.get("/listened")
async def get_listened_users(
        user: Annotated[dict, Depends(get_verified_user)]
):
    try:
        listened = (
            supabase.table("listened_users")
            .select("listened_id")
            .eq("listener_id", user["id"])
            .execute()
        )

        if getattr(listened, "error", None) is not None or listened.data is None:
            raise HTTPException(status_code=400, detail="Error fetching listened users")

        listened_ids = [entry["listened_id"] for entry in listened.data]

        if not listened_ids:
            return []

        profiles = (
            supabase.table("user_profiles")
            .select("*")
            .in_("id", listened_ids)
            .execute()
        )

        if getattr(profiles, "error", None) is not None or profiles.data is None:
            raise HTTPException(status_code=400, detail="Error fetching profiles")

        return profiles.data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching listened users: {str(e)}")


@router.get("/{user_id}")
async def get_user_profile_by_id(
        user_id: str,
        user: Annotated[Optional[dict], Depends(get_optional_user)]  # Made optional for guest access
):
    try:
        print(f"Fetching profile for user_id: {user_id}")

        response = supabase.table("user_profiles").select("*").eq("id", user_id).single().execute()

        if getattr(response, "error", None) is not None or response.data is None:
            print(f"User not found: {user_id}")
            raise HTTPException(status_code=404, detail="User not found")

        profile_data = response.data
        print(f"Found profile: {profile_data}")

        return {
            "id": profile_data.get("id"),
            "name": profile_data.get("name", ""),
            "login": profile_data.get("login", ""),
            "avatar_url": profile_data.get("avatar_url", ""),
            "description": profile_data.get("description", ""),
            "tag_id": profile_data.get("tag_id")  # Return UUID for frontend mapping
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching user profile: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching user profile: {str(e)}")


@router.get("/{user_id}/stats")
async def get_user_stats(
        user_id: str,
        user: Annotated[Optional[dict], Depends(get_optional_user)]  # Made optional for guest access
):
    try:
        print(f"Fetching stats for user_id: {user_id}")

        # Get posts count
        try:
            posts_resp = supabase.table("posts").select("id", count="exact").eq("user_id", user_id).execute()
            print(f"Posts query response: {getattr(posts_resp, 'data', None)}")
            print(f"Posts count: {getattr(posts_resp, 'count', None)}")

            if getattr(posts_resp, "error", None) is not None:
                print(f"Error fetching posts count: {posts_resp.error}")
                posts_count = 0  # Fallback to 0 instead of throwing error
            else:
                posts_count = posts_resp.count or 0
        except Exception as e:
            print(f"Exception in posts query: {str(e)}")
            posts_count = 0

        # Get listeners count (people following this user)
        try:
            listeners_resp = supabase.table("listened_users").select("listener_id", count="exact").eq("listened_id",
                                                                                                      user_id).execute()
            print(f"Listeners query response: {getattr(listeners_resp, 'data', None)}")
            print(f"Listeners count: {getattr(listeners_resp, 'count', None)}")

            if getattr(listeners_resp, "error", None) is not None:
                print(f"Error fetching listeners count: {listeners_resp.error}")
                listeners_count = 0  # Fallback to 0 instead of throwing error
            else:
                listeners_count = listeners_resp.count or 0
        except Exception as e:
            print(f"Exception in listeners query: {str(e)}")
            listeners_count = 0

        # Get listenedTo count (people this user follows)
        try:
            listened_resp = supabase.table("listened_users").select("listened_id", count="exact").eq("listener_id",
                                                                                                     user_id).execute()
            print(f"ListenedTo query response: {getattr(listened_resp, 'data', None)}")
            print(f"ListenedTo count: {getattr(listened_resp, 'count', None)}")

            if getattr(listened_resp, "error", None) is not None:
                print(f"Error fetching listened count: {listened_resp.error}")
                listened_count = 0  # Fallback to 0 instead of throwing error
            else:
                listened_count = listened_resp.count or 0
        except Exception as e:
            print(f"Exception in listened query: {str(e)}")
            listened_count = 0

        stats_data = {
            "posts": posts_count,
            "listeners": listeners_count,
            "listenedTo": listened_count
        }

        print(f"Final user stats: {stats_data}")
        return stats_data

    except Exception as e:
        print(f"Unexpected error in get_user_stats: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

        # Return zeros instead of throwing error
        return {
            "posts": 0,
            "listeners": 0,
            "listenedTo": 0
        }


@router.get("/{user_id}/posts")
async def get_user_posts_stats(
        user_id: str,
        user: Annotated[dict, Depends(get_verified_user)]
):
    try:
        posts_resp = supabase.table("posts").select("id", count="exact").eq("user_id", user_id).execute()
        if getattr(posts_resp, "error", None) is not None:
            raise HTTPException(status_code=400, detail="Error fetching posts count")

        total_posts = posts_resp.count or 0

        listeners_resp = supabase.table("listened_users").select("listener_id", count="exact").eq("listened_id",
                                                                                                  user_id).execute()
        if getattr(listeners_resp, "error", None) is not None:
            raise HTTPException(status_code=400, detail="Error fetching listeners count")

        total_listeners = listeners_resp.count or 0

        listened_resp = supabase.table("listened_users").select("listened_id", count="exact").eq("listener_id",
                                                                                                 user_id).execute()
        if getattr(listened_resp, "error", None) is not None:
            raise HTTPException(status_code=400, detail="Error fetching listened count")

        total_listened = listened_resp.count or 0

        return {
            "total_posts": total_posts,
            "total_listeners": total_listeners,
            "total_listened": total_listened
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user stats: {str(e)}")