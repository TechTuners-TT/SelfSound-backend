from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from uuid import UUID
from routes.profile_routes.profile_router import supabase
from routes.dependencies import get_verified_user

router = APIRouter(prefix="/profiles/blocks", tags=["Blocked"])


@router.post("/{user_id}")
async def block_user(
        user_id: str,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Block a user"""
    blocker_id = current_user["id"]

    if blocker_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot block yourself")

    try:
        print(f"Trying to block: {blocker_id} -> {user_id}")

        # Check if user exists
        try:
            user_check = supabase.table("user_profiles").select("id").eq("id", user_id).single().execute()
            if getattr(user_check, "error", None) is not None or user_check.data is None:
                print(f"User not found in user_profiles: {user_id}")
                raise HTTPException(status_code=404, detail="User not found")
        except Exception as e:
            print(f"Error checking if user exists: {e}")
            raise HTTPException(status_code=404, detail="User not found")

        # Check if already blocked
        try:
            existing = (
                supabase.table("blocked_users")
                .select("*")
                .eq("blocker_id", blocker_id)
                .eq("blocked_id", user_id)
                .execute()
            )

            if getattr(existing, "error", None) is not None:
                print("Error checking existing block:", existing.error)
                raise HTTPException(status_code=400, detail="Error checking existing block record")

            if existing.data and len(existing.data) > 0:
                return {"message": "User is already blocked."}
        except HTTPException:
            raise
        except Exception as e:
            print(f"Error checking existing block: {e}")
            raise HTTPException(status_code=400, detail="Error checking existing block record")

        # Insert block record
        try:
            insert_resp = (
                supabase.table("blocked_users")
                .insert({
                    "blocker_id": blocker_id,
                    "blocked_id": user_id
                })
                .execute()
            )

            if getattr(insert_resp, "error", None) is not None:
                print("Insert error:", insert_resp.error)
                error_obj = getattr(insert_resp, "error", {})
                error_message = "Unknown database error"

                if hasattr(error_obj, 'message'):
                    error_message = str(error_obj.message)
                elif isinstance(error_obj, dict) and 'message' in error_obj:
                    error_message = str(error_obj['message'])
                else:
                    error_message = str(error_obj)

                if 'foreign key constraint' in error_message.lower():
                    raise HTTPException(status_code=400, detail="Invalid user ID - user not found in database")
                else:
                    raise HTTPException(status_code=400, detail=f"Error inserting block record: {error_message}")
        except HTTPException:
            raise
        except Exception as e:
            print(f"Error inserting block record: {e}")
            raise HTTPException(status_code=400, detail="Error inserting block record")

        # Also remove any existing listening relationships in both directions
        try:
            print("Removing listening relationships...")

            # Remove if blocker was listening to blocked user
            unlisten_resp1 = supabase.table("listened_users").delete().eq("listener_id", blocker_id).eq("listened_id",
                                                                                                        user_id).execute()
            print(f"Removed listening relationship (blocker->blocked): {getattr(unlisten_resp1, 'data', None)}")

            if getattr(unlisten_resp1, "error", None) is not None:
                print(f"Warning: Error removing blocker->blocked relationship: {unlisten_resp1.error}")

            # Remove if blocked user was listening to blocker
            unlisten_resp2 = supabase.table("listened_users").delete().eq("listener_id", user_id).eq("listened_id",
                                                                                                     blocker_id).execute()
            print(f"Removed listening relationship (blocked->blocker): {getattr(unlisten_resp2, 'data', None)}")

            if getattr(unlisten_resp2, "error", None) is not None:
                print(f"Warning: Error removing blocked->blocker relationship: {unlisten_resp2.error}")

        except Exception as e:
            print(f"Warning: Error removing listening relationships: {e}")
            # Don't fail the block operation if this fails

        return {"message": "User blocked successfully."}

    except HTTPException:
        raise
    except Exception as e:
        print("Unexpected error:", repr(e))
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")


@router.delete("/{user_id}")
async def unblock_user(
        user_id: str,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Unblock a user"""
    blocker_id = current_user["id"]

    if blocker_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot unblock yourself")

    try:
        delete_resp = (
            supabase.table("blocked_users")
            .delete()
            .eq("blocker_id", blocker_id)
            .eq("blocked_id", user_id)
            .execute()
        )

        if getattr(delete_resp, "error", None) is not None:
            print("Delete error:", delete_resp.error)
            raise HTTPException(status_code=400, detail="Error deleting block record")

        return {"message": "User unblocked successfully."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error unblocking user: {str(e)}")


@router.get("/check/{user_id}")
async def check_if_blocked(
        user_id: str,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Check if current user has blocked the specified user"""
    blocker_id = current_user["id"]

    try:
        existing = (
            supabase.table("blocked_users")
            .select("*")
            .eq("blocker_id", blocker_id)
            .eq("blocked_id", user_id)
            .execute()
        )

        if getattr(existing, "error", None) is not None:
            print("Error checking block status:", existing.error)
            raise HTTPException(status_code=400, detail="Error checking block status")

        # Fix: Check if data exists and has length > 0, then convert to boolean
        is_blocked = bool(existing.data and len(existing.data) > 0)

        print(f"Block check - blocker: {blocker_id}, blocked: {user_id}, result: {is_blocked}")
        print(f"Query result data: {existing.data}")

        return {"is_blocked": is_blocked}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error checking block status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error checking block status: {str(e)}")


@router.get("")
async def get_blocked_users(
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Get all users blocked by the current user"""
    try:
        blocked = (
            supabase.table("blocked_users")
            .select("blocked_id")
            .eq("blocker_id", current_user["id"])
            .execute()
        )

        if getattr(blocked, "error", None) is not None or blocked.data is None:
            raise HTTPException(status_code=400, detail="Error fetching blocked users")

        blocked_ids = [entry["blocked_id"] for entry in blocked.data]

        if not blocked_ids:
            return []

        # Get profile information for blocked users
        profiles = (
            supabase.table("user_profiles")
            .select("*")
            .in_("id", blocked_ids)
            .execute()
        )

        if getattr(profiles, "error", None) is not None or profiles.data is None:
            raise HTTPException(status_code=400, detail="Error fetching blocked user profiles")

        return profiles.data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching blocked users: {str(e)}")