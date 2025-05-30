from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated, Optional
from datetime import datetime, timezone
from routes.dependencies import get_verified_user
from routes.profile_routes.profile_router import supabase

router = APIRouter(prefix="/notifications", tags=["Notifications"])


# Add this to your notifications_router.py - UPDATE the create_notification function:

async def create_notification(
        recipient_id: str,
        sender_id: str,
        notification_type: str,
        message: str,
        post_id: str = None  # ADD THIS PARAMETER
):
    """Helper function to create a notification"""
    try:
        # Check if recipient and sender are different
        if recipient_id == sender_id:
            return

        # Check if users are blocked (don't send notifications to/from blocked users)
        block_check1 = (
            supabase.table("blocked_users")
            .select("id")
            .eq("blocker_id", recipient_id)
            .eq("blocked_id", sender_id)
            .execute()
        )

        block_check2 = (
            supabase.table("blocked_users")
            .select("id")
            .eq("blocker_id", sender_id)
            .eq("blocked_id", recipient_id)
            .execute()
        )

        # If either user has blocked the other, don't create notification
        if ((block_check1.data and len(block_check1.data) > 0) or
                (block_check2.data and len(block_check2.data) > 0)):
            print(f"Not creating notification - users are blocked")
            return

        # Create the notification with post_id
        notification_data = {
            "recipient_id": recipient_id,
            "sender_id": sender_id,
            "type": notification_type,
            "message": message,
            "read": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        # Add post_id if provided
        if post_id:
            notification_data["post_id"] = post_id

        insert_resp = (
            supabase.table("notifications")
            .insert(notification_data)
            .execute()
        )

        if getattr(insert_resp, "error", None) is not None:
            print("Error creating notification:", insert_resp.error)
        else:
            print(f"Created notification: {notification_type} from {sender_id} to {recipient_id} for post {post_id}")

    except Exception as e:
        print(f"Error creating notification: {str(e)}")
        # Don't raise exception - notifications are not critical

@router.get("")
async def get_notifications(
        current_user: Annotated[dict, Depends(get_verified_user)],
        limit: int = 50,
        offset: int = 0
):
    """Get notifications for the current user"""
    try:
        user_id = current_user["id"]
        print(f"Fetching notifications for user: {user_id}")

        # Get notifications first
        notifications_resp = (
            supabase.table("notifications")
            .select("*")
            .eq("recipient_id", user_id)
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        if getattr(notifications_resp, "error", None) is not None:
            print("Error fetching notifications:", notifications_resp.error)
            raise HTTPException(status_code=400, detail="Error fetching notifications")

        notifications = notifications_resp.data or []

        if not notifications:
            return []

        # Get sender IDs
        sender_ids = [notif["sender_id"] for notif in notifications]

        # Fetch user profiles separately
        profiles_resp = (
            supabase.table("user_profiles")
            .select("id, name, login, avatar_url")
            .in_("id", sender_ids)
            .execute()
        )

        if getattr(profiles_resp, "error", None) is not None:
            print("Error fetching user profiles:", profiles_resp.error)
            # Continue without profiles - use fallback data
            profiles_data = []
        else:
            profiles_data = profiles_resp.data or []

        # Create a lookup dictionary for profiles
        profiles_lookup = {profile["id"]: profile for profile in profiles_data}

        # Transform notifications to match frontend format
        transformed_notifications = []
        for notif in notifications:
            sender_profile = profiles_lookup.get(notif["sender_id"], {})
            transformed_notifications.append({
                "id": notif["id"],
                "name": sender_profile.get("name", "Unknown User"),
                "username": sender_profile.get("login", "unknown"),
                "message": notif["message"],
                "timestamp": notif["created_at"],
                "type": notif["type"],
                "read": notif["read"],
                "sender_id": notif["sender_id"],
                "post_id": notif.get("post_id")  # ADD THIS LINE
            })
        print(f"Returning {len(transformed_notifications)} notifications")
        return transformed_notifications

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching notifications: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching notifications")


@router.patch("/{notification_id}/read")
async def mark_notification_read(
        notification_id: str,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Mark a notification as read"""
    try:
        user_id = current_user["id"]

        # Update notification to mark as read
        update_resp = (
            supabase.table("notifications")
            .update({"read": True})
            .eq("id", notification_id)
            .eq("recipient_id", user_id)  # Ensure user can only mark their own notifications
            .execute()
        )

        if getattr(update_resp, "error", None) is not None:
            print("Error marking notification as read:", update_resp.error)
            raise HTTPException(status_code=400, detail="Error updating notification")

        return {"message": "Notification marked as read"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error marking notification as read: {str(e)}")
        raise HTTPException(status_code=500, detail="Error updating notification")


@router.get("/unread-count")
async def get_unread_count(
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Get count of unread notifications"""
    try:
        user_id = current_user["id"]

        count_resp = (
            supabase.table("notifications")
            .select("id", count="exact")
            .eq("recipient_id", user_id)
            .eq("read", False)
            .execute()
        )

        if getattr(count_resp, "error", None) is not None:
            print("Error fetching unread count:", count_resp.error)
            raise HTTPException(status_code=400, detail="Error fetching unread count")

        unread_count = count_resp.count or 0
        return {"unread_count": unread_count}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching unread count: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching unread count")


async def create_notification(
        recipient_id: str,
        sender_id: str,
        notification_type: str,
        message: str
):
    """Helper function to create a notification"""
    try:
        # Check if recipient and sender are different
        if recipient_id == sender_id:
            return

        # Check if users are blocked (don't send notifications to/from blocked users)
        block_check1 = (
            supabase.table("blocked_users")
            .select("id")
            .eq("blocker_id", recipient_id)
            .eq("blocked_id", sender_id)
            .execute()
        )

        block_check2 = (
            supabase.table("blocked_users")
            .select("id")
            .eq("blocker_id", sender_id)
            .eq("blocked_id", recipient_id)
            .execute()
        )

        # If either user has blocked the other, don't create notification
        if ((block_check1.data and len(block_check1.data) > 0) or
                (block_check2.data and len(block_check2.data) > 0)):
            print(f"Not creating notification - users are blocked")
            return

        # Create the notification
        insert_resp = (
            supabase.table("notifications")
            .insert({
                "recipient_id": recipient_id,
                "sender_id": sender_id,
                "type": notification_type,
                "message": message,
                "read": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            .execute()
        )

        if getattr(insert_resp, "error", None) is not None:
            print("Error creating notification:", insert_resp.error)
        else:
            print(f"Created notification: {notification_type} from {sender_id} to {recipient_id}")

    except Exception as e:
        print(f"Error creating notification: {str(e)}")
        # Don't raise exception - notifications are not critical