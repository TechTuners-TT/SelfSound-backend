from fastapi import APIRouter, HTTPException, Request
from jwt_handler import generate_jwt, decode_jwt
from supabase_client import supabase

router = APIRouter(prefix="/listeners", tags=["Listeners"])

@router.post("/me/listeners/{user_id}")
async def tolisten_user(request: Request, user_id: str):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the token to get the user info
        payload = decode_jwt(token)
        current_user_id = payload.get("sub")  # Use 'sub' (Google's user ID) to find the user

        # Check if the user is trying to follow themselves
        if current_user_id == user_id:
            raise HTTPException(status_code=400, detail="You cannot subscribe to yourself")

        # Insert into the subscriptions table
        subscription_data = {
            "subscriber_id": current_user_id,
            "subscribed_id": user_id
        }

        # Check if the subscription already exists
        existing_subscription = supabase.from_("subscriptions") \
            .select("*") \
            .eq("subscriber_id", current_user_id) \
            .eq("subscribed_id", user_id) \
            .single() \
            .execute()

        if existing_subscription.data:
            raise HTTPException(status_code=400, detail="You are already subscribed to this user")

        # Create subscription
        supabase.from_("listeners").insert(subscription_data).execute()

        return {"message": "Is listening now"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to subscribe: {str(e)}")

# Unsubscribe from a user endpoint
@router.post("/me/unlisten/{user_id}")
async def unlisten_user(request: Request, user_id: str):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the token to get the user info
        payload = decode_jwt(token)
        current_user_id = payload.get("sub")  # Use 'sub' (Google's user ID) to find the user

        # Remove subscription from the subscriptions table
        supabase.from_("listeners") \
            .delete() \
            .eq("subscriber_id", current_user_id) \
            .eq("subscribed_id", user_id) \
            .execute()

        return {"message": "Not listening now!"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unsubscribe: {str(e)}")


# Endpoint to Get subscribers (People following the users)
@router.get("/me/listeners")
async def get_listeners(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Decode the token to get the user info
        payload = decode_jwt(token)
        user_id = payload.get("sub")  # Use 'sub' to get the current user's ID

        # Fetch the users who are subscribed to the current user (followers)
        subscribers = supabase.from_("listeners") \
            .select("subscriber_id") \
            .eq("subscribed_id", user_id) \
            .execute()

        return {"listeners": subscribers.data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch subscribers: {str(e)}")

@router.get("/tags")
async def get_tags():
    try:
        response = supabase.from_("tags").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
