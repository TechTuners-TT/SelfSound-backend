import re
from uuid import UUID
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from supabase_client import supabase
from routes.dependencies import get_verified_user
from models.schemas.comments import CommentOut, CommentCreate
from routes.notifications_router import create_notification  # Import notification function

router = APIRouter(prefix="/posts", tags=["Post Comments"])

# Regex to extract mentions like @username
mention_regex = re.compile(r'@([a-zA-Z0-9_]+)')


def extract_mentions(text: str) -> List[str]:
    return mention_regex.findall(text)


import re
from uuid import UUID
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from supabase_client import supabase
from routes.dependencies import get_verified_user
from models.schemas.comments import CommentOut, CommentCreate
from routes.notifications_router import create_notification  # Import notification function

router = APIRouter(prefix="/posts", tags=["Post Comments"])

# Regex to extract mentions like @username
mention_regex = re.compile(r'@([a-zA-Z0-9_-]+)')


def extract_mentions(text: str) -> List[str]:
    """Extract @username mentions from text"""
    mentions = mention_regex.findall(text)
    print(f"🔍 Extracted mentions from '{text}': {mentions}")
    return mentions


@router.post("/{post_id}/comments", response_model=CommentOut, status_code=status.HTTP_201_CREATED)
async def add_comment(post_id: UUID, comment: CommentCreate, user=Depends(get_verified_user)):
    """Add a comment to a post with mention notifications"""
    print(f"🔔 Starting add_comment for post {post_id}")
    print(f"🔔 Comment content: '{comment.content}'")
    print(f"🔔 Comment author: {user['id']} ({user.get('login', 'unknown')})")

    try:
        # 1. Get post info first (for notifications)
        print(f"📄 Fetching post data...")
        post_response = supabase.table("posts").select("id, user_id").eq("id", str(post_id)).single().execute()

        if post_response.error:
            print(f"❌ Error fetching post: {post_response.error}")
            raise HTTPException(status_code=500, detail=f"Error fetching post: {post_response.error}")

        if not post_response.data:
            print(f"❌ Post not found: {post_id}")
            raise HTTPException(status_code=404, detail="Post not found")

        post_data = post_response.data
        print(f"📄 Post data: {post_data}")

        # 2. Insert the comment
        print(f"💬 Creating comment...")
        comment_insert_data = {
            "post_id": str(post_id),
            "author_id": user["id"],
            "content": comment.content,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        comment_response = supabase.table("post_comments").insert(comment_insert_data).execute()

        if comment_response.error:
            print(f"❌ Error creating comment: {comment_response.error}")
            raise HTTPException(status_code=500, detail=f"Error creating comment: {comment_response.error}")

        if not comment_response.data:
            print(f"❌ No comment data returned")
            raise HTTPException(status_code=500, detail="Failed to create comment")

        comment_data = comment_response.data[0]
        comment_id = comment_data["id"]
        print(f"💬 Comment created with ID: {comment_id}")

        # 3. Extract mentions from comment content
        print(f"🔍 Extracting mentions...")
        mentioned_usernames = extract_mentions(comment.content)
        mentioned_user_ids = []

        if mentioned_usernames:
            print(f"👥 Found {len(mentioned_usernames)} mentions: {mentioned_usernames}")

            # 4. Query user IDs for mentioned usernames
            print(f"🔎 Looking up user IDs for mentions...")
            users_resp = supabase.table("user_profiles").select("id, login").in_("login", mentioned_usernames).execute()

            if users_resp.error:
                print(f"❌ Error fetching mentioned users: {users_resp.error}")
            else:
                mentioned_users_data = users_resp.data or []
                mentioned_user_ids = [user_data["id"] for user_data in mentioned_users_data]
                print(f"👥 Resolved user IDs: {mentioned_user_ids}")

                # 5. Insert mentions into comment_mentions table
                if mentioned_user_ids:
                    print(f"💾 Saving mentions to database...")
                    mentions_data = [
                        {
                            "comment_id": comment_id,
                            "mentioned_user_id": uid,
                            "created_at": datetime.now(timezone.utc).isoformat()
                        }
                        for uid in mentioned_user_ids
                    ]

                    mentions_resp = supabase.table("comment_mentions").insert(mentions_data).execute()
                    if mentions_resp.error:
                        print(f"⚠️ Error saving mentions (non-critical): {mentions_resp.error}")
                    else:
                        print(f"💾 Mentions saved successfully")
        else:
            print(f"👥 No mentions found in comment")

        # 6. Send notifications
        print(f"🔔 Starting notification process...")
        print(f"🔔 Mentioned user IDs: {mentioned_user_ids}")
        print(f"🔔 Post owner ID: {post_data['user_id']}")
        print(f"🔔 Comment author ID: {user['id']}")

        notification_count = 0

        try:
            # Send mention notifications
            for mentioned_user_id in mentioned_user_ids:
                if mentioned_user_id != user["id"]:  # Don't notify yourself
                    print(f"📨 Sending mention notification to user {mentioned_user_id}...")
                    try:
                        await create_notification(
                            recipient_id=mentioned_user_id,
                            sender_id=user["id"],
                            notification_type="mention",
                            message="mentioned you in a comment"
                        )
                        print(f"✅ Mention notification sent to {mentioned_user_id}")
                        notification_count += 1
                    except Exception as e:
                        print(f"❌ Failed to send mention notification to {mentioned_user_id}: {str(e)}")
                else:
                    print(f"⏭️ Skipping self-mention for user {mentioned_user_id}")

            # Send comment notification to post owner (if not the commenter and not already mentioned)
            post_owner_id = post_data["user_id"]
            if post_owner_id != user["id"] and post_owner_id not in mentioned_user_ids:
                print(f"📨 Sending comment notification to post owner {post_owner_id}...")
                try:
                    await create_notification(
                        recipient_id=post_owner_id,
                        sender_id=user["id"],
                        notification_type="comment",
                        message="commented on your post"
                    )
                    print(f"✅ Comment notification sent to post owner {post_owner_id}")
                    notification_count += 1
                except Exception as e:
                    print(f"❌ Failed to send comment notification to post owner: {str(e)}")
            else:
                print(f"⏭️ Skipping comment notification (owner is commenter or already mentioned)")

            print(f"🔔 Notification process complete. Sent {notification_count} notifications.")

        except Exception as e:
            print(f"❌ Error in notification process: {str(e)}")
            # Don't fail the comment creation if notification fails

        # 7. Return the comment data
        print(f"✅ Comment creation successful")
        return comment_data

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Unexpected error in add_comment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create comment: {str(e)}")


@router.get("/{post_id}/comments", response_model=List[CommentOut])
def get_comments(post_id: UUID, user: Optional[dict] = Depends(get_verified_user)):
    """Get all comments for a post with mentions and user data"""
    print(f"📖 Fetching comments for post {post_id}")

    try:
        # Get all comments for the post
        print(f"💬 Querying comments...")
        comments_response = supabase.table("post_comments") \
            .select("id, post_id, author_id, content, created_at") \
            .eq("post_id", str(post_id)) \
            .order("created_at", desc=False) \
            .execute()

        if comments_response.error:
            print(f"❌ Error fetching comments: {comments_response.error}")
            raise HTTPException(status_code=500, detail=f"Error fetching comments: {comments_response.error}")

        comments = comments_response.data or []
        print(f"💬 Found {len(comments)} comments")

        if not comments:
            print(f"📖 No comments found, returning empty list")
            return []

        comment_ids = [comment["id"] for comment in comments]
        author_ids = [comment["author_id"] for comment in comments]

        # Get author data for each comment
        print(f"👥 Fetching author data for {len(set(author_ids))} unique authors...")
        authors_response = supabase.table("user_profiles") \
            .select("id, name, login, avatar_url, tag_id") \
            .in_("id", author_ids) \
            .execute()

        if authors_response.error:
            print(f"❌ Error fetching authors: {authors_response.error}")
            raise HTTPException(status_code=500, detail=f"Error fetching authors: {authors_response.error}")

        authors_data = authors_response.data or []
        author_lookup = {author["id"]: author for author in authors_data}
        print(f"👥 Loaded {len(authors_data)} author profiles")

        # Map user roles
        def map_user_role(tag_id):
            role_map = {
                "146fb41a-2f3e-48c7-bef9-01de0279dfd7": "Listener",
                "b361c6f9-9425-4548-8c07-cb408140c304": "Musician",
                "5ee121a6-b467-4ead-b3f7-00e1ce6097d5": "Learner"
            }
            return role_map.get(tag_id, "Listener")

        # Get like counts and user likes
        print(f"❤️ Fetching like data...")
        likes_response = supabase.table("comment_likes") \
            .select("comment_id, user_id") \
            .in_("comment_id", comment_ids) \
            .execute()

        if likes_response.error:
            print(f"⚠️ Error fetching likes (non-critical): {likes_response.error}")
            likes_data = []
        else:
            likes_data = likes_response.data or []

        like_counts = {}
        liked_by_user = set()
        for like in likes_data:
            cid = like["comment_id"]
            like_counts[cid] = like_counts.get(cid, 0) + 1
            if user and like["user_id"] == user["id"]:
                liked_by_user.add(cid)

        print(f"❤️ Processed {len(likes_data)} likes")

        # Get mentions for each comment
        print(f"🏷️ Fetching mention data...")
        mentions_response = supabase.table("comment_mentions") \
            .select("comment_id, mentioned_user_id") \
            .in_("comment_id", comment_ids) \
            .execute()

        if mentions_response.error:
            print(f"⚠️ Error fetching mentions (non-critical): {mentions_response.error}")
            mentions_data = []
        else:
            mentions_data = mentions_response.data or []

        # Get mentioned user profiles
        mentioned_user_ids = list(set([mention["mentioned_user_id"] for mention in mentions_data]))
        mentioned_users_lookup = {}

        if mentioned_user_ids:
            print(f"👥 Fetching {len(mentioned_user_ids)} mentioned user profiles...")
            mentioned_users_response = supabase.table("user_profiles") \
                .select("id, login, name, avatar_url") \
                .in_("id", mentioned_user_ids) \
                .execute()

            if mentioned_users_response.error:
                print(f"⚠️ Error fetching mentioned users: {mentioned_users_response.error}")
            else:
                mentioned_users_data = mentioned_users_response.data or []
                mentioned_users_lookup = {user_data["id"]: user_data for user_data in mentioned_users_data}

        # Group mentions by comment_id
        mentions_lookup = {}
        for mention in mentions_data:
            cid = mention["comment_id"]
            mentioned_user_data = mentioned_users_lookup.get(mention["mentioned_user_id"])
            if mentioned_user_data:
                if cid not in mentions_lookup:
                    mentions_lookup[cid] = []
                mentions_lookup[cid].append({
                    "user_id": mention["mentioned_user_id"],
                    "login": mentioned_user_data["login"],
                    "name": mentioned_user_data["name"],
                    "avatar_url": mentioned_user_data["avatar_url"]
                })

        print(f"🏷️ Processed mentions for {len(mentions_lookup)} comments")

        # Build result
        print(f"🔧 Building response...")
        result = []
        for comment in comments:
            author = author_lookup.get(comment["author_id"], {})

            formatted_comment = {
                "id": comment["id"],
                "post_id": comment["post_id"],
                "author_id": comment["author_id"],
                "content": comment["content"],
                "created_at": comment["created_at"],
                "author_name": author.get("name", "Unknown User"),
                "author_login": author.get("login", "unknown"),
                "author_avatar_url": author.get("avatar_url", ""),
                "like_count": like_counts.get(comment["id"], 0),
                "liked": comment["id"] in liked_by_user,
                "mentions": mentions_lookup.get(comment["id"], []),
                # Add these fields for your frontend
                "text": comment["content"],  # Alias for content
                "user": {
                    "id": comment["author_id"],
                    "name": author.get("name", "Unknown User"),
                    "login": author.get("login", "unknown"),
                    "avatar_url": author.get("avatar_url", ""),
                    "role": map_user_role(author.get("tag_id"))
                }
            }
            result.append(formatted_comment)

        print(f"✅ Returning {len(result)} formatted comments")
        return result

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Unexpected error in get_comments: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get comments: {str(e)}")


# Add endpoint for user search (for autocomplete)
@router.get("/users/search")
async def search_users_for_mention(
        q: str,
        limit: int = 10
):
    """Search users by login/name for mention autocomplete"""
    print(f"🔎 Searching users with query: '{q}'")

    try:
        if not q or len(q.strip()) < 2:
            print(f"🔎 Query too short, returning empty results")
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

            if users_response.error:
                print(f"❌ Error searching users: {users_response.error}")
                return []

            users_data = users_response.data or []
            print(f"🔎 Found {len(users_data)} users matching '{q}'")

        except Exception as e:
            print(f"❌ Error searching users: {str(e)}")
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
        print(f"❌ Error in search_users_for_mention: {str(e)}")
        return []

# Add endpoint for user search (for autocomplete)
@router.get("/users/search")
async def search_users_for_mention(
        q: str,
        limit: int = 10
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


@router.delete("/comments/{comment_id}")
def delete_comment(comment_id: UUID, user=Depends(get_verified_user)):
    response = supabase.from_("post_comments").select("*").eq("id", str(comment_id)).single().execute()

    if response.error or not response.data:
        raise HTTPException(status_code=404, detail="Comment not found")

    comment = response.data

    if comment["author_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")

    delete_response = supabase.from_("post_comments").delete().eq("id", str(comment_id)).execute()

    if delete_response.error:
        raise HTTPException(status_code=500, detail=delete_response.error.message)

    return {"detail": "Comment deleted"}


@router.post("/comments/{comment_id}/like", status_code=status.HTTP_201_CREATED)
def like_comment(comment_id: UUID, user=Depends(get_verified_user)):
    # Check if already liked
    check_response = supabase.from_("comment_likes") \
        .select("id") \
        .eq("comment_id", str(comment_id)) \
        .eq("user_id", user["id"]) \
        .execute()

    if check_response.error:
        raise HTTPException(status_code=500, detail=check_response.error.message)

    if check_response.data:
        raise HTTPException(status_code=400, detail="Already liked")

    insert_response = supabase.from_("comment_likes") \
        .insert({"comment_id": str(comment_id), "user_id": user["id"]}) \
        .execute()

    if insert_response.error:
        raise HTTPException(status_code=500, detail=insert_response.error.message)

    return {"detail": "Comment liked"}


@router.delete("/comments/{comment_id}/like", status_code=status.HTTP_204_NO_CONTENT)
def unlike_comment(comment_id: UUID, user=Depends(get_verified_user)):
    delete_response = supabase.from_("comment_likes") \
        .delete() \
        .eq("comment_id", str(comment_id)) \
        .eq("user_id", user["id"]) \
        .execute()

    if delete_response.error:
        raise HTTPException(status_code=500, detail=delete_response.error.message)

    return