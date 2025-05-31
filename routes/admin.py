from fastapi import APIRouter, HTTPException, status, Request
from datetime import datetime, date
import logging
from supabase_client import supabase

router = APIRouter(prefix="/admin", tags=["admin"])


# Admin middleware to check if user is admin
async def verify_admin(request: Request):
    """Verify that the current user is an admin"""
    try:
        # Get cookies for session-based auth (like your existing /authorization/me endpoint)
        cookies = request.cookies

        # Alternative: try to get user from your existing auth system
        # This should match however you handle auth in other endpoints

        # Method 1: Using session cookie (recommended if you're using session-based auth)
        try:
            # Try to get user from your existing session system
            # This assumes you have a way to get current user from session
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://backend-m5qb.onrender.com/authorization/me",
                    cookies=cookies
                )
                if not response.is_success:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated"
                    )

                user_data = response.json()
                user_id = user_data.get('id')

                if not user_id:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid user data"
                    )

        except Exception as auth_error:
            logging.error(f"Auth error: {auth_error}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed"
            )

        # Check if user is admin in your users table
        user_response = supabase.table('users').select('is_admin').eq('id', user_id).execute()

        if not user_response.data or not user_response.data[0].get('is_admin'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )

        return {"id": user_id}

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error verifying admin: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


# Simple admin check endpoint
@router.get("/check")
async def check_admin(request: Request):
    """Simple endpoint to check if user is admin"""
    admin_user = await verify_admin(request)
    return {"is_admin": True, "user_id": admin_user["id"]}


# Analytics endpoints
@router.get("/analytics")
async def get_analytics(request: Request):
    """Get analytics data for admin dashboard"""
    # Verify admin first
    admin_user = await verify_admin(request)

    try:
        # Get today's date
        today = date.today().isoformat()

        # Total posts count
        total_posts_response = supabase.table('posts').select('id', count='exact').execute()
        total_posts = total_posts_response.count or 0

        # Total users count
        total_users_response = supabase.table('users').select('id', count='exact').execute()
        total_users = total_users_response.count or 0

        # Posts created today
        posts_today_response = supabase.table('posts').select('id', count='exact').gte('created_at',
                                                                                       f'{today}T00:00:00').lt(
            'created_at', f'{today}T23:59:59').execute()
        posts_today = posts_today_response.count or 0

        # New users today
        new_users_today_response = supabase.table('users').select('id', count='exact').gte('created_at',
                                                                                           f'{today}T00:00:00').lt(
            'created_at', f'{today}T23:59:59').execute()
        new_users_today = new_users_today_response.count or 0

        return [
            {"posts_title": "Total Posts", "posts_data": str(total_posts)},
            {"posts_title": "Total Users", "posts_data": str(total_users)},
            {"posts_title": "Posts Today", "posts_data": str(posts_today)},
            {"posts_title": "New Users Today", "posts_data": str(new_users_today)},
        ]

    except Exception as e:
        logging.error(f"Error getting analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch analytics data"
        )

        # Reports/Complaints endpoints
@router.get("/reports")
async def get_reports(request: Request):
            """Get all user reports for admin review"""
            # Verify admin first
            admin_user = await verify_admin(request)

            try:
                # Get all reports from post_reports table
                reports_response = supabase.table('post_reports').select('*').execute()

                formatted_reports = []
                for report in reports_response.data:
                    # Parse the created_at timestamp
                    created_at = datetime.fromisoformat(report['created_at'].replace('Z', '+00:00'))

                    # Get reporter info - try different column names
                    try:
                        # First try with just 'name' since 'login' doesn't exist
                        reporter_response = supabase.table('users').select('name').eq('id',
                                                                                      report['reporter_id']).execute()
                        reporter_name = "Unknown"
                        if reporter_response.data and len(reporter_response.data) > 0:
                            reporter_name = reporter_response.data[0].get('name', 'Unknown')
                    except Exception as e:
                        logging.warning(f"Could not fetch reporter info: {e}")
                        reporter_name = "Unknown"

                    formatted_reports.append({
                        "id": report['id'],
                        "title": f"Report #{report['id'][:8]}...",  # Truncate UUID for display
                        "data": created_at.strftime("%Y-%m-%d %H:%M"),
                        "reporter_id": str(report['reporter_id']),
                        "post_id": str(report['post_id']),
                        "reason": report['reason'],
                        "description": report.get('description', ''),
                        "post_link": f"https://techtuners-tt.github.io/SelfSound/#/post/{report['post_id']}",
                        "reporter_name": reporter_name,
                        "status": report.get('status', 'pending')
                    })

                return formatted_reports

            except Exception as e:
                logging.error(f"Error getting reports: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to fetch reports"
                )

@router.post("/reports/{report_id}/resolve")
async def resolve_report(
                report_id: str,
                request: Request
        ):
            """Resolve a report by either deleting the post or ignoring the report"""
            # Verify admin first
            admin_user = await verify_admin(request)

            try:
                # Get action from request body
                body = await request.json()
                action = body.get('action')

                if not action or action not in ['delete_post', 'ignore']:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid action. Use 'delete_post' or 'ignore'"
                    )

                # Get the report from post_reports table
                report_response = supabase.table('post_reports').select('*').eq('id', report_id).execute()

                if not report_response.data:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Report not found"
                    )

                report = report_response.data[0]

                if action == "delete_post":
                    # Delete the reported post
                    delete_response = supabase.table('posts').delete().eq('id', report['post_id']).execute()
                    logging.info(f"Admin {admin_user['id']} deleted post {report['post_id']}")

                elif action == "ignore":
                    # Just log the action
                    logging.info(f"Admin {admin_user['id']} ignored report {report_id}")

                # Delete the report after processing
                supabase.table('post_reports').delete().eq('id', report_id).execute()

                return {"message": f"Report {action.replace('_', ' ')} successfully"}

            except HTTPException:
                raise
            except Exception as e:
                logging.error(f"Error resolving report: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to resolve report"
                )
# User management endpoint (optional)
@router.get("/users")
async def get_users(request: Request):
    """Get all users for admin management"""
    # Verify admin first
    admin_user = await verify_admin(request)

    try:
        users_response = supabase.table('users').select('*').execute()

        formatted_users = []
        for user in users_response.data:
            created_at = datetime.fromisoformat(user['created_at'].replace('Z', '+00:00'))

            formatted_users.append({
                "id": user['id'],
                "name": user['name'],
                "login": user['login'],
                "email": user.get('email', ''),
                "is_admin": user.get('is_admin', False),
                "created_at": created_at.strftime("%Y-%m-%d %H:%M"),
                "role": user.get('role', 'User')
            })

        return formatted_users

    except Exception as e:
        logging.error(f"Error getting users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users"
        )