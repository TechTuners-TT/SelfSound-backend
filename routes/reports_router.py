# Create a new file: routes/reports_router.py

from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated, Optional
import uuid
from datetime import datetime, timezone
from routes.dependencies import get_verified_user
from supabase_client import supabase
from pydantic import BaseModel

router = APIRouter(prefix="/reports", tags=["Reports"])


# Pydantic models
class ReportRequest(BaseModel):
    post_id: str
    reason: str
    description: Optional[str] = None


class ReportResponse(BaseModel):
    message: str
    report_id: str


# Allowed report reasons
ALLOWED_REASONS = {
    "Spam",
    "Harassment",
    "Hate speech",
    "Inappropriate content",
    "Copyright violation",
    "False information",
    "Other"
}


@router.post("/post", response_model=ReportResponse)
async def report_post(
        report_data: ReportRequest,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Report a post for violating community guidelines"""
    try:
        # Validate post_id is UUID
        try:
            uuid.UUID(report_data.post_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid post ID format")

        # Validate reason
        if report_data.reason not in ALLOWED_REASONS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid reason. Allowed reasons: {', '.join(ALLOWED_REASONS)}"
            )

        # Check if post exists
        try:
            post_response = supabase.table("posts").select("id, user_id").eq("id",
                                                                             report_data.post_id).single().execute()
            if not post_response.data:
                raise HTTPException(status_code=404, detail="Post not found")
            post_data = post_response.data
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                raise HTTPException(status_code=404, detail="Post not found")
            raise HTTPException(status_code=500, detail="Failed to verify post")

        user_id = current_user["id"]

        # Check if user already reported this post
        try:
            existing_report = (
                supabase.table("post_reports")
                .select("id")
                .eq("post_id", report_data.post_id)
                .eq("reporter_id", user_id)
                .execute()
            )

            if existing_report.data and len(existing_report.data) > 0:
                raise HTTPException(status_code=400, detail="You have already reported this post")
        except HTTPException:
            raise
        except Exception as e:
            print(f"Error checking existing report: {str(e)}")
            # Continue if we can't check - better to allow duplicate than block legitimate reports

        # Create report record
        report_record = {
            "post_id": report_data.post_id,
            "reported_user_id": post_data["user_id"],  # User who created the post
            "reporter_id": user_id,  # User who is reporting
            "reason": report_data.reason,
            "description": report_data.description,
            "status": "pending",  # pending, reviewed, resolved, dismissed
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            report_response = supabase.table("post_reports").insert(report_record).execute()
            created_report = report_response.data[0]
            print(f"✅ Report created with ID: {created_report['id']}")
        except Exception as e:
            print(f"❌ Error creating report: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create report")

        # Optionally notify moderators/admins about the new report
        # You can implement this later with a notification system for admins

        return ReportResponse(
            message="Report submitted successfully. Thank you for helping keep our community safe.",
            report_id=created_report["id"]
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Unexpected error in report_post: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit report")


@router.get("/my-reports")
async def get_my_reports(
        current_user: Annotated[dict, Depends(get_verified_user)],
        limit: int = 20,
        offset: int = 0
):
    """Get reports submitted by the current user"""
    try:
        user_id = current_user["id"]

        # Get user's reports with post information
        reports_response = (
            supabase.table("post_reports")
            .select("""
                id,
                post_id,
                reason,
                description,
                status,
                created_at,
                posts!post_reports_post_id_fkey(id, type, caption, created_at, user_id)
            """)
            .eq("reporter_id", user_id)
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        reports = reports_response.data or []

        return {
            "reports": reports,
            "total": len(reports)
        }

    except Exception as e:
        print(f"❌ Error fetching user reports: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch reports")


# Admin endpoints (you can add role-based access control later)
@router.get("/admin/all")
async def get_all_reports(
        current_user: Annotated[dict, Depends(get_verified_user)],
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
):
    """Get all reports (admin only - you should add role check)"""
    try:
        # TODO: Add admin role check here
        # if current_user.get("role") != "admin":
        #     raise HTTPException(status_code=403, detail="Admin access required")

        query = supabase.table("post_reports").select("""
            id,
            post_id,
            reported_user_id,
            reporter_id,
            reason,
            description,
            status,
            created_at,
            posts!post_reports_post_id_fkey(id, type, caption, user_id),
            reporter:user_profiles!post_reports_reporter_id_fkey(id, name, login),
            reported_user:user_profiles!post_reports_reported_user_id_fkey(id, name, login)
        """)

        if status:
            query = query.eq("status", status)

        reports_response = (
            query
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        reports = reports_response.data or []

        return {
            "reports": reports,
            "total": len(reports)
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error fetching all reports: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch reports")


@router.patch("/admin/{report_id}/status")
async def update_report_status(
        report_id: str,
        status: str,
        current_user: Annotated[dict, Depends(get_verified_user)]
):
    """Update report status (admin only)"""
    try:
        # TODO: Add admin role check
        # if current_user.get("role") != "admin":
        #     raise HTTPException(status_code=403, detail="Admin access required")

        # Validate report_id is UUID
        try:
            uuid.UUID(report_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid report ID format")

        # Validate status
        allowed_statuses = {"pending", "reviewed", "resolved", "dismissed"}
        if status not in allowed_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Allowed: {', '.join(allowed_statuses)}"
            )

        # Update report status
        update_response = (
            supabase.table("post_reports")
            .update({"status": status, "updated_at": datetime.now(timezone.utc).isoformat()})
            .eq("id", report_id)
            .execute()
        )

        if not update_response.data:
            raise HTTPException(status_code=404, detail="Report not found")

        return {"message": f"Report status updated to {status}"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error updating report status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update report status")