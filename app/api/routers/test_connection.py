# app/api/router/test_connection.py 

from fastapi import APIRouter
from app.database.database import supabase

router = APIRouter()

# Test the connection to Supabase with a GET request
@router.get("/test-connection")
async def test_connection():
    try:
        response = supabase.from_("User").select("*").execute()
        print(response)  # Log the full response for debugging
        return {"status": "success", "data": response.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}

