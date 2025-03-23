from fastapi import APIRouter, Depends
from app.schemas.user_schemas import User


router = APIRouter()

@router.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

