from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db

from src.users.errors import EmailAlreadyExistsException

from argon2 import PasswordHasher

ph = PasswordHasher(
    memory_cost=65536,
    time_cost=3,
    parallelism=4
)

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    user_id = len(user_db) + 1
    if request.email in [item['email'] for item in user_db]:
        raise EmailAlreadyExistsException()
    user_db.append({
        "user_id": user_id,
        "email": request.email,
        "hashed_password": ph.hash(request.password),
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio
    })
    return UserResponse(
        user_id=user_id,
        email=request.email,
        name=request.name,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio
    )

@user_router.get("/me")
def get_user_info():
    pass
