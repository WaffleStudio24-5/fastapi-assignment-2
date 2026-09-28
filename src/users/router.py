from threading import Lock

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, status

from src.common import CustomException
from src.common.database import user_db
from src.users.schemas import CreateUserRequest, UserResponse
from src.auth.security import get_current_user


user_router = APIRouter(prefix="/users", tags=["users"])

password_hasher = PasswordHasher()
user_creation_lock = Lock()


@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    with user_creation_lock:
        for user in user_db:
            if user["email"] == request.email:
                raise CustomException(
                    status_code=409,
                    error_code="ERR_005",
                    error_message="EMAIL ALREADY EXISTS",
                )

        user_id = max(
            (user["user_id"] for user in user_db),
            default=0,
        ) + 1

        user_data = request.model_dump(exclude={"password"})

        user_db.append(
            {
                "user_id": user_id,
                **user_data,
                "hashed_password": password_hasher.hash(request.password),
            }
        )

    return UserResponse(
        user_id=user_id,
        **user_data,
    )

@user_router.get("/me")
def get_user_info(
    current_user: dict = Depends(get_current_user),
) -> UserResponse:
    return UserResponse(
        user_id=current_user["user_id"],
        name=current_user["name"],
        email=current_user["email"],
        phone_number=current_user["phone_number"],
        height=current_user["height"],
        bio=current_user.get("bio"),
    )