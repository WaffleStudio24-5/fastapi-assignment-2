from typing import Annotated
from argon2 import PasswordHasher
from datetime import datetime, timezone
from fastapi import APIRouter, Header, Response, Cookie, status

from src.users.schemas import CreateUserRequest, User, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import DuplicateEmailException
from src.auth.errors import InvalidSessionException
from src.auth.router import decode_jwt, get_bearer_token

user_router = APIRouter(prefix="/users", tags=["users"])
password_hasher = PasswordHasher()

@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    for existing_user in user_db:
        if existing_user.email == request.email:
            raise DuplicateEmailException()

    user_id = max(
        (existing_user.user_id for existing_user in user_db),
        default=0,
    ) + 1

    user = User(
        user_id=user_id,
        email=request.email,
        hashed_password=password_hasher.hash(request.password),
        name=request.name,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio,
    )

    user_db.append(user)

    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.name,
        phone_number=user.phone_number,
        height=user.height,
        bio=user.bio,
    )

@user_router.get("/me")
def get_user_info(
    sid: Annotated[str | None, Cookie()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> UserResponse:
    if sid is not None:
        session = session_db.get(sid)

        if session is None:
            raise InvalidSessionException()

        if session["expires_at"] <= datetime.now(timezone.utc):
            session_db.pop(sid, None)
            raise InvalidSessionException()

        user = next(
            (
                existing_user
                for existing_user in user_db
                if existing_user.user_id == session["user_id"]
            ),
            None,
        )

        if user is None:
            raise InvalidSessionException()

    else:
        access_token = get_bearer_token(authorization)

        _, user = decode_jwt(
            access_token,
            expected_type="access",
        )

    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.name,
        phone_number=user.phone_number,
        height=user.height,
        bio=user.bio,
    )