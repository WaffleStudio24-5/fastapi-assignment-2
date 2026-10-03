from typing import Annotated
from argon2 import PasswordHasher
from datetime import datetime, timezone
import jwt
from src.auth.router import JWT_SECRET_KEY
from src.auth.errors import (
    UnauthenticatedException,
    InvalidSessionException,
    BadAuthorizationHeaderException,
    InvalidTokenException,
)
from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.users.errors import EmailAlreadyExistsException
from src.common.database import blocked_token_db, session_db, user_db

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    if any(user["email"] == request.email for user in user_db):
        raise EmailAlreadyExistsException()

    user = {
        "user_id": max((entry["user_id"] for entry in user_db), default=0) + 1,
        "email": str(request.email),
        "hashed_password": PasswordHasher().hash(request.password),
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio,
    }
    user_db.append(user)

    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user["bio"],
    )

@user_router.get("/me")
def get_user_info(
    sid: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
):
    if sid is None and authorization is None:
        raise UnauthenticatedException()

    if sid is not None:
        session = session_db.get(sid)
        if session is None or datetime.now(timezone.utc) >= session["expires_at"]:
            raise InvalidSessionException()

        user = next(
            (item for item in user_db if item["user_id"] == session["user_id"]),
            None,
        )
        if user is None:
            raise InvalidSessionException()

        return UserResponse.model_validate(user)
    if authorization is not None:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise BadAuthorizationHeaderException()

        token = parts[1]
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=["HS256"],
                options={"require": ["sub", "exp"]},
            )
        except jwt.InvalidTokenError:
            raise InvalidTokenException()

        if payload.get("token_type") != "access":
            raise InvalidTokenException()

        user = next(
            (item for item in user_db if str(item["user_id"]) == payload["sub"]),
            None,
        )
        if user is None:
            raise InvalidTokenException()

        return UserResponse.model_validate(user)