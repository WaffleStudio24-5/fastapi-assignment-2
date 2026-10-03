from datetime import datetime, timezone

import jwt
from argon2 import PasswordHasher
from fastapi import APIRouter, Cookie, Header, status

from src.auth.errors import (
    InvalidSessionException,
    InvalidTokenException,
    UnauthenticatedException,
)
from src.auth.router import ALGORITHM, SECRET_KEY, get_bearer_token
from src.common.database import session_db, user_db
from src.users.errors import EmailAlreadyExistsException
from src.users.schemas import CreateUserRequest, UserResponse


user_router = APIRouter(prefix="/users", tags=["users"])

password_hasher = PasswordHasher()


@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    if any(user["email"] == str(request.email) for user in user_db):
        raise EmailAlreadyExistsException()

    user = {
        "user_id": len(user_db) + 1,
        "email": str(request.email),
        "hashed_password": password_hasher.hash(request.password),
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
) -> UserResponse:
    if sid is not None:
        session = session_db.get(sid)

        if (
            session is None
            or session["expires_at"] <= datetime.now(timezone.utc)
        ):
            raise InvalidSessionException()

        user_id = session["user_id"]

    elif authorization is not None:
        token = get_bearer_token(authorization)

        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=[ALGORITHM],
                options={"require": ["sub", "exp", "token_type"]},
            )
        except jwt.PyJWTError:
            raise InvalidTokenException()

        if payload["token_type"] != "access":
            raise InvalidTokenException()

        user_id = int(payload["sub"])

    else:
        raise UnauthenticatedException()

    user = next(
        (user for user in user_db if user["user_id"] == user_id),
        None,
    )

    if user is None:
        raise InvalidTokenException()

    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user["bio"],
    )

    
