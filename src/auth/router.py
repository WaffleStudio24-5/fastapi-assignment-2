from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Header, Response, Cookie

from src.auth.errors import (
    BadAuthorizationHeaderException,
    InvalidAccountException,
    InvalidTokenException,
    UnauthenticatedException,
)
from src.auth.schemas import LoginRequest, TokenResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.users.schemas import User

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

JWT_SECRET_KEY = "fastapi-assignment-secret"
JWT_ALGORITHM = "HS256"

password_hasher = PasswordHasher()


def create_jwt(
    user_id: int,
    lifespan_minutes: int,
    token_type: str,
) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=lifespan_minutes
    )

    payload = {
        "sub": str(user_id),
        "exp": expires_at,
        "jti": str(uuid4()),
        "token_type": token_type,
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def get_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise UnauthenticatedException()

    parts = authorization.split()

    if len(parts) != 2 or parts[0] != "Bearer":
        raise BadAuthorizationHeaderException()

    return parts[1]


def decode_jwt(
    token: str,
    expected_type: str,
) -> tuple[dict, User]:
    if token in blocked_token_db:
        raise InvalidTokenException()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
    except jwt.InvalidTokenError:
        raise InvalidTokenException()

    if payload.get("token_type") != expected_type:
        raise InvalidTokenException()

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise InvalidTokenException()

    user = next(
        (
            existing_user
            for existing_user in user_db
            if existing_user.user_id == user_id
        ),
        None,
    )

    if user is None:
        raise InvalidTokenException()

    return payload, user

def authenticate_user(email: str, password: str) -> User:
    user = next(
        (
            existing_user
            for existing_user in user_db
            if existing_user.email == email
        ),
        None,
    )

    if user is None:
        raise InvalidAccountException()

    try:
        password_hasher.verify(
            user.hashed_password,
            password,
        )
    except (VerificationError, InvalidHashError):
        raise InvalidAccountException()

    return user

@auth_router.post("/token")
def create_token(request: LoginRequest) -> TokenResponse:
    user = authenticate_user(
        email=request.email,
        password=request.password,
    )

    return TokenResponse(
        access_token=create_jwt(
            user_id=user.user_id,
            lifespan_minutes=SHORT_SESSION_LIFESPAN,
            token_type="access",
        ),
        refresh_token=create_jwt(
            user_id=user.user_id,
            lifespan_minutes=LONG_SESSION_LIFESPAN,
            token_type="refresh",
        ),
    )

@auth_router.post("/token/refresh")
def refresh_token(
    authorization: Annotated[str | None, Header()] = None,
) -> TokenResponse:
    old_refresh_token = get_bearer_token(authorization)

    payload, user = decode_jwt(
        old_refresh_token,
        expected_type="refresh",
    )

    blocked_token_db[old_refresh_token] = payload["exp"]

    return TokenResponse(
        access_token=create_jwt(
            user_id=user.user_id,
            lifespan_minutes=SHORT_SESSION_LIFESPAN,
            token_type="access",
        ),
        refresh_token=create_jwt(
            user_id=user.user_id,
            lifespan_minutes=LONG_SESSION_LIFESPAN,
            token_type="refresh",
        ),
    )

@auth_router.delete("/token")
def delete_token(
    authorization: Annotated[str | None, Header()] = None,
) -> Response:
    refresh_token = get_bearer_token(authorization)

    payload, _ = decode_jwt(
        refresh_token,
        expected_type="refresh",
    )

    blocked_token_db[refresh_token] = payload["exp"]

    return Response(status_code=204)

@auth_router.post("/session")
def create_session(
    request: LoginRequest,
    response: Response,
):
    user = authenticate_user(
        email=request.email,
        password=request.password,
    )

    sid = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=LONG_SESSION_LIFESPAN
    )

    session_db[sid] = {
        "user_id": user.user_id,
        "expires_at": expires_at,
    }

    response.set_cookie(
        key="sid",
        value=sid,
        max_age=LONG_SESSION_LIFESPAN * 60,
        httponly=True,
        samesite="lax",
    )

    return {"message": "SESSION CREATED"}

@auth_router.delete("/session")
def delete_session(
    response: Response,
    sid: Annotated[str | None, Cookie()] = None,
) -> Response:
    if sid is not None:
        session_db.pop(sid, None)

    response.delete_cookie("sid")
    response.status_code = 204
    return response