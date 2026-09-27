from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import APIRouter, Cookie, Header, Response, status

from src.auth.errors import (
    BadAuthorizationHeaderException,
    InvalidAccountException,
    InvalidTokenException,
    UnauthenticatedException,
)
from src.auth.schemas import LoginRequest, TokenResponse
from src.common.database import blocked_token_db, session_db, user_db


auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

SECRET_KEY = "fastapi-assignment-2-secret-key"
ALGORITHM = "HS256"
password_hasher = PasswordHasher()


def authenticate_user(request: LoginRequest) -> dict:
    user = next(
        (user for user in user_db if user["email"] == str(request.email)),
        None,
    )

    if user is None:
        raise InvalidAccountException()

    try:
        password_hasher.verify(user["hashed_password"], request.password)
    except VerificationError:
        raise InvalidAccountException()

    return user


def create_token_pair(user_id: int) -> TokenResponse:
    now = datetime.now(timezone.utc)

    access_token = jwt.encode(
        {
            "sub": str(user_id),
            "exp": now + timedelta(minutes=SHORT_SESSION_LIFESPAN),
            "token_type": "access",
            "jti": str(uuid4()),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    refresh_token = jwt.encode(
        {
            "sub": str(user_id),
            "exp": now + timedelta(minutes=LONG_SESSION_LIFESPAN),
            "token_type": "refresh",
            "jti": str(uuid4()),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


def get_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise UnauthenticatedException()

    parts = authorization.split(" ")

    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise BadAuthorizationHeaderException()

    return parts[1]


def decode_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp", "token_type"]},
        )
    except jwt.PyJWTError:
        raise InvalidTokenException()

    if payload["token_type"] != "refresh" or token in blocked_token_db:
        raise InvalidTokenException()

    return payload


@auth_router.post("/token", response_model=TokenResponse)
def create_token(request: LoginRequest) -> TokenResponse:
    user = authenticate_user(request)
    return create_token_pair(user["user_id"])


@auth_router.post("/token/refresh", response_model=TokenResponse)
def refresh_token(
    authorization: str | None = Header(default=None),
) -> TokenResponse:
    token = get_bearer_token(authorization)
    payload = decode_refresh_token(token)

    blocked_token_db[token] = payload["exp"]

    return create_token_pair(int(payload["sub"]))


@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def delete_token(
    authorization: str | None = Header(default=None),
) -> Response:
    token = get_bearer_token(authorization)
    payload = decode_refresh_token(token)

    blocked_token_db[token] = payload["exp"]

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@auth_router.post("/session", status_code=status.HTTP_200_OK)
def create_session(request: LoginRequest) -> Response:
    user = authenticate_user(request)

    sid = token_urlsafe(32)
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": datetime.now(timezone.utc)
        + timedelta(minutes=LONG_SESSION_LIFESPAN),
    }

    response = Response(status_code=status.HTTP_200_OK)
    response.set_cookie(key="sid", value=sid, httponly=True)

    return response


@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(
    sid: str | None = Cookie(default=None),
) -> Response:
    if sid is not None:
        session_db.pop(sid, None)

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(key="sid")

    return response

