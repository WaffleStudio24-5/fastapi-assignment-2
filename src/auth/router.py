from fastapi import APIRouter
from fastapi import Depends, Cookie, Header, Response
from src.auth.schemas import LoginRequest
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from src.auth.errors import (
    InvalidAccountException,
    UnauthenticatedException,
    BadAuthorizationHeaderException,
    InvalidTokenException,
)
from datetime import datetime, timedelta, timezone
import secrets
import jwt

from src.common.database import blocked_token_db, session_db, user_db

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60
JWT_SECRET_KEY = secrets.token_urlsafe(32)

@auth_router.post("/token")
def create_token(request: LoginRequest):
    user = next(
        (item for item in user_db if item["email"] == str(request.email)),
        None,
    )
    if user is None:
        raise InvalidAccountException()

    try:
        PasswordHasher().verify(user["hashed_password"], request.password)
    except (VerificationError, InvalidHashError):
        raise InvalidAccountException()
    
    now = datetime.now(timezone.utc)
    subject = str(user["user_id"])

    access_token = jwt.encode(
        {
            "sub": subject,
            "exp": now + timedelta(minutes=SHORT_SESSION_LIFESPAN),
            "token_type": "access",
        },
        JWT_SECRET_KEY,
        algorithm="HS256",
    )
    refresh_token = jwt.encode(
        {
            "sub": subject,
            "exp": now + timedelta(minutes=LONG_SESSION_LIFESPAN),
            "token_type": "refresh",
            "jti": secrets.token_hex(16),
        },
        JWT_SECRET_KEY,
        algorithm="HS256",
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@auth_router.post("/token/refresh")
def refresh_token(authorization: str | None = Header(default=None)):
    if authorization is None:
        raise UnauthenticatedException()
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

    if payload.get("token_type") != "refresh":
        raise InvalidTokenException()
    if token in blocked_token_db:
        raise InvalidTokenException()
    if not any(str(user["user_id"]) == payload["sub"] for user in user_db):
        raise InvalidTokenException()

    blocked_token_db[token] = payload["exp"]

    now = datetime.now(timezone.utc)
    subject = payload["sub"]

    access_token = jwt.encode(
        {
            "sub": subject,
            "exp": now + timedelta(minutes=SHORT_SESSION_LIFESPAN),
            "token_type": "access",
            "jti": secrets.token_hex(16),
        },
        JWT_SECRET_KEY,
        algorithm="HS256",
    )
    new_refresh_token = jwt.encode(
        {
            "sub": subject,
            "exp": now + timedelta(minutes=LONG_SESSION_LIFESPAN),
            "token_type": "refresh",
            "jti": secrets.token_hex(16),
        },
        JWT_SECRET_KEY,
        algorithm="HS256",
    )
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
    }

@auth_router.delete("/token", status_code=204)
def delete_token(authorization: str | None = Header(default=None)):
    if authorization is None:
        raise UnauthenticatedException()

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

    if payload.get("token_type") != "refresh" or token in blocked_token_db:
        raise InvalidTokenException()
    if not any(str(user["user_id"]) == payload["sub"] for user in user_db):
        raise InvalidTokenException()

    blocked_token_db[token] = payload["exp"]


@auth_router.post("/session")
def create_session(request: LoginRequest, response: Response):
    user = next(
        (item for item in user_db if item["email"] == str(request.email)),
        None,
    )
    if user is None:
        raise InvalidAccountException()

    try:
        PasswordHasher().verify(user["hashed_password"], request.password)
    except (VerificationError, InvalidHashError):
        raise InvalidAccountException()
    
    sid = secrets.token_urlsafe(32)
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": datetime.now(timezone.utc)
        + timedelta(minutes=LONG_SESSION_LIFESPAN),
    }
    response.set_cookie(key="sid", value=sid, httponly=True)


@auth_router.delete("/session", status_code=204)
def delete_session(
    response: Response,
    sid: str | None = Cookie(default=None),
):
    if sid is not None:
        session_db.pop(sid, None)
        response.delete_cookie(key="sid")
