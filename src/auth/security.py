import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Cookie, Header

from src.common import CustomException
from src.common.database import session_db, user_db


ALGORITHM = "HS256"

SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_urlsafe(32)

password_hasher = PasswordHasher()


def auth_error(
    error_code: str,
    error_message: str,
    status_code: int = 401,
) -> CustomException:
    return CustomException(
        status_code=status_code,
        error_code=error_code,
        error_message=error_message,
    )


def authenticate_user(email: str, password: str) -> dict:
    user = next(
        (user for user in user_db if user["email"] == email),
        None,
    )

    if user is None:
        raise auth_error("ERR_010", "INVALID ACCOUNT")

    try:
        password_hasher.verify(user["hashed_password"], password)
    except (VerificationError, InvalidHashError):
        raise auth_error("ERR_010", "INVALID ACCOUNT") from None

    return user


def create_jwt(
    user_id: int,
    token_type: str,
    lifespan_minutes: int,
) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=lifespan_minutes
    )

    payload = {
        "sub": str(user_id),
        "exp": expires_at,
        "type": token_type,
        "jti": str(uuid4()),
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_jwt(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp", "type"]},
        )
    except jwt.InvalidTokenError:
        raise auth_error("ERR_008", "INVALID TOKEN") from None

    if payload["type"] != expected_type:
        raise auth_error("ERR_008", "INVALID TOKEN")

    if not isinstance(payload["sub"], str):
        raise auth_error("ERR_008", "INVALID TOKEN")

    return payload


def read_bearer_token(
    authorization: str | None = Header(default=None),
) -> str:
    if authorization is None:
        raise auth_error("ERR_009", "UNAUTHENTICATED")

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise auth_error(
            "ERR_007",
            "BAD AUTHORIZATION HEADER",
            status_code=400,
        )

    return parts[1]


def get_current_user(
    authorization: str | None = Header(default=None),
    sid: str | None = Cookie(default=None),
) -> dict:
    if authorization is not None:
        token = read_bearer_token(authorization)
        payload = decode_jwt(token, expected_type="access")

        user = next(
            (
                user
                for user in user_db
                if str(user["user_id"]) == payload["sub"]
            ),
            None,
        )

        if user is None:
            raise auth_error("ERR_008", "INVALID TOKEN")

        return user

    if sid is not None:
        session = session_db.get(sid)

        if session is None:
            raise auth_error("ERR_006", "INVALID SESSION")

        if session["expires_at"] <= datetime.now(timezone.utc):
            session_db.pop(sid, None)
            raise auth_error("ERR_006", "INVALID SESSION")

        user = next(
            (
                user
                for user in user_db
                if user["user_id"] == session["user_id"]
            ),
            None,
        )

        if user is None:
            raise auth_error("ERR_006", "INVALID SESSION")

        return user

    raise auth_error("ERR_009", "UNAUTHENTICATED")