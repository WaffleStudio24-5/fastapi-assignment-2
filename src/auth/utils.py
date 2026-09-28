import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Cookie, Header

from src.common.database import session_db, user_db
from src.users.errors import (
    BadAuthorizationHeaderException,
    InvalidAccountException,
    InvalidSessionException,
    InvalidTokenException,
    UnauthenticatedException
)

SECRET_KEY = os.getenv("SECRET_KEY", "waffle-fastapi-seminar-secret")
ALGORITHM = "HS256"

ph = PasswordHasher(
    memory_cost=65536,
    time_cost=3,
    parallelism=4
)

def find_user_by_email(email: str) -> dict | None:
    for user in user_db:
        if user['email'] == email:
            return user
    return None

def find_user_by_id(user_id: int) -> dict | None:
    for user in user_db:
        if user['user_id'] == user_id:
            return user
    return None

def authenticate(email: str, password: str) -> dict:
    user = find_user_by_email(email)
    if user is None:
        raise InvalidAccountException()
    try:
        ph.verify(user['hashed_password'], password)
    except VerificationError:
        raise InvalidAccountException()
    return user

def create_token(user_id: int, lifespan: int, token_type: str) -> str:
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "jti": uuid.uuid4().hex,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=lifespan)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str, token_type: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp"]}
        )
    except jwt.InvalidTokenError:
        raise InvalidTokenException()

    if payload.get("type") != token_type:
        raise InvalidTokenException()
    return payload

def parse_bearer(authorization: str) -> str:
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise BadAuthorizationHeaderException()
    return parts[1]

def get_bearer_token(
    authorization: Annotated[str | None, Header()] = None
) -> str:
    if authorization is None:
        raise UnauthenticatedException()
    return parse_bearer(authorization)

def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    sid: Annotated[str | None, Cookie()] = None
) -> dict:
    if authorization is not None:
        token = parse_bearer(authorization)
        payload = decode_token(token, "access")
        user = find_user_by_id(int(payload["sub"]))
        if user is None:
            raise InvalidTokenException()
        return user

    if sid is not None:
        session = session_db.get(sid)
        if session is None:
            raise InvalidSessionException()
        if session["expires_at"] <= datetime.now(timezone.utc):
            del session_db[sid]
            raise InvalidSessionException()
        return find_user_by_id(session["user_id"])

    raise UnauthenticatedException()
