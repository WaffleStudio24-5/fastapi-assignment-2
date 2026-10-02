from datetime import datetime, timedelta, timezone
import secrets

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import APIRouter
from fastapi import Depends, Cookie , Header , Response
from fastapi.responses import JSONResponse

from src.auth.schemas import LoginRequest, TokenResponse
from src.common.database import blocked_token_db, session_db, user_db

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

JWT_SECRET_KEY = "seng-yee-secret-key"
JWT_ALGORITHM = "HS256"

password_hasher = PasswordHasher()

def error_response(status_code: int, error_code: str, error_msg: str):
    return JSONResponse(
        status_code=status_code,
        content={
            "error_code": error_code,
            "error_msg": error_msg,
        },
    )

def parse_bearer_token(authorization: str | None):
    if authorization is None:
        return None

    scheme, separator, token = authorization.partition(" ")

    if (
        scheme != "Bearer"
        or not separator
        or not token
        or " " in token
    ):
        return False

    return token

def find_user_by_email(email: str):
    return next((user for user in user_db if user["email"] == email), None)


def authenticate(email: str, password: str):
    user = find_user_by_email(email)

    if user is None:
        return None

    try:
        password_hasher.verify(user["hashed_password"], password)
    except VerificationError:
        return None

    return user


def create_tokens(user_id: int) -> dict[str, str]:
    now = datetime.now(timezone.utc)

    access_token = jwt.encode(
        {
            "sub": str(user_id),
            "exp": now + timedelta(minutes=SHORT_SESSION_LIFESPAN),
            "token_type": "access",
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    refresh_token = jwt.encode(
        {
            "sub": str(user_id),
            "exp": now + timedelta(minutes=LONG_SESSION_LIFESPAN),
            "token_type": "refresh",
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


def decode_refresh_token(token: str):
    if token in blocked_token_db:
        raise jwt.InvalidTokenError

    payload = jwt.decode(
        token,
        JWT_SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
    )

    if payload.get("token_type") != "refresh":
        raise jwt.InvalidTokenError

    user_id = int(payload["sub"])

    if not any(user["user_id"] == user_id for user in user_db):
        raise jwt.InvalidTokenError

    return payload




@auth_router.post("/token")
def create_token(request: LoginRequest):
    user = authenticate(str(request.email), request.password)

    if user is None:
        return error_response(401, "ERR_010", "INVALID ACCOUNT")

    return create_tokens(user["user_id"])


@auth_router.post("/token/refresh")
def refresh_token(authorization: str | None = Header(default=None)):
    token = parse_bearer_token(authorization)

    if token is None:
        return error_response(401, "ERR_009", "UNAUTHENTICATED")

    if token is False:
        return error_response(400, "ERR_007", "BAD AUTHORIZATION HEADER")

    try:
        payload = decode_refresh_token(token)
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return error_response(401, "ERR_008", "INVALID TOKEN")

    blocked_token_db[token] = payload["exp"]
    return create_tokens(int(payload["sub"]))


@auth_router.delete("/token" , status_code=204)
def delete_token(authorization: str | None = Header(default=None)):
    token = parse_bearer_token(authorization)

    if token is None:
        return error_response(401, "ERR_009", "UNAUTHENTICATED")

    if token is False:
        return error_response(400, "ERR_007", "BAD AUTHORIZATION HEADER")

    try:
        payload = decode_refresh_token(token)
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return error_response(401, "ERR_008", "INVALID TOKEN")

    blocked_token_db[token] = payload["exp"]
    return Response(status_code=204)


@auth_router.post("/session")
def create_session(request: LoginRequest):
    user = authenticate(str(request.email), request.password)

    if user is None:
        return error_response(401, "ERR_010", "INVALID ACCOUNT")

    sid = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=LONG_SESSION_LIFESPAN
    )

    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": expires_at,
    }

    response = Response(status_code=200)
    response.set_cookie(
        key="sid",
        value=sid,
        max_age=LONG_SESSION_LIFESPAN * 60,
        httponly=True,
        samesite="lax",
    )
    return response


@auth_router.delete("/session" ,  status_code=204)
def delete_session(sid: str | None = Cookie(default=None)):
    response = Response(status_code=204)

    if sid is not None:
        session_db.pop(sid, None)
        response.delete_cookie("sid")

    return response
