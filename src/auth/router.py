from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Header, status, Response, Cookie

from src.common.database import blocked_token_db, session_db, user_db
import jwt 
from src.auth.schemas import LoginRequest
from src.users.errors import (
    InvalidAccountException,
    InvalidTokenException,
    BadAuthorizationHeaderException,
    UnauthenticatedException
    )
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

@auth_router.post("/token", status_code=status.HTTP_200_OK)
def create_token(request: LoginRequest):

    #find the user who has the email in request
    user = next(
        (user for user in user_db if user["email"] == request.email),
        None
    )

    if user is None or not password_hash.verify(
        request.password,
        user["hashed_password"]
    ):
        raise InvalidAccountException()

    now = datetime.now(timezone.utc)

    # 토큰 따로 만들고 dict로 둘 다 반환
    access_token = jwt.encode(
        {
            "sub": str(user["user_id"]),
            "exp": now + timedelta(minutes=SHORT_SESSION_LIFESPAN),
        },
        "SECRET_KEY",
        algorithm="HS256",
    )
    refresh_token = jwt.encode(
        {
            "sub": str(user["user_id"]),
            "exp": now + timedelta(minutes=LONG_SESSION_LIFESPAN),
        },
        "SECRET_KEY",
        algorithm="HS256",
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@auth_router.post("/token/refresh")
def refresh_token(authorization: str | None = Header(default=None)):
    # authorization이 맞는지 검토
    if authorization is None:
        raise UnauthenticatedException()
    
    auth = authorization.split()
    if len(auth) != 2 or auth[0] != "Bearer":
        raise BadAuthorizationHeaderException()
    try:
        payload = jwt.decode(
            auth[1],
            "SECRET_KEY",
            algorithms=["HS256"],
        )
        user_id=int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise InvalidTokenException()
    
    # check that token in blocke_token_db
    token = auth[1]
    if token in blocked_token_db:
        raise InvalidTokenException()
    else:
        blocked_token_db[token] = payload["exp"]

    # regenerate access & refresh Token
    now = datetime.now(timezone.utc)

    accessToken = jwt.encode(
        {
            "sub": str(user_id),
            "exp": now + timedelta(minutes=SHORT_SESSION_LIFESPAN),
        },
        "SECRET_KEY",
        algorithm="HS256",
    )
    refreshToken = jwt.encode(
        {
            "sub": str(user_id),
            "exp": now + timedelta(minutes=LONG_SESSION_LIFESPAN),
        },
        "SECRET_KEY",
        algorithm="HS256",
    )

    return {
        "access_token": accessToken,
        "refresh_token": refreshToken,
    }


@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def delete_token(authorization: str | None = Header(default=None)):
    # authorization이 맞는지 검토
    if authorization is None:
        raise UnauthenticatedException()

    auth = authorization.split()
    if len(auth) != 2 or auth[0] != "Bearer":
        raise BadAuthorizationHeaderException()
    try:
        payload = jwt.decode(
            auth[1],
            "SECRET_KEY",
            algorithms=["HS256"],
        )
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise InvalidTokenException()
    
    token = auth[1]
    blocked_token_db[token] = payload["exp"]

    return 0


@auth_router.post("/session", status_code=status.HTTP_200_OK)
def create_session(response: Response, request: LoginRequest):
    #find the user who has the email in request
    user = next(
        (user for user in user_db if user["email"] == request.email),
        None
    )

    if user is None or not password_hash.verify(
        request.password,
        user["hashed_password"]
    ):
        raise InvalidAccountException()

    #make sid
    sid = uuid4().hex
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=LONG_SESSION_LIFESPAN
    )
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": expires_at,
    }

    response.set_cookie(
        key="sid",
        value=sid,
        max_age=LONG_SESSION_LIFESPAN * 60,
    )
    

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(
    response: Response,
    sid: str | None = Cookie(default=None),
):
    if sid is not None:
        session_db.pop(sid, None)
        response.delete_cookie(key="sid")
