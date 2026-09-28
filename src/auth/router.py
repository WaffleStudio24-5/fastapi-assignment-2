import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends, Cookie, Response, status

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import LoginRequest, TokenResponse
from src.auth.utils import authenticate, create_token, decode_token, get_bearer_token
from src.users.errors import InvalidTokenException

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

def issue_tokens(user_id: int) -> TokenResponse:
    return TokenResponse(
        access_token=create_token(user_id, SHORT_SESSION_LIFESPAN, "access"),
        refresh_token=create_token(user_id, LONG_SESSION_LIFESPAN, "refresh")
    )

def block_refresh_token(token: str) -> dict:
    payload = decode_token(token, "refresh")
    if token in blocked_token_db:
        raise InvalidTokenException()
    blocked_token_db[token] = payload["exp"]
    return payload

@auth_router.post("/token")
def create_token_pair(request: LoginRequest) -> TokenResponse:
    user = authenticate(request.email, request.password)
    return issue_tokens(user['user_id'])


@auth_router.post("/token/refresh")
def refresh_token(token: Annotated[str, Depends(get_bearer_token)]) -> TokenResponse:
    payload = block_refresh_token(token)
    return issue_tokens(int(payload["sub"]))


@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def delete_token(token: Annotated[str, Depends(get_bearer_token)]):
    block_refresh_token(token)


@auth_router.post("/session")
def create_session(request: LoginRequest, response: Response):
    user = authenticate(request.email, request.password)

    sid = secrets.token_urlsafe(32)
    session_db[sid] = {
        "user_id": user['user_id'],
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=LONG_SESSION_LIFESPAN)
    }
    response.set_cookie(
        key="sid",
        value=sid,
        max_age=LONG_SESSION_LIFESPAN * 60,
        httponly=True,
        samesite="lax"
    )


@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(
    response: Response,
    sid: Annotated[str | None, Cookie()] = None
):
    if sid is None:
        return
    session_db.pop(sid, None)
    response.delete_cookie(key="sid", httponly=True, samesite="lax")
