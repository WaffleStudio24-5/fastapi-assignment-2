import secrets
from datetime import datetime, timedelta, timezone
from threading import Lock

from fastapi import APIRouter, Cookie, Depends, Response

from src.auth.schemas import LoginRequest, TokenResponse
from src.auth.security import (
    authenticate_user,
    auth_error,
    create_jwt,
    decode_jwt,
    read_bearer_token,
)
from src.common.database import (
    blocked_token_db,
    session_db,
    user_db,
)

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

token_lock = Lock()


def issue_token_pair(user_id: int) -> TokenResponse:
    """새 access token과 refresh token을 발급합니다."""
    return TokenResponse(
        access_token=create_jwt(
            user_id=user_id,
            token_type="access",
            lifespan_minutes=SHORT_SESSION_LIFESPAN,
        ),
        refresh_token=create_jwt(
            user_id=user_id,
            token_type="refresh",
            lifespan_minutes=LONG_SESSION_LIFESPAN,
        ),
    )


def validate_refresh_token(token: str) -> dict:
    """refresh token의 유효성과 차단 여부를 확인합니다."""
    payload = decode_jwt(token, expected_type="refresh")

    if token in blocked_token_db:
        raise auth_error("ERR_008", "INVALID TOKEN")

    user_exists = any(
        str(user["user_id"]) == payload["sub"]
        for user in user_db
    )

    if not user_exists:
        raise auth_error("ERR_008", "INVALID TOKEN")

    return payload


@auth_router.post("/token")
def create_token(request: LoginRequest) -> TokenResponse:
    user = authenticate_user(
        email=request.email,
        password=request.password,
    )

    return issue_token_pair(user["user_id"])


@auth_router.post("/token/refresh")
def refresh_token(
    token: str = Depends(read_bearer_token),
) -> TokenResponse:
    with token_lock:
        payload = validate_refresh_token(token)

        new_tokens = issue_token_pair(int(payload["sub"]))

        blocked_token_db[token] = payload["exp"]

    return new_tokens


@auth_router.delete("/token", status_code=204)
def delete_token(
    token: str = Depends(read_bearer_token),
) -> Response:
    with token_lock:
        payload = validate_refresh_token(token)
        blocked_token_db[token] = payload["exp"]

    return Response(status_code=204)


@auth_router.post("/session")
def create_session(request: LoginRequest) -> Response:
    user = authenticate_user(
        email=request.email,
        password=request.password,
    )

    sid = secrets.token_urlsafe(32)

    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": (
            datetime.now(timezone.utc)
            + timedelta(minutes=LONG_SESSION_LIFESPAN)
        ),
    }

    response = Response(status_code=200)

    response.set_cookie(
        key="sid",
        value=sid,
        max_age=LONG_SESSION_LIFESPAN * 60,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )

    return response


@auth_router.delete("/session", status_code=204)
def delete_session(
    sid: str | None = Cookie(default=None),
) -> Response:
    if sid is not None:
        session_db.pop(sid, None)

    response = Response(status_code=204)

    response.delete_cookie(
        key="sid",
        path="/",
        httponly=True,
        secure=False,
        samesite="lax",
    )

    return response