from typing import Annotated
from datetime import datetime, timezone
import jwt

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status,
    Query,
    HTTPException
)

from fastapi.responses import JSONResponse

from src.auth.router import JWT_ALGORITHM , JWT_SECRET_KEY , password_hasher
from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db

user_router = APIRouter(prefix="/users", tags=["users"])

def error_response(status_code: int, error_code: str, error_msg: str):
    return JSONResponse(
        status_code=status_code,
        content={
            "error_code": error_code,
            "error_msg": error_msg,
        },
    )

def to_user_response(user: dict) -> UserResponse:
    return UserResponse(
        user_id=user["user_id"],
        name=user["name"],
        email=user["email"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user["bio"],
    )


def find_user_by_id(user_id: int) -> dict | None:
    return next(
        (user for user in user_db if user["user_id"] == user_id),
        None,
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


@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    if any(user["email"] == str(request.email) for user in user_db):
        return error_response(
            409,
            "ERR_005",
            "EMAIL ALREADY EXISTS",
        )

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

    return to_user_response(user)

@user_router.get("", response_model=list[UserResponse])
def get_users(
    min_height: float = Query(...),
    max_height: float = Query(...),
):
    return [
        to_user_response(user)
        for user in user_db
        if min_height <= user["height"] <= max_height
    ]

@user_router.get("/me", response_model=UserResponse)
def get_user_info(
    sid: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
):
    if sid is not None:
        session = session_db.get(sid)

        if (
            session is None
            or session["expires_at"] <= datetime.now(timezone.utc)
        ):
            session_db.pop(sid, None)
            return error_response(401, "ERR_006", "INVALID SESSION")

        user = find_user_by_id(session["user_id"])
        if user is None:
            return error_response(401, "ERR_006", "INVALID SESSION")

        return to_user_response(user)

    token = parse_bearer_token(authorization)

    if token is None:
        return error_response(401, "ERR_009", "UNAUTHENTICATED")

    if token is False:
        return error_response(400, "ERR_007", "BAD AUTHORIZATION HEADER")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        if payload.get("token_type") != "access":
            raise jwt.InvalidTokenError

        user = find_user_by_id(int(payload["sub"]))
        if user is None:
            raise jwt.InvalidTokenError

    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        return error_response(401, "ERR_008", "INVALID TOKEN")

    return to_user_response(user)


# Assignment 1 continued: get a user by id
@user_router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int):
    user = find_user_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="USER NOT FOUND",
        )

    return to_user_response(user)
