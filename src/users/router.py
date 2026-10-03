from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.users.errors import (
    EmailAlreadyExistsException, 
    InvalidSessionException, 
    BadAuthorizationHeaderException,
    InvalidTokenException,
    UnauthenticatedException)
from src.common.database import blocked_token_db, session_db, user_db
from pwdlib import PasswordHash
from jwt import decode, InvalidTokenError

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    if any(user["email"] == request.email for user in user_db):
        raise EmailAlreadyExistsException()

    user_id = len(user_db)+1
    password_hash = PasswordHash.recommended()
    hashed_password = password_hash.hash(request.password)

    user_db.append({
            "user_id":user_id,
            "email":request.email,
            "hashed_password":hashed_password,
            "name":request.name,
            "phone_number":request.phone_number,
            "height":request.height,
            "bio":request.bio
        }
    )

    return UserResponse(
        user_id=user_id,
        name=request.name,
        email=request.email,
        phone_number=request.phone_number,
        bio=request.bio,
        height=request.height
    )

def get_current_user(
    sid: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None)
    ):
    # 세션 검증
    if sid is not None:
        session = session_db.get(sid)
        if session is None or session["expires_at"] <= datetime.now(timezone.utc):
            raise InvalidSessionException()
        
        user_id = session["user_id"]
        return next(user for user in user_db if user["user_id"]==user_id)
    
    # 토큰 검증
    if authorization is not None:
        auth = authorization.split()
        if len(auth) != 2 or auth[0] != "Bearer":
            raise BadAuthorizationHeaderException()
        
        try:
            payload = decode(
                auth[1],
                "SECRET_KEY",
                algorithms=["HS256"],
            )
            user_id=int(payload["sub"])
        except (InvalidTokenError, KeyError, ValueError):
            raise InvalidTokenException()
        
        return next(user for user in user_db if user["user_id"] == user_id)
    


    raise UnauthenticatedException()


@user_router.get("/me", status_code=status.HTTP_200_OK)
def get_user_info(
    user: Annotated[dict, Depends(get_current_user)]
    ) -> UserResponse:
    return UserResponse(
        user_id=user["user_id"],
        name=user["name"],
        email=user["email"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user["bio"],
    )
