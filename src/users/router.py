from fastapi import APIRouter, Cookie, Header, status
from argon2 import PasswordHasher

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import user_db
from src.users.errors import EmailAlreadyExistsException
from src.auth.errors import UnauthenticatedException
# 토큰/세션 검사 로직은 auth/router.py의 도우미 함수로 옮겨서 재사용
from src.auth.router import get_user_by_token, get_user_by_session

user_router = APIRouter(prefix="/users", tags=["users"])

ph = PasswordHasher()


# 1-1) 회원 가입
@user_router.post("", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    # 이메일 중복 확인
    for user in user_db:
        if user["email"] == request.email:
            raise EmailAlreadyExistsException()

    # 비밀번호는 단방향 암호화(해싱)해서 저장
    hashed_password = ph.hash(request.password)

    # user_id: 지금 회원 수 + 1
    user_id = len(user_db) + 1

    new_user = {
        "user_id": user_id,
        "email": request.email,
        "hashed_password": hashed_password,
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio,
    }

    user_db.append(new_user)

    # -> UserResponse 덕분에 hashed_password는 응답에서 자동으로 빠짐
    return new_user


# 1-2) 내 정보 조회
@user_router.get("/me")
# authorization
    # FastAPI가 요청 헤더 중 Authorization이라는 이름을 찾아서
    # 여기에 넣어줌. 변수 이름이 헤더 이름과 연결되는 것
# str | None
    # 헤더가 있으면 문자열, 없으면 None
# Header(default=None)
    # "이건 헤더에서 꺼내고, 없으면 None으로 해줘"라는 뜻
# sid: 쿠키 중 이름이 sid인 것을 꺼내줌 (없으면 None)
def get_user_info(
    authorization: str | None = Header(default=None),
    sid: str | None = Cookie(default=None),
) -> UserResponse:
    # 토큰이 있으면 토큰 방식
    if authorization is not None:
        return get_user_by_token(authorization)

    # 토큰은 없고 쿠키가 있으면 세션 방식
    if sid is not None:
        return get_user_by_session(sid)

    # 둘 다 없으면 신분 증명 없이 요청한 것 -> ERR_009
    raise UnauthenticatedException()