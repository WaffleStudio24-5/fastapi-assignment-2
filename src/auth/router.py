import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
# VerifyMismatchError: argon2가 "비밀번호가 틀렸다"고 알려줄 때 쓰는 에러 클래스
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Cookie, Header, Response, status

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import LoginRequest
from src.auth.errors import (
    InvalidAccountException,
    InvalidSessionException,
    BadAuthorizationHeaderException,
    InvalidTokenException,
    UnauthenticatedException,
)

auth_router = APIRouter(prefix="/auth", tags=["auth"])

# 해셔 만들기
# ph: 해싱 도구 그 자체
ph = PasswordHasher()

SHORT_SESSION_LIFESPAN = 15       # Access Token 유효시간 15분
LONG_SESSION_LIFESPAN = 24 * 60   # Refresh Token과 세션 유효 시간 1440분(하루)

SECRET_KEY = "waffle-fastapi-assignment2-secret-key-2026"
ALGORITHM = "HS256"


# ===== 재사용하는 도우미 함수들 =====

# user_id로 회원 찾기 (없으면 None)
def find_user_by_id(user_id):
    for user in user_db:
        if user["user_id"] == user_id:
            return user
    return None


# 이 사람이 진짜 회원인지 확인 (토큰 로그인, 세션 로그인 둘 다 사용)
def authenticate_user(email, password):
    found_user = None  # 회원을 기억해둘 빈 상자

    # 이메일로 회원 찾기
    for user in user_db:
        if user["email"] == email:
            found_user = user  # 회원 정보 전체가 담기도록

    # 없으면 -> 에러로 끝
    if found_user is None:
        raise InvalidAccountException()

    # 있으면 -> 비밀번호 확인
    try:
        # ph.verify: 맞으면 -> 조용히 넘어감 / 틀리면 -> VerifyMismatchError 발생
        # 순서 주의: (저장된 해시, 입력한 평문)
        ph.verify(found_user["hashed_password"], password)
    except VerifyMismatchError:
        raise InvalidAccountException()

    return found_user


# JWT 토큰 하나 만들기
def create_jwt(user_id, minutes):
    # 토큰에 적을 내용: 누구의 토큰인지(sub) + 언제 만료되는지(exp)
    payload = {
        "sub": str(user_id),  # pyjwt는 sub가 반드시 문자열이어야 함
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes),
        # jti: 토큰마다 고유한 값. 같은 초에 만들어도 토큰이 겹치지 않게 함
        "jti": uuid.uuid4().hex,
    }
    # 비밀 키로 서명(위조 방지 도장)해서 토큰 문자열 만들기
    # encode: 도장을 '하나' 골라서 찍는 것 -> algorithm (단수)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# Access Token(15분) + Refresh Token(하루) 한 쌍 발급
def issue_tokens(user_id):
    return {
        "access_token": create_jwt(user_id, SHORT_SESSION_LIFESPAN),
        "refresh_token": create_jwt(user_id, LONG_SESSION_LIFESPAN),
    }


# Authorization 헤더에서 토큰만 꺼내기
def extract_bearer_token(authorization):
    # 헤더가 아예 없음: UnauthenticatedException (ERR_009)
    if authorization is None:
        raise UnauthenticatedException()

    # 헤더 형식 검사; "Bearer" + 띄어쓰기 한 칸 + 토큰
    # split(): 문자열을 띄어쓰기 기준으로 잘라서 리스트로 만들어줌
    parts = authorization.split(" ")

    # 헤더는 있는데 모양이 이상함: BadAuthorizationHeaderException (ERR_007)
    if len(parts) != 2 or parts[0] != "Bearer":
        raise BadAuthorizationHeaderException()

    # 토큰만 꺼내기
    return parts[1]


# 토큰이 진짜인지/만료되지 않았는지 확인
def decode_token(token):
    # 블랙리스트(로그아웃·갱신된 토큰)에 있으면 무효
    if token in blocked_token_db:
        raise InvalidTokenException()

    # jwt.decode: 두 가지를 자동으로 검사해줌
        # 서명이 SECRET_KEY로 찍힌 게 맞는지 (위조·변조 확인)
        # exp가 지나지 않았는지 (만료 확인)
    try:
        # decode: '이 도장들만 인정할게'라는 허용 목록 -> algorithms (복수, 리스트)
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    # jwt.InvalidTokenError: 위조, 변조, 만료 등 토큰이 잘못된 모든 경우를 잡아줌
    except jwt.InvalidTokenError:
        raise InvalidTokenException()


# 토큰 방식: 헤더 -> 토큰 -> 해독 -> 회원 찾기
def get_user_by_token(authorization):
    token = extract_bearer_token(authorization)
    payload = decode_token(token)

    # sub는 문자열로 넣었으니 int()로 다시 숫자로 바꿔야 user_db와 비교 가능
    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError):
        raise InvalidTokenException()

    # 토큰은 진짜인데 회원이 없으면 쓸 수 없는 토큰 -> ERR_008
    user = find_user_by_id(user_id)
    if user is None:
        raise InvalidTokenException()
    return user


# 세션 방식: sid -> 세션 존재 확인 -> 만료 확인 -> 회원 찾기
def get_user_by_session(sid):
    session = session_db.get(sid)  # 없으면 None
    if session is None:
        raise InvalidSessionException()

    # 만료됐으면 서버 쪽 세션도 지우고 에러
    if datetime.now(timezone.utc) > session["expires_at"]:
        session_db.pop(sid, None)
        raise InvalidSessionException()

    user = find_user_by_id(session["user_id"])
    if user is None:
        raise InvalidSessionException()
    return user


# ===== 엔드포인트 =====

# 2-1) 로그인 및 토큰 발급
@auth_router.post("/token")
def create_token(request: LoginRequest):
    user = authenticate_user(request.email, request.password)
    return issue_tokens(user["user_id"])


# 2-2) 토큰 갱신: refresh token 검증 후 새 토큰 한 쌍 발급
@auth_router.post("/token/refresh")
def refresh_token(authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    payload = decode_token(token)

    user = find_user_by_id(int(payload["sub"]))
    if user is None:
        raise InvalidTokenException()

    # 기존 refresh token은 블랙리스트에 (key: 토큰 원문, value: 원래 만료 시점)
    blocked_token_db[token] = payload["exp"]
    return issue_tokens(user["user_id"])


# 2-3) 토큰 무효화(로그아웃): 블랙리스트에 넣어 재사용 방지, 성공 시 204
@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def delete_token(authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    payload = decode_token(token)
    blocked_token_db[token] = payload["exp"]


# 3-1) 세션 로그인: 세션을 만들고 sid를 쿠키로 설정
@auth_router.post("/session")
def create_session(request: LoginRequest, response: Response):
    user = authenticate_user(request.email, request.password)

    # 추측하기 어려운 랜덤 문자열로 세션 ID 만들기
    sid = secrets.token_urlsafe(32)
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=LONG_SESSION_LIFESPAN),
    }

    # max_age는 초 단위라서 분 * 60
    # httponly=True: 브라우저의 자바스크립트가 쿠키를 못 읽게 막음 (보안)
    response.set_cookie(key="sid", value=sid, max_age=LONG_SESSION_LIFESPAN * 60, httponly=True)


# 3-2) 세션 로그아웃: 쿠키 만료 + 서버 세션 삭제, 항상 204
@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(response: Response, sid: str | None = Cookie(default=None)):
    if sid is not None:
        response.delete_cookie("sid")   # 클라이언트 쿠키 만료
        session_db.pop(sid, None)       # 서버 세션 삭제 (없어도 에러 안 남)