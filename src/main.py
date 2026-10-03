from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from src.common import CustomException
from src.users.errors import MissingValueException

from tests.util import get_all_src_py_files_hash
from src.api import api_router

app = FastAPI()

app.include_router(api_router)

# 요청 본문이 Pydantic 모델 검증에 실패했을 때(필수값 누락/자료형 틀림 등)
# FastAPI가 자동으로 발생시키는 에러
@app.exception_handler(RequestValidationError)
# request: 에러를 일으킨 요청 정보(주소,헤더,..)
# exc: 발생한 에러 객체(exception의 줄임말)
# exc.__: 에러 안의 값을 꺼내는 것
# error handle하는 함수를 2개 만드는 이유
# RequestValidationError: FastAPI가 기본 제공; 안에 든 값: 에러 목록 (exc.errors())
    # handle_custom_exception처럼 exc.error_code를 꺼내 쓸 수가 없음
    # 대신 "이 에러가 오면 ERR_001로 바꿔서 응답하자"고 번역해주는 별도 핸들러가 필요
# CustomException: 우리가 만듦; 안에 든 값: status_code, error_code, error_message
# (비유) 입구 2개, 출구 1개
    # 입구 1: FastAPI 에러 → handle_request_validation_error가 ERR_001로 번역
    # 입구 2: 우리 에러 → handle_custom_exception이 바로 처리
def handle_request_validation_error(request, exc):
    return handle_custom_exception(request, MissingValueException())

@app.exception_handler(CustomException)
def handle_custom_exception(request, exc):
    # status_code: HTTP 상태코드(422,409,..)
    # content: 응답 본문 JSON 형식으로 출력됨
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "error_msg": exc.error_message,
        },
    )

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }