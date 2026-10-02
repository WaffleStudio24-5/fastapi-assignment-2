from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from tests.util import get_all_src_py_files_hash
from src.api import api_router

app = FastAPI()

app.include_router(api_router)

@app.exception_handler(RequestValidationError)
def handle_request_validation_error(request : Request, exc:RequestValidationError):
    error_type = exc.errors()[0]["type"]
    
    error_map = {
        "invalid_password": ("ERR_002", "INVALID PASSWORD"),
        "invalid_phone_number": ("ERR_003", "INVALID PHONE NUMBER"),
        "bio_too_long": ("ERR_004", "BIO TOO LONG"),
    }

    error_code , error_msg = error_map.get(
        error_type,
        ("ERR_001", "MISSING VALUE")
    )

    return JSONResponse(
        status_code=422,
        content={
            "error_code":error_code,
            "error_msg":error_msg
        }
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