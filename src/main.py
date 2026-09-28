from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from tests.util import get_all_src_py_files_hash
from src.api import api_router
from src.common import CustomException


app = FastAPI()

app.include_router(api_router)


@app.exception_handler(CustomException)
async def handle_custom_exception(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "error_msg": exc.error_message,
        },
    )


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    request: Request,
    exc: RequestValidationError,
):
    errors = exc.errors()

    if any(error["type"] == "missing" for error in errors):
        return JSONResponse(
            status_code=422,
            content={
                "error_code": "ERR_001",
                "error_msg": "MISSING VALUE",
            },
        )

    if request.url.path.rstrip("/") == "/api/users":
        field_errors = {
            "password": ("ERR_002", "INVALID PASSWORD"),
            "phone_number": ("ERR_003", "INVALID PHONE NUMBER"),
        }

        for error in errors:
            location = error.get("loc", ())
            field = location[-1] if location else None

            if field in field_errors:
                error_code, error_msg = field_errors[field]
                return JSONResponse(
                    status_code=422,
                    content={
                        "error_code": error_code,
                        "error_msg": error_msg,
                    },
                )

    return await request_validation_exception_handler(request, exc)

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }