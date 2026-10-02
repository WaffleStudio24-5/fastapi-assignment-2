from collections.abc import Callable, Generator

import pytest
from fastapi.testclient import TestClient

from src.common.database import blocked_token_db, session_db, user_db
from src.main import app


UserFactory = Callable[..., tuple[dict, dict]]


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    blocked_token_db.clear()
    session_db.clear()
    user_db.clear()

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client

    blocked_token_db.clear()
    session_db.clear()
    user_db.clear()


@pytest.fixture
def user_factory(client: TestClient) -> UserFactory:
    sequence = 0

    def create_user(**overrides) -> tuple[dict, dict]:
        nonlocal sequence
        sequence += 1

        request = {
            "name": f"김와플{sequence}",
            "email": f"student{sequence}@wafflestudio.com",
            "password": "password000",
            "height": 170.0 + sequence,
            "phone_number": f"010-1234-{sequence:04d}",
        }
        request.update(overrides)

        response = client.post("/api/users", json=request)
        assert response.status_code == 201, response.text
        return request, response.json()

    return create_user


def record_to_dict(record) -> dict:
    if isinstance(record, dict):
        return record
    if hasattr(record, "model_dump"):
        return record.model_dump()
    if hasattr(record, "dict"):
        return record.dict()
    return vars(record)


def find_user_by_email(email: str) -> dict:
    for record in user_db:
        user = record_to_dict(record)
        if user.get("email") == email:
            return user
    raise AssertionError(f"user_db에 {email!r} 사용자가 저장되지 않았습니다.")


def assert_error(response, status_code: int, error_code: str, error_msg: str) -> None:
    assert response.status_code == status_code, response.text
    assert response.json() == {
        "error_code": error_code,
        "error_msg": error_msg,
    }
