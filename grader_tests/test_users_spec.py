import pytest
from fastapi.testclient import TestClient

from grader_tests.conftest import (
    UserFactory,
    assert_error,
    find_user_by_email,
)


def test_password_is_hashed_before_storing(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory(password="plain-password")
    stored_user = find_user_by_email(request["email"])

    assert "password" not in stored_user
    assert isinstance(stored_user.get("hashed_password"), str)
    assert stored_user["hashed_password"] != request["password"]
    assert request["password"] not in stored_user["hashed_password"]

    login_response = client.post(
        "/api/auth/token",
        json={"email": request["email"], "password": request["password"]},
    )
    assert login_response.status_code == 200, login_response.text


@pytest.mark.parametrize(
    "missing_field",
    ["name", "email", "password", "phone_number", "height"],
)
def test_create_user_rejects_each_missing_required_field(
    client: TestClient,
    missing_field: str,
) -> None:
    request = {
        "name": "김와플",
        "email": "required@wafflestudio.com",
        "password": "password000",
        "phone_number": "010-1234-5678",
        "height": 175.0,
    }
    request.pop(missing_field)

    response = client.post("/api/users", json=request)
    assert_error(response, 422, "ERR_001", "MISSING VALUE")


@pytest.mark.parametrize("length", [8, 20])
def test_create_user_accepts_password_boundary_lengths(
    user_factory: UserFactory,
    length: int,
) -> None:
    request, response = user_factory(password="p" * length)
    assert response["email"] == request["email"]


def test_create_user_accepts_500_character_bio(
    user_factory: UserFactory,
) -> None:
    request, response = user_factory(bio="a" * 500)
    assert response["bio"] == request["bio"]


@pytest.mark.parametrize(
    "phone_number",
    [
        "011-1234-5678",
        "010-123-5678",
        "010-12345-5678",
        "010-1234-567",
        "x010-1234-5678",
        "010-1234-5678x",
        "010 1234 5678",
    ],
)
def test_create_user_rejects_invalid_phone_number_variants(
    client: TestClient,
    phone_number: str,
) -> None:
    response = client.post(
        "/api/users",
        json={
            "name": "김와플",
            "email": "phone@wafflestudio.com",
            "password": "password000",
            "phone_number": phone_number,
            "height": 175.0,
        },
    )
    assert_error(response, 422, "ERR_003", "INVALID PHONE NUMBER")


def test_token_and_session_identify_the_correct_user(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    _, first_user = user_factory(
        email="first@wafflestudio.com",
        name="첫번째",
        phone_number="010-1111-1111",
    )
    second_request, second_user = user_factory(
        email="second@wafflestudio.com",
        name="두번째",
        phone_number="010-2222-2222",
    )
    assert first_user["user_id"] != second_user["user_id"]

    token_response = client.post(
        "/api/auth/token",
        json={
            "email": second_request["email"],
            "password": second_request["password"],
        },
    )
    assert token_response.status_code == 200, token_response.text

    profile_response = client.get(
        "/api/users/me",
        headers={
            "Authorization": f"Bearer {token_response.json()['access_token']}"
        },
    )
    assert profile_response.status_code == 200, profile_response.text
    assert profile_response.json()["user_id"] == second_user["user_id"]
    assert profile_response.json()["email"] == second_request["email"]

    session_response = client.post(
        "/api/auth/session",
        json={
            "email": second_request["email"],
            "password": second_request["password"],
        },
    )
    assert session_response.status_code == 200, session_response.text

    profile_response = client.get("/api/users/me")
    assert profile_response.status_code == 200, profile_response.text
    assert profile_response.json()["user_id"] == second_user["user_id"]
    assert profile_response.json()["email"] == second_request["email"]


def test_user_responses_do_not_expose_passwords(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, create_response = user_factory()
    assert "password" not in create_response
    assert "hashed_password" not in create_response

    token_response = client.post(
        "/api/auth/token",
        json={"email": request["email"], "password": request["password"]},
    )
    profile_response = client.get(
        "/api/users/me",
        headers={
            "Authorization": f"Bearer {token_response.json()['access_token']}"
        },
    )
    assert profile_response.status_code == 200, profile_response.text
    assert "password" not in profile_response.json()
    assert "hashed_password" not in profile_response.json()
