from fastapi.testclient import TestClient

from grader_tests.conftest import UserFactory, assert_error
from src.common.database import session_db


def create_session(client: TestClient, email: str, password: str):
    response = client.post(
        "/api/auth/session",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    assert "sid" in response.cookies
    return response


def test_session_logout_removes_server_side_session(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    session_response = create_session(client, request["email"], request["password"])
    sid = session_response.cookies["sid"]
    assert sid in session_db

    logout_response = client.delete("/api/auth/session")
    assert logout_response.status_code == 204, logout_response.text
    assert sid not in session_db

    client.cookies.set("sid", sid)
    profile_response = client.get("/api/users/me")
    assert_error(profile_response, 401, "ERR_006", "INVALID SESSION")


def test_profile_rejects_unknown_session_id(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    user_factory()
    client.cookies.set("sid", "unknown-session-id")

    response = client.get("/api/users/me")
    assert_error(response, 401, "ERR_006", "INVALID SESSION")


def test_session_logout_without_sid_returns_empty_204(client: TestClient) -> None:
    response = client.delete("/api/auth/session")
    assert response.status_code == 204
    assert response.content == b""

