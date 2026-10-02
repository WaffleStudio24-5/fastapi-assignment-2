from datetime import timedelta

from fastapi.testclient import TestClient
from freezegun import freeze_time

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


def test_session_is_stored_and_uses_configured_lifespan(
    client: TestClient,
    user_factory: UserFactory,
    monkeypatch,
) -> None:
    monkeypatch.setattr("src.auth.router.LONG_SESSION_LIFESPAN", 1)
    request, _ = user_factory()

    with freeze_time("2030-01-01 00:00:00") as frozen_time:
        session_response = create_session(
            client, request["email"], request["password"]
        )
        sid = session_response.cookies["sid"]
        assert sid in session_db

        frozen_time.tick(delta=timedelta(seconds=59))
        valid_response = client.get("/api/users/me")
        assert valid_response.status_code == 200, valid_response.text

        frozen_time.tick(delta=timedelta(seconds=2))
        expired_response = client.get("/api/users/me")
        assert_error(expired_response, 401, "ERR_006", "INVALID SESSION")


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


def test_session_logout_with_unknown_sid_returns_empty_204(
    client: TestClient,
) -> None:
    client.cookies.set("sid", "unknown-session-id")

    response = client.delete("/api/auth/session")
    assert response.status_code == 204
    assert response.content == b""
    assert "sid" not in client.cookies
