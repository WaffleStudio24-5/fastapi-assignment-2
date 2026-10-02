from time import sleep, time

import jwt
from fastapi.testclient import TestClient

from grader_tests.conftest import UserFactory, assert_error
from src.auth.router import LONG_SESSION_LIFESPAN, SHORT_SESSION_LIFESPAN
from src.common.database import blocked_token_db


def decode_without_verification(token: str) -> dict:
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_sub": False,
        },
    )


def issue_tokens(
    client: TestClient,
    email: str,
    password: str,
) -> dict:
    response = client.post(
        "/api/auth/token",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_issued_jwts_contain_subject_and_correct_expiration(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    first_request, _ = user_factory(email="jwt1@wafflestudio.com")
    second_request, _ = user_factory(email="jwt2@wafflestudio.com")

    issued_before = time()
    first_tokens = issue_tokens(
        client, first_request["email"], first_request["password"]
    )
    issued_after = time()
    second_tokens = issue_tokens(
        client, second_request["email"], second_request["password"]
    )

    access_claims = decode_without_verification(first_tokens["access_token"])
    refresh_claims = decode_without_verification(first_tokens["refresh_token"])
    second_claims = decode_without_verification(second_tokens["access_token"])

    assert access_claims.get("sub") is not None
    assert refresh_claims.get("sub") == access_claims["sub"]
    assert second_claims.get("sub") != access_claims["sub"]

    tolerance = 2
    assert (
        issued_before + SHORT_SESSION_LIFESPAN * 60 - tolerance
        <= access_claims["exp"]
        <= issued_after + SHORT_SESSION_LIFESPAN * 60 + tolerance
    )
    assert (
        issued_before + LONG_SESSION_LIFESPAN * 60 - tolerance
        <= refresh_claims["exp"]
        <= issued_after + LONG_SESSION_LIFESPAN * 60 + tolerance
    )


def test_refreshed_refresh_token_can_be_used_again(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    original_tokens = issue_tokens(client, request["email"], request["password"])

    # README only requires sub/exp claims. Waiting avoids requiring an
    # undocumented jti claim merely to make a same-second token unique.
    sleep(1)

    first_refresh = client.post(
        "/api/auth/token/refresh",
        headers={"Authorization": f"Bearer {original_tokens['refresh_token']}"},
    )
    assert first_refresh.status_code == 200, first_refresh.text
    refreshed_tokens = first_refresh.json()

    second_refresh = client.post(
        "/api/auth/token/refresh",
        headers={"Authorization": f"Bearer {refreshed_tokens['refresh_token']}"},
    )
    assert second_refresh.status_code == 200, second_refresh.text

    profile_response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {refreshed_tokens['access_token']}"},
    )
    assert profile_response.status_code == 200, profile_response.text


def test_refresh_stores_original_expiration_in_blocklist(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    tokens = issue_tokens(client, request["email"], request["password"])
    refresh_token = tokens["refresh_token"]
    original_expiration = decode_without_verification(refresh_token)["exp"]

    response = client.post(
        "/api/auth/token/refresh",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert response.status_code == 200, response.text
    assert blocked_token_db.get(refresh_token) == original_expiration


def test_delete_token_stores_original_expiration_in_blocklist(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    tokens = issue_tokens(client, request["email"], request["password"])
    refresh_token = tokens["refresh_token"]
    original_expiration = decode_without_verification(refresh_token)["exp"]

    response = client.delete(
        "/api/auth/token",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert response.status_code == 204, response.text
    assert blocked_token_db.get(refresh_token) == original_expiration


def test_delete_token_without_authorization_header(client: TestClient) -> None:
    response = client.delete("/api/auth/token")
    assert_error(response, 401, "ERR_009", "UNAUTHENTICATED")


def test_delete_token_with_bad_authorization_header(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    tokens = issue_tokens(client, request["email"], request["password"])

    response = client.delete(
        "/api/auth/token",
        headers={"Authorization": tokens["refresh_token"]},
    )
    assert_error(response, 400, "ERR_007", "BAD AUTHORIZATION HEADER")


def test_delete_token_with_invalid_token(client: TestClient) -> None:
    response = client.delete(
        "/api/auth/token",
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert_error(response, 401, "ERR_008", "INVALID TOKEN")


def test_profile_rejects_bad_authorization_header(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    tokens = issue_tokens(client, request["email"], request["password"])

    response = client.get(
        "/api/users/me",
        headers={"Authorization": tokens["access_token"]},
    )
    assert_error(response, 400, "ERR_007", "BAD AUTHORIZATION HEADER")


def test_profile_rejects_forged_access_token(
    client: TestClient,
    user_factory: UserFactory,
) -> None:
    request, _ = user_factory()
    tokens = issue_tokens(client, request["email"], request["password"])
    header, payload, _ = tokens["access_token"].split(".")
    forged_token = f"{header}.{payload}.AAAA"

    response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert_error(response, 401, "ERR_008", "INVALID TOKEN")
