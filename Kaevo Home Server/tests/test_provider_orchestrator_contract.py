from kaevo_home_server.main import (
    RequestIntent,
    RemovalPlanInput,
    credential_requirements,
    ProviderCredentials,
    OperationResult,
    RetryStepInput,
    user_has_permission,
    user_can_request,
    require_ios_command,
    validate_security_configuration,
    xor_secret,
    unxor_secret,
)
from fastapi import HTTPException
from starlette.requests import Request
import pytest
import kaevo_home_server.main as home_main


def test_seerr_target_user_request_body_shape():
    intent = RequestIntent(
        operationId="op-1",
        kaevoProfileId="margaret",
        verifiedLinkedSeerrUserId=42,
        mediaType="movie",
        mediaId=10830,
        requesterMode="dedicatedLinkedIdentity",
    )
    assert intent.verifiedLinkedSeerrUserId == 42


def test_manage_permissions_are_distinct():
    admin = {"permissions": 12}
    assert user_has_permission(admin, 8)
    assert user_has_permission(admin, 4)


def test_target_user_request_permission_is_media_specific():
    movie_user = {"permissions": 32}
    assert user_can_request(movie_user, "movie")
    assert not user_can_request(movie_user, "tv")


def test_qbittorrent_requires_username_and_password():
    creds = ProviderCredentials(kind="qbittorrent", base_url="http://qbit", enabled=True, credential_revision=1, password="pw")
    assert credential_requirements("qbittorrent", creds) == ["username"]


def test_removal_plan_input_uses_stable_ids():
    payload = RemovalPlanInput(
        requestCorrelationId="local-1",
        seerrRequestId=91,
        mediaType="movie",
        tmdbId=10830,
        requestedMode="permanentDeleteEverywhere",
    )
    assert payload.tmdbId == 10830


def test_operation_lookup_shape_has_no_secret_payload():
    result = OperationResult(
        operationId="op-1",
        operationType="createMediaRequest",
        state="complete",
        stepStates={"createRequest": "confirmedComplete"},
    )
    encoded = result.model_dump()
    assert "payload" not in encoded
    assert "apiKey" not in str(encoded)
    assert "password" not in str(encoded)


def test_retry_step_requires_exact_step_identifier():
    command = RetryStepInput(step="arrDeletion")
    assert command.step == "arrDeletion"


def request_with_token(token: str | None = None) -> Request:
    headers = [] if token is None else [(b"x-kaevo-home-server-token", token.encode())]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers})


def test_mutation_authentication_fails_closed_when_token_is_not_configured(monkeypatch):
    monkeypatch.setattr(home_main, "IOS_COMMAND_TOKEN", None)
    with pytest.raises(HTTPException) as error:
        require_ios_command(request_with_token())
    assert error.value.status_code == 503


def test_sensitive_read_endpoints_require_ios_auth(monkeypatch):
    import asyncio

    monkeypatch.setattr(home_main, "IOS_COMMAND_TOKEN", "x" * 32)
    unauthenticated = request_with_token()
    with pytest.raises(HTTPException) as providers_error:
        asyncio.run(home_main.list_providers(unauthenticated))
    assert providers_error.value.status_code == 401
    with pytest.raises(HTTPException) as audit_error:
        asyncio.run(home_main.provider_audit(unauthenticated))
    assert audit_error.value.status_code == 401
    with pytest.raises(HTTPException) as operation_error:
        asyncio.run(home_main.get_operation("op-1", unauthenticated))
    assert operation_error.value.status_code == 401


def test_security_configuration_requires_strong_explicit_secrets(monkeypatch):
    monkeypatch.setattr(home_main, "SECRET_KEY_VALUE", "short")
    monkeypatch.setattr(home_main, "IOS_COMMAND_TOKEN", "x" * 32)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        validate_security_configuration()


def test_provider_credentials_use_authenticated_encryption(monkeypatch):
    monkeypatch.setattr(home_main, "SECRET_KEY", b"s" * 32)
    encoded = xor_secret(b'{"apiKey":"not-plaintext"}')
    assert encoded.startswith("v2:")
    assert "not-plaintext" not in encoded
    assert unxor_secret(encoded) == '{"apiKey":"not-plaintext"}'
    tampered = encoded[:-2] + ("AA" if encoded[-2:] != "AA" else "BB")
    with pytest.raises(Exception):
        unxor_secret(tampered)
