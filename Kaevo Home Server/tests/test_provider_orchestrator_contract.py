from kaevo_home_server.main import (
    RequestIntent,
    RemovalPlanInput,
    credential_requirements,
    ProviderCredentials,
    OperationResult,
    RetryStepInput,
    user_has_permission,
    user_can_request,
)


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
