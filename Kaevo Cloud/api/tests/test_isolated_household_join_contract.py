import json
import logging
from pathlib import Path

import pytest

import household_join_handler as join
from handler import _join_code_hash as creator_join_code_hash
from profile_binding import build_profile_creation


COMPLETION_CONTRACT = Path(__file__).parents[1] / "contracts" / "household_join_completion_contract.json"


class Table:
    name = "test-table"

    def __init__(self, items=()):
        self.items = {item["join_resume_hash"]: dict(item) for item in items if "join_resume_hash" in item}

    def get_item(self, *, Key, **_kwargs):
        item = self.items.get(Key["join_resume_hash"])
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item, **_kwargs):
        self.items[Item["join_resume_hash"]] = dict(Item)

    def update_item(self, *, Key, ExpressionAttributeValues, **_kwargs):
        item = self.items.setdefault(Key["join_resume_hash"], {})
        if ":one" in ExpressionAttributeValues:
            item["attempts"] = item.get("attempts", 0) + 1
        if ":state" in ExpressionAttributeValues:
            item["state"] = ExpressionAttributeValues[":state"]
            item["auth_state_hash"] = ExpressionAttributeValues[":state_hash"]
            item["email_hash"] = ExpressionAttributeValues[":email_hash"]
            item["code_challenge"] = ExpressionAttributeValues[":challenge"]
            item["oidc_nonce"] = ExpressionAttributeValues[":nonce"]
            item["cognito_route"] = ExpressionAttributeValues[":route"]
        if ":auth_expires" in ExpressionAttributeValues:
            item["auth_expires_at"] = ExpressionAttributeValues[":auth_expires"]
            item["expires_at"] = ExpressionAttributeValues[":auth_expires"]


class InvitationTable:
    name = "test-invitations"

    def __init__(self, item):
        self.item = dict(item)
        self.keys = []

    def get_item(self, *, Key, **_kwargs):
        self.keys.append(dict(Key))
        return {"Item": dict(self.item)} if Key["code_hash"] == self.item["code_hash"] else {}


class BeginTable:
    name = "test-joins"

    def __init__(self):
        self.items = []

    def put_item(self, *, Item, **_kwargs):
        self.items.append(dict(Item))


def body(result):
    return json.loads(result["body"])


def test_rate_limits_are_isolated_by_join_phase(monkeypatch):
    consumed = []
    monkeypatch.setattr(join, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(join, "_network_bucket", lambda _event: "network")
    monkeypatch.setattr(
        join,
        "_limit",
        lambda scope, value, maximum, now: consumed.append((scope, value, maximum, now)) or True,
    )

    common = {
        "installation_hash": "device",
        "invitation_hash": "invitation",
    }
    assert join._rate_ok({}, phase="begin", **common)
    assert join._rate_ok(
        {},
        phase="route",
        transaction_hash="transaction",
        email_hash="email",
        **common,
    )

    scopes = [entry[0] for entry in consumed]
    assert scopes[:3] == ["begin-ip", "begin-device", "begin-invitation"]
    assert scopes[3:] == [
        "route-ip",
        "route-device",
        "route-invitation",
        "route-transaction",
        "route-email-invitation",
    ]
    assert not set(scopes[:3]).intersection(scopes[3:])


def test_rate_limit_rejects_an_unknown_phase_without_consuming(monkeypatch):
    consumed = []
    monkeypatch.setattr(join, "_limit", lambda *args: consumed.append(args) or True)

    assert not join._rate_ok({}, phase="unknown", installation_hash="device")
    assert consumed == []


def test_begin_outcome_logging_is_bounded_and_redacted(caplog):
    event = {
        "requestContext": {"http": {"sourceIp": "203.0.113.42"}},
        "_kaevo_lambda_request_fingerprint": "request-fingerprint",
    }

    with caplog.at_level(logging.INFO):
        join._begin_outcome(
            event,
            "rate_limited",
            429,
            installation_hash="raw-installation-hash",
            invitation_hash="raw-invitation-hash",
        )

    record = caplog.records[-1].getMessage()
    assert "HOUSEHOLD_JOIN_BEGIN_OUTCOME" in record
    assert '"outcome":"rate_limited"' in record
    assert '"status":429' in record
    assert "raw-installation-hash" not in record
    assert "raw-invitation-hash" not in record
    assert "203.0.113.42" not in record


def test_completion_outcome_logging_is_bounded_and_redacted(caplog):
    event = {"requestContext": {"http": {"sourceIp": "203.0.113.42"}}}
    item = {"join_resume_hash": "raw-join-transaction-key"}

    with caplog.at_level(logging.WARNING):
        join._completion_outcome(
            event,
            "authenticated_subject_lookup_invalid",
            401,
            item=item,
            subject="raw-cognito-subject",
            installation_hash="raw-installation-key",
        )

    record = caplog.records[-1].getMessage()
    assert "HOUSEHOLD_JOIN_COMPLETION_OUTCOME" in record
    assert '"outcome":"authenticated_subject_lookup_invalid"' in record
    assert '"status":401' in record
    assert "raw-cognito-subject" not in record
    assert "raw-join-transaction-key" not in record
    assert "raw-installation-key" not in record
    assert "203.0.113.42" not in record


def test_begin_hashes_displayed_and_qr_join_codes_like_invitation_creation(monkeypatch):
    displayed_code = "ABCDE-12345"
    invitation = InvitationTable({
        "code_hash": creator_join_code_hash(displayed_code),
        "invitation_id": "invite-fixture", "state": "pending", "code_expires_at": 1_100,
    })
    joins = BeginTable()
    monkeypatch.setattr(join, "invitations", invitation)
    monkeypatch.setattr(join, "joins", joins)
    monkeypatch.setattr(join, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(join, "_rate_ok", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(join, "_safe_event", lambda *_args, **_kwargs: None)

    result = join.begin({"body": json.dumps({
        "invitation": f"kaevo://join?code={displayed_code}",
        "installation_id": "installation-begin-test-1234",
        "dpop_thumbprint": "t" * 43,
        "correlation_nonce": "c" * 24,
    })})

    assert result["statusCode"] == 201
    assert body(result)["state"] == "household_join_ready"
    assert invitation.keys == [{"code_hash": creator_join_code_hash(displayed_code)}]
    assert joins.items[0]["invitation_code_hash"] == creator_join_code_hash(displayed_code)


def _onboarding_item(*, handle, installation_id, subject):
    return {
        "join_resume_hash": join._sha(handle),
        "member_principal_id": subject,
        "device_binding_hash": join._installation_hash(installation_id),
        "dpop_thumbprint": "t" * 43,
        "state": "membership_accepted",
        "expires_at": join.epoch_now() + 120,
    }


def _install_onboarding_context(monkeypatch, *, item, subject):
    monkeypatch.setattr(join, "joins", Table([item]))
    monkeypatch.setattr(join, "household_memberships", object())
    monkeypatch.setattr(join, "PUBLIC_API_BASE_URL", "https://api.example")
    monkeypatch.setattr(join, "_jwt_subject", lambda _event: subject)
    monkeypatch.setattr(join, "_pending_membership", lambda _item: {"status": "pending_profile"})


def test_onboarding_status_401_emits_one_safe_dpop_reason_without_secret_material(monkeypatch, caplog):
    handle = "jr_" + "a" * 43
    installation_id = "installation-fixture-canary-1234"
    subject = "fixture-subject-canary"
    _install_onboarding_context(
        monkeypatch,
        item=_onboarding_item(handle=handle, installation_id=installation_id, subject=subject),
        subject=subject,
    )
    monkeypatch.setattr(
        join,
        "verify_dpop",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(join.IdentityError("installation_key_mismatch", 401)),
    )
    caplog.set_level(logging.WARNING, logger=join.__name__)

    result = join.onboarding_status({
        "headers": {"dpop": "proof-token-canary"},
        "queryStringParameters": {"resume": handle, "installation_id": installation_id},
        "_kaevo_lambda_request_fingerprint": "request-fingerprint-canary",
    })

    assert result["statusCode"] == 401
    assert body(result) == {"state": "authentication_mismatch", "retryable": False}
    records = [record for record in caplog.records if join.ONBOARDING_STATUS_DIAGNOSTIC_EVENT in record.message]
    assert len(records) == 1
    assert '"reason_category":"DPOP_KEY_BINDING_MISMATCH"' in records[0].message
    for secret in (handle, installation_id, subject, "proof-token-canary"):
        assert secret not in records[0].message


def test_onboarding_status_authorization_decision_survives_diagnostic_logger_failure(monkeypatch):
    handle = "jr_" + "b" * 43
    installation_id = "installation-fixture-logger-1234"
    subject = "fixture-subject-logger"
    _install_onboarding_context(
        monkeypatch,
        item=_onboarding_item(handle=handle, installation_id=installation_id, subject=subject),
        subject=subject,
    )
    monkeypatch.setattr(
        join,
        "verify_dpop",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(join.IdentityError("dpop_url_mismatch", 401)),
    )
    monkeypatch.setattr(join.LOGGER, "warning", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("logger unavailable")))

    result = join.onboarding_status({
        "queryStringParameters": {"resume": handle, "installation_id": installation_id},
    })

    assert result["statusCode"] == 401
    assert body(result) == {"state": "authentication_mismatch", "retryable": False}


def test_onboarding_status_valid_proof_keeps_the_existing_public_contract(monkeypatch, caplog):
    handle = "jr_" + "c" * 43
    installation_id = "installation-fixture-valid-1234"
    subject = "fixture-subject-valid"
    _install_onboarding_context(
        monkeypatch,
        item=_onboarding_item(handle=handle, installation_id=installation_id, subject=subject),
        subject=subject,
    )
    monkeypatch.setattr(join, "verify_dpop", lambda *_args, **_kwargs: {"jti": "safe-test"})
    caplog.set_level(logging.WARNING, logger=join.__name__)

    result = join.onboarding_status({
        "queryStringParameters": {"resume": handle, "installation_id": installation_id},
    })

    assert result["statusCode"] == 200
    assert body(result) == {"state": "membership_created", "next": "profile_setup_required"}
    assert join.ONBOARDING_STATUS_DIAGNOSTIC_EVENT not in caplog.text


def test_onboarding_status_returns_the_complete_server_reserved_profile_identity(monkeypatch):
    handle = "jr_" + "d" * 43
    installation_id = "installation-fixture-canonical-1234"
    subject = "fixture-subject-canonical"
    _install_onboarding_context(
        monkeypatch,
        item=_onboarding_item(handle=handle, installation_id=installation_id, subject=subject),
        subject=subject,
    )
    monkeypatch.setattr(join, "verify_dpop", lambda *_args, **_kwargs: {"jti": "safe-test"})
    monkeypatch.setattr(
        join,
        "_pending_membership",
        lambda _item: {
            "status": "pending_profile",
            "reserved_profile_id": "profile_" + "a" * 24,
            "reserved_display_name": "Invited Member",
            "reserved_profile_type": "adult",
        },
    )

    result = join.onboarding_status({
        "queryStringParameters": {"resume": handle, "installation_id": installation_id},
    })

    assert result["statusCode"] == 200
    assert body(result) == {
        "state": "membership_created",
        "next": "profile_setup_required",
        "profile_id": "profile_" + "a" * 24,
        "display_name": "Invited Member",
        "profile_type": "adult",
    }


def test_profile_activation_reuses_the_invitation_reserved_profile_identity():
    reserved_profile_id = "profile_" + "b" * 24
    creation = build_profile_creation(
        household_id="household-canonical",
        account_id="account-canonical",
        display_name="Invited Member",
        profile_type="adult",
        age_classification="adult",
        now_iso="2026-07-31T00:00:00Z",
        now_epoch=1_785_456_000,
        reserved_profile_id=reserved_profile_id,
    )

    assert creation.profile["profile_id"] == reserved_profile_id
    assert creation.profile["display_name"] == "Invited Member"
    assert creation.binding["profile_id"] == reserved_profile_id


def test_route_auth_returns_one_kaevo_continuation_shape(monkeypatch):
    handle = "jr_" + "a" * 43
    item = {
        "join_resume_hash": join._sha(handle), "invitation_code_hash": "i" * 64,
        "device_binding_hash": join._installation_hash("installation-test-1234"),
        "state": "initiated", "expires_at": join.epoch_now() + 120,
        "absolute_expires_at": join.epoch_now() + join.JOIN_ABSOLUTE_MAX_TTL_SECONDS,
    }
    table = Table([item])
    monkeypatch.setattr(join, "joins", table)
    monkeypatch.setattr(join, "USER_POOL_ID", "pool")
    monkeypatch.setattr(join, "AUTHORIZE_BASE_URL", "https://api.example/v3/identity/household-joins/authorize")
    monkeypatch.setattr(join, "NATIVE_CALLBACK_URI", "kaevo://oauth/callback")
    monkeypatch.setattr(join, "NATIVE_AUTHORIZE_ENDPOINT", "https://auth.example/oauth2/authorize")
    monkeypatch.setattr(join, "EXPECTED_CLIENT_ID", "native")
    monkeypatch.setattr(
        join,
        "_user_exists",
        lambda _email: pytest.fail("Join must not perform an account-existence lookup"),
    )
    result = join.route_auth({"body": json.dumps({
        "join_resume_handle": handle, "installation_id": "installation-test-1234",
        "email": "member@example.com", "oauth_state": "b" * 24, "code_challenge": "c" * 43,
        "nonce": "n" * 24,
    })})
    payload = body(result)
    assert result["statusCode"] == 200
    assert set(payload) == {"state", "authorization_continuation_url", "expires_at"}
    assert payload["authorization_continuation_url"].startswith("https://api.example/")
    assert "signup" not in payload["authorization_continuation_url"]
    assert "member@example.com" not in json.dumps(payload)
    assert "n" * 24 not in json.dumps(payload)


def test_route_auth_retries_only_the_same_nonce_and_authorize_uses_stored_nonce(monkeypatch):
    handle = "jr_" + "a" * 43
    state, challenge, nonce = "s" * 24, "c" * 43, "n" * 24
    item = {
        "join_resume_hash": join._sha(handle), "invitation_code_hash": "i" * 64,
        "device_binding_hash": join._installation_hash("installation-test-1234"),
        "state": "initiated", "expires_at": join.epoch_now() + 120,
        "absolute_expires_at": join.epoch_now() + join.JOIN_ABSOLUTE_MAX_TTL_SECONDS,
    }
    table = Table([item])
    monkeypatch.setattr(join, "joins", table)
    monkeypatch.setattr(join, "USER_POOL_ID", "pool")
    monkeypatch.setattr(join, "AUTHORIZE_BASE_URL", "https://api.example/v3/identity/household-joins/authorize")
    monkeypatch.setattr(join, "NATIVE_CALLBACK_URI", "kaevo://oauth/callback")
    monkeypatch.setattr(join, "NATIVE_AUTHORIZE_ENDPOINT", "https://auth.example/oauth2/authorize")
    monkeypatch.setattr(join, "EXPECTED_CLIENT_ID", "native")
    monkeypatch.setattr(join, "_user_exists", lambda _email: True)
    request = {"body": json.dumps({
        "join_resume_handle": handle, "installation_id": "installation-test-1234",
        "email": "member@example.com", "oauth_state": state, "code_challenge": challenge, "nonce": nonce,
    })}
    assert join.route_auth(request)["statusCode"] == 200
    assert join.route_auth(request)["statusCode"] == 200
    changed = json.loads(request["body"])
    changed["nonce"] = "x" * 24
    assert join.route_auth({"body": json.dumps(changed)})["statusCode"] == 409
    redirect = join.authorize({"queryStringParameters": {"resume": handle, "state": state, "nonce": "x" * 24}})
    assert redirect["statusCode"] == 302
    assert "nonce=" + nonce in redirect["headers"]["Location"]
    assert "nonce=" + "x" * 24 not in redirect["headers"]["Location"]
    assert redirect["headers"]["Location"].startswith("https://auth.example/oauth2/authorize?")
    assert "/signup" not in redirect["headers"]["Location"]


def test_new_account_authorization_always_originates_at_oauth_authorize(monkeypatch):
    handle = "jr_" + "u" * 43
    state, challenge, nonce = "s" * 24, "c" * 43, "n" * 24
    item = {
        "join_resume_hash": join._sha(handle), "invitation_code_hash": "i" * 64,
        "device_binding_hash": join._installation_hash("installation-new-account-1234"),
        "state": "initiated", "expires_at": join.epoch_now() + 120,
        "absolute_expires_at": join.epoch_now() + join.JOIN_ABSOLUTE_MAX_TTL_SECONDS,
    }
    table = Table([item])
    monkeypatch.setattr(join, "joins", table)
    monkeypatch.setattr(join, "USER_POOL_ID", "pool")
    monkeypatch.setattr(join, "AUTHORIZE_BASE_URL", "https://api.example/v3/identity/household-joins/authorize")
    monkeypatch.setattr(join, "NATIVE_CALLBACK_URI", "kaevo://oauth/callback")
    monkeypatch.setattr(join, "NATIVE_AUTHORIZE_ENDPOINT", "https://auth.example/oauth2/authorize")
    monkeypatch.setattr(join, "EXPECTED_CLIENT_ID", "native")
    monkeypatch.setattr(
        join,
        "_user_exists",
        lambda _email: pytest.fail("new-account Join must not probe Cognito users"),
    )

    result = join.route_auth({"body": json.dumps({
        "join_resume_handle": handle,
        "installation_id": "installation-new-account-1234",
        "email": "new-member@example.com",
        "oauth_state": state,
        "code_challenge": challenge,
        "nonce": nonce,
    })})

    assert result["statusCode"] == 200
    assert table.items[join._sha(handle)]["cognito_route"] == "authorize"
    redirect = join.authorize({"queryStringParameters": {"resume": handle, "state": state}})
    assert redirect["statusCode"] == 302
    assert redirect["headers"]["Location"].startswith("https://auth.example/oauth2/authorize?")
    assert "/signup" not in redirect["headers"]["Location"]


def test_auth_result_is_exactly_transaction_and_dpop_bound_without_tokens(monkeypatch):
    handle, installation_id, state = "jr_" + "q" * 43, "installation-auth-result-123", "s" * 24
    item = {
        "join_resume_hash": join._sha(handle), "state": "awaiting_authorization",
        "expires_at": join.epoch_now() + 120,
        "device_binding_hash": join._installation_hash(installation_id),
        "auth_state_hash": join._sha(state), "dpop_thumbprint": "t" * 43,
    }
    observed, verification = [], {}
    monkeypatch.setattr(join, "joins", Table([item]))
    monkeypatch.setattr(join, "PUBLIC_API_BASE_URL", "https://api.example")
    monkeypatch.setattr(join, "_safe_event", lambda *_args, **_kwargs: observed.append((_args, _kwargs)))
    monkeypatch.setattr(join, "_consume_dpop_replay", lambda *_args, **_kwargs: True)

    def verify(_proof, **kwargs):
        verification.update(kwargs)

    monkeypatch.setattr(join, "verify_dpop", verify)
    result = join.auth_result({
        "headers": {"dpop": "proof-canary"},
        "body": json.dumps({
            "join_resume_handle": handle, "installation_id": installation_id,
            "oauth_state": state, "category": "token_exchange_failed",
        }),
    })

    assert result["statusCode"] == 204
    assert verification["access_token"] is None
    assert verification["method"] == "POST"
    assert verification["url"] == "https://api.example/v3/identity/household-joins/auth-result"
    assert observed[0][0][1:] == ("auth_result_token_exchange_failed", "observed")


def test_auth_result_accepts_only_the_new_finite_provider_callback_categories(monkeypatch, caplog):
    handle, installation_id, state = "jr_" + "p" * 43, "installation-auth-result-category", "t" * 24
    item = {
        "join_resume_hash": join._sha(handle), "state": "awaiting_authorization",
        "expires_at": join.epoch_now() + 120,
        "device_binding_hash": join._installation_hash(installation_id),
        "auth_state_hash": join._sha(state), "dpop_thumbprint": "t" * 43,
    }
    observed = []
    monkeypatch.setattr(join, "joins", Table([item]))
    monkeypatch.setattr(join, "PUBLIC_API_BASE_URL", "https://api.example")
    monkeypatch.setattr(join, "_safe_event", lambda *_args, **_kwargs: observed.append((_args, _kwargs)))
    monkeypatch.setattr(join, "_consume_dpop_replay", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(join, "verify_dpop", lambda *_args, **_kwargs: None)
    caplog.set_level(logging.WARNING, logger=join.__name__)
    result = join.auth_result({
        "headers": {"dpop": "proof-canary"},
        "body": json.dumps({
            "join_resume_handle": handle, "installation_id": installation_id,
            "oauth_state": state, "category": "provider_callback_server_error",
        }),
    })
    assert result["statusCode"] == 204
    assert observed[0][0][1:] == ("auth_result_provider_callback_server_error", "observed")
    assert "HOUSEHOLD_JOIN_AUTH_RESULT" in caplog.text
    assert "provider_callback_server_error" in caplog.text
    assert handle not in caplog.text
    assert installation_id not in caplog.text


def test_auth_result_rejects_a_wrong_state_without_recording_anything(monkeypatch):
    handle, installation_id = "jr_" + "w" * 43, "installation-auth-result-456"
    item = {
        "join_resume_hash": join._sha(handle), "state": "awaiting_authorization",
        "expires_at": join.epoch_now() + 120,
        "device_binding_hash": join._installation_hash(installation_id),
        "auth_state_hash": join._sha("s" * 24), "dpop_thumbprint": "t" * 43,
    }
    monkeypatch.setattr(join, "joins", Table([item]))
    monkeypatch.setattr(join, "PUBLIC_API_BASE_URL", "https://api.example")
    monkeypatch.setattr(join, "verify_dpop", lambda *_args, **_kwargs: pytest.fail("proof must not be checked"))
    monkeypatch.setattr(join, "_safe_event", lambda *_args, **_kwargs: pytest.fail("audit must not be written"))
    result = join.auth_result({"body": json.dumps({
        "join_resume_handle": handle, "installation_id": installation_id,
        "oauth_state": "x" * 24, "category": "token_exchange_failed",
    })})
    assert result["statusCode"] == 401


def test_isolated_template_uses_explicit_routes_without_shared_api_events():
    template = Path(__file__).parents[2] / "infra" / "template.yaml"
    text = template.read_text()
    for logical_id in (
        "KaevoHouseholdJoinFunction:", "KaevoHouseholdJoinIntegration:",
        "KaevoHouseholdJoinBeginRoute:", "KaevoHouseholdJoinRouteAuthRoute:",
        "KaevoHouseholdJoinAuthorizeRoute:", "KaevoHouseholdJoinAuthResultRoute:", "KaevoHouseholdJoinCompleteRoute:",
        "KaevoHouseholdJoinOnboardingStatusRoute:", "KaevoHouseholdJoinProfileSetupRoute:",
    ):
        assert logical_id in text
    assert "RouteKey: POST /v3/identity/household-joins/complete" in text
    assert "DeletionPolicy: Retain" in text
    shared = text[text.index("KaevoCloudApiFunction:"):text.index("KaevoIdentityV3ApiIntegration:")]
    assert "household-joins/begin" not in shared
    assert "household-joins/route-auth" not in shared


def test_completion_iam_allows_only_the_four_missing_transactional_puts():
    """Keep completion's underlying DynamoDB permissions least-privilege."""
    template = (Path(__file__).parents[2] / "infra" / "template.yaml").read_text()
    start = template.index("Sid: PutHouseholdJoinCompletionRecordsTransactionally")
    end = template.index("Sid: PutProfileSetupRecordsTransactionally", start)
    statement = template[start:end]

    assert "dynamodb:PutItem" in statement
    assert "dynamodb:EnclosingOperation: TransactWriteItems" in statement
    allowed = {
        "KaevoHouseholdInvitationsTable",
        "KaevoAccountsTable",
        "KaevoAuthIdentitiesTable",
        "KaevoHouseholdMembershipsTable",
    }
    referenced = {
        line.strip().removeprefix("- !GetAtt ").removeprefix("Resource: !GetAtt ").removesuffix(".Arn")
        for line in statement.splitlines()
        if "!GetAtt" in line
    }
    assert referenced == allowed
    for forbidden_action in ("dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan", "dynamodb:Query"):
        assert forbidden_action not in statement
    assert "Resource: '*'" not in statement


def test_profile_setup_iam_allows_only_its_transactional_record_writes():
    template = (Path(__file__).parents[2] / "infra" / "template.yaml").read_text()
    start = template.index("Sid: PutProfileSetupRecordsTransactionally")
    end = template.index("Sid: ResolveAuthenticatedSubjectOnly", start)
    statement = template[start:end]

    assert "dynamodb:PutItem" in statement
    assert "dynamodb:UpdateItem" in statement
    assert "dynamodb:EnclosingOperation: TransactWriteItems" in statement
    allowed = {
        "KaevoIdentityProfilesTable",
        "KaevoProfilesTable",
        "KaevoProfileBindingsTable",
        "KaevoProfileMappingsTable",
        "KaevoEntitlementsTable",
        "KaevoPrincipalsTable",
        "KaevoIdentityMembershipsTable",
        "KaevoHouseholdMembershipsTable",
    }
    referenced = {
        line.strip().removeprefix("- !GetAtt ").removeprefix("Resource: !GetAtt ").removesuffix(".Arn")
        for line in statement.splitlines()
        if "!GetAtt" in line
    }
    assert referenced == allowed
    assert "dynamodb:DeleteItem" not in statement
    assert "dynamodb:Scan" not in statement
    assert "dynamodb:Query" not in statement
    assert "Resource: '*'" not in statement


def test_intent_first_client_targets_only_v3_completion():
    client = (Path(__file__).parents[4] / "iOS" / "iOS Kaevo v2" / "Cloud" / "KaevoCloudClient.swift").read_text()
    start = client.index("func completeHouseholdJoin(")
    section = client[start:client.index("func listOwnerDevices", start)]
    assert 'appendingPathComponent("v3/identity/household-joins/complete")' in section
    assert 'path: "/v2/identity/join-household"' not in section


def test_complete_creates_only_normalized_pending_membership_and_defers_profile_authority():
    source = (Path(__file__).parents[2] / "api" / "src" / "household_join_handler.py").read_text()
    complete_source = source[source.index("def complete(event):"):source.index("def onboarding_status(event):")]
    assert '"status": "pending_profile"' in complete_source
    assert '"entity_type": "HouseholdJoinPendingLookup"' in complete_source
    assert '"TableName": PRINCIPALS_TABLE' not in complete_source
    assert '"TableName": MEMBERSHIPS_TABLE' not in complete_source
    assert 'TableName": IDENTITY_PROFILES_TABLE' not in complete_source
    assert 'TableName": ENTITLEMENTS_TABLE' not in complete_source
    assert "transact_write_items(TransactItems=transaction)" in complete_source
    assert "_serialize_transact_items" not in complete_source


def test_complete_binds_the_authenticated_subject_not_the_pre_login_email_hash():
    source = (Path(__file__).parents[2] / "api" / "src" / "household_join_handler.py").read_text()
    complete_source = source[source.index("def complete(event):"):source.index("def onboarding_status(event):")]
    assert "authenticated_subject_lookup_invalid" in complete_source
    assert "item.get(\"email_hash\")" not in complete_source
    assert "hmac.compare_digest(_sha(_email(attributes.get(\"email\")))" not in complete_source


def test_profile_setup_uses_native_values_for_the_resource_client_transaction():
    source = (Path(__file__).parents[2] / "api" / "src" / "household_join_handler.py").read_text()
    profile_setup_source = source[source.index("def profile_setup(event):"):source.index("def _canonical_route_path", source.index("def profile_setup(event):"))]
    assert "transact_write_items(TransactItems=transaction)" in profile_setup_source
    assert '"TableName": PROFILES_TABLE' in profile_setup_source
    assert "IDENTITY_PROFILES_TABLE" not in profile_setup_source


def test_profile_setup_promotes_only_the_exact_consumed_invitation_jellyfin_binding():
    valid = {
        "state": "consumed",
        "household_id": "household-1",
        "profile_id": "profile_member_1234567890",
        "member_principal_id": "principal-member",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "01234567-89ab-cdef-0123-456789abcdef",
        "jellyfin_binding_updated_at": "2026-07-31T12:00:00Z",
    }
    binding = join._consumed_invitation_jellyfin_binding(
        valid,
        household_id="household-1",
        profile_id="profile_member_1234567890",
        member_principal_id="principal-member",
    )
    assert binding == {
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
        "jellyfin_binding_state": "active",
        "jellyfin_binding_updated_at": "2026-07-31T12:00:00Z",
    }
    with pytest.raises(join.AccountFoundationError):
        join._consumed_invitation_jellyfin_binding(
            {**valid, "member_principal_id": "unrelated-principal"},
            household_id="household-1",
            profile_id="profile_member_1234567890",
            member_principal_id="principal-member",
        )


def test_profile_setup_binding_promotion_is_exact_get_item_only_without_scan():
    source = (Path(__file__).parents[2] / "api" / "src" / "household_join_handler.py").read_text()
    profile_setup_source = source[source.index("def profile_setup(event):"):source.index("def _canonical_route_path", source.index("def profile_setup(event):"))]
    assert 'Key={"code_hash": invitation_code_hash}, ConsistentRead=True' in profile_setup_source
    assert "_consumed_invitation_jellyfin_binding(" in profile_setup_source
    assert ".scan(" not in profile_setup_source


def test_pending_recovery_is_a_direct_subject_and_device_pointer_without_scan():
    source = (Path(__file__).parents[2] / "api" / "src" / "household_join_handler.py").read_text()
    recovery = source[source.index("def _pending_lookup_key"):source.index("def complete(event):")]
    assert "HouseholdJoinPendingLookup" in recovery
    assert "_pending_lookup_key(subject, installation_hash)" in recovery
    assert ".scan(" not in recovery
    assert "no_pending_onboarding" in source


def test_stage_prefixed_http_api_path_routes_only_when_it_matches_the_event_stage(monkeypatch):
    sentinel = {"statusCode": 299, "body": "stage-normalized"}
    monkeypatch.setattr(join, "begin", lambda _event: sentinel)
    request = {
        "rawPath": "/dev/v3/identity/household-joins/begin",
        "requestContext": {"stage": "dev", "http": {"method": "POST"}},
    }
    assert join.lambda_handler(request, None) == sentinel

    wrong_prefix = {**request, "rawPath": "/other/v3/identity/household-joins/begin"}
    assert body(join.lambda_handler(wrong_prefix, None))["state"] == "not_found"


def test_complete_consumes_a_valid_proof_before_later_invitation_validation(monkeypatch):
    handle = "jr_" + "r" * 43
    item = {
        "join_resume_hash": join._sha(handle), "state": "awaiting_authorization",
        "expires_at": join.epoch_now() + 120, "device_binding_hash": join._installation_hash("installation-replay-123"),
        "auth_state_hash": join._sha("s" * 24), "dpop_thumbprint": "t" * 43,
    }
    table = Table([item])
    calls = {"proof": 0, "email": 0}

    class ExpiredInvitation:
        def get_item(self, **_kwargs):
            return {"Item": {"state": "pending", "expires_at": join.epoch_now() - 1}}

    monkeypatch.setattr(join, "joins", table)
    monkeypatch.setattr(join, "invitations", ExpiredInvitation())
    monkeypatch.setattr(join, "principals", object())
    monkeypatch.setattr(join, "memberships", object())
    monkeypatch.setattr(join, "profiles", object())
    monkeypatch.setattr(join, "entitlements", object())
    monkeypatch.setattr(join, "accounts", object())
    monkeypatch.setattr(join, "auth_identities", object())
    monkeypatch.setattr(join, "household_memberships", object())
    monkeypatch.setattr(join, "USER_POOL_ID", "pool")
    monkeypatch.setattr(join, "PUBLIC_API_BASE_URL", "https://api.example")
    monkeypatch.setattr(join, "_jwt_subject", lambda _event: "subject-1")
    monkeypatch.setattr(join, "_rate_ok", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(join, "_safe_event", lambda *_args, **_kwargs: None)
    consumed = set()
    monkeypatch.setattr(join, "_consume_dpop_replay", lambda _item, jti, _expires, **_kwargs: not (jti in consumed or consumed.add(jti)))
    def verify(*_args, **kwargs):
        calls["proof"] += 1
        if not kwargs["replay_guard"]("proof-1", join.epoch_now() + 60):
            raise join.IdentityError("dpop_replay", 401)
        return {"jti": "proof-1"}
    monkeypatch.setattr(join, "verify_dpop", verify)
    class Cognito:
        def list_users(self, **_kwargs):
            calls["email"] += 1
            return {"Users": [{"Attributes": [{"Name": "email", "Value": "different@example.com"}]}]}
    monkeypatch.setattr(join, "cognito", Cognito())
    event = {"headers": {"authorization": "Bearer access", "dpop": "proof"}, "body": json.dumps({"join_resume_handle": handle, "installation_id": "installation-replay-123", "oauth_state": "s" * 24})}
    # The authenticated Cognito e-mail is intentionally different from the
    # pre-hosted-login route value. It must proceed to the next validation
    # boundary, not be rejected as an authentication mismatch.
    assert join.complete(event)["statusCode"] == 410
    assert join.complete(event)["statusCode"] == 401
    assert calls == {"proof": 2, "email": 1}


def test_cloud_and_ios_share_the_canonical_completion_contract():
    contract = json.loads(COMPLETION_CONTRACT.read_text())
    assert contract["response"]["state"] == [
        "membership_created", "already_completed", "already_member",
        "profile_created", "profile_mapped", "completed",
    ]
    assert contract["response"]["next"] == ["profile_setup_required", "installation_setup_required", "completed"]
    handler = Path(__file__).parents[2] / "api" / "src" / "household_join_handler.py"
    text = handler.read_text()
    for state in contract["response"]["state"]:
        assert f'"{state}"' in text
    for next_step in contract["response"]["next"]:
        if next_step == "profile_setup_required":
            assert f'"next": "{next_step}"' in text
    client = (Path(__file__).parents[4] / "iOS" / "iOS Kaevo v2" / "Cloud" / "KaevoCloudModels.swift").read_text()
    for value in contract["response"]["state"] + contract["response"]["next"]:
        assert f'"{value}"' in client
    for value in contract["onboarding_status"]["state"]:
        assert f'"{value}"' in text
        assert f'"{value}"' in client
