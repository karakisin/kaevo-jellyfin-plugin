"""Deterministic, server-clock coverage for Household Join expiry boundaries."""

import json

import household_join_handler as join


class JoinTable:
    name = "test-joins"

    def __init__(self, item):
        self.item = dict(item)
        self.updated = False

    def get_item(self, *, Key, **_kwargs):
        return {"Item": dict(self.item)} if Key["join_resume_hash"] == self.item["join_resume_hash"] else {}

    def update_item(self, *, ExpressionAttributeValues, **_kwargs):
        self.updated = True
        self.item.update({
            "state": ExpressionAttributeValues[":state"],
            "auth_state_hash": ExpressionAttributeValues[":state_hash"],
            "code_challenge": ExpressionAttributeValues[":challenge"],
            "oidc_nonce": ExpressionAttributeValues[":nonce"],
            "email_hash": ExpressionAttributeValues[":email_hash"],
            "cognito_route": ExpressionAttributeValues[":route"],
            "auth_expires_at": ExpressionAttributeValues[":auth_expires"],
            "expires_at": ExpressionAttributeValues[":auth_expires"],
            "route_attempts": self.item.get("route_attempts", 0) + 1,
        })


def _request(handle):
    return {"body": json.dumps({
        "join_resume_handle": handle,
        "installation_id": "installation-clock-1234",
        "email": "member@example.com",
        "oauth_state": "s" * 24,
        "code_challenge": "c" * 43,
        "nonce": "n" * 24,
    })}


def _configured_route(monkeypatch, now, *, created_at=1_000, expires_at=None, absolute_expires_at=None):
    handle = "jr_" + "a" * 43
    item = {
        "join_resume_hash": join._sha(handle),
        "invitation_code_hash": "i" * 64,
        "invitation_id": "fixture-invitation",
        "device_binding_hash": join._installation_hash("installation-clock-1234"),
        "dpop_thumbprint": "t" * 43,
        "state": "initiated",
        "created_at_epoch": created_at,
        "preauth_expires_at": expires_at if expires_at is not None else created_at + join.JOIN_PREAUTH_TTL_SECONDS,
        "absolute_expires_at": absolute_expires_at if absolute_expires_at is not None else created_at + join.JOIN_ABSOLUTE_MAX_TTL_SECONDS,
        "expires_at": expires_at if expires_at is not None else created_at + join.JOIN_PREAUTH_TTL_SECONDS,
        "route_attempts": 0,
    }
    table = JoinTable(item)
    monkeypatch.setattr(join, "joins", table)
    monkeypatch.setattr(join, "epoch_now", lambda: now)
    monkeypatch.setattr(join, "USER_POOL_ID", "pool")
    monkeypatch.setattr(join, "AUTHORIZE_BASE_URL", "https://api.example/v3/identity/household-joins/authorize")
    monkeypatch.setattr(join, "NATIVE_CALLBACK_URI", "kaevo://oauth/callback")
    monkeypatch.setattr(join, "NATIVE_AUTHORIZE_ENDPOINT", "https://auth.example/oauth2/authorize")
    monkeypatch.setattr(join, "EXPECTED_CLIENT_ID", "native")
    monkeypatch.setattr(join, "_user_exists", lambda _email: True)
    monkeypatch.setattr(join, "_rate_ok", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(join, "_safe_event", lambda *_args, **_kwargs: None)
    return handle, table


def _payload(result):
    return json.loads(result["body"])


def test_route_auth_establishes_server_auth_completion_deadline_one_second_before_preauth_expiry(monkeypatch):
    created_at = 1_000
    preauth_expiry = created_at + join.JOIN_PREAUTH_TTL_SECONDS
    handle, table = _configured_route(monkeypatch, preauth_expiry - 1, created_at=created_at)

    result = join.route_auth(_request(handle))

    assert result["statusCode"] == 200
    assert _payload(result)["expires_at"] == preauth_expiry - 1 + join.JOIN_AUTH_COMPLETION_TTL_SECONDS
    assert table.item["auth_expires_at"] == _payload(result)["expires_at"]
    assert table.item["expires_at"] == table.item["auth_expires_at"]


def test_route_auth_never_extends_beyond_immutable_absolute_deadline(monkeypatch):
    created_at = 1_000
    absolute = created_at + join.JOIN_ABSOLUTE_MAX_TTL_SECONDS
    handle, table = _configured_route(monkeypatch, absolute - 10, created_at=created_at, expires_at=absolute - 1, absolute_expires_at=absolute)

    result = join.route_auth(_request(handle))

    assert result["statusCode"] == 200
    assert _payload(result)["expires_at"] == absolute
    assert table.item["expires_at"] == absolute


def test_route_auth_at_the_documented_preauth_boundary_is_expired_and_cannot_be_revived(monkeypatch):
    created_at = 1_000
    preauth_expiry = created_at + join.JOIN_PREAUTH_TTL_SECONDS
    handle, table = _configured_route(monkeypatch, preauth_expiry, created_at=created_at)

    result = join.route_auth(_request(handle))

    assert result["statusCode"] == 410
    assert _payload(result)["state"] == "transaction_expired"
    assert table.updated is False


def test_route_auth_is_idempotent_without_refreshing_the_auth_deadline(monkeypatch):
    handle, table = _configured_route(monkeypatch, 1_100)
    first = join.route_auth(_request(handle))
    first_expiry = _payload(first)["expires_at"]
    monkeypatch.setattr(join, "epoch_now", lambda: 1_200)

    second = join.route_auth(_request(handle))

    assert second["statusCode"] == 200
    assert _payload(second)["expires_at"] == first_expiry
    assert table.item["route_attempts"] == 1


def test_deadlines_are_integer_epoch_seconds_not_milliseconds_or_strings(monkeypatch):
    handle, table = _configured_route(monkeypatch, 1_100)
    result = join.route_auth(_request(handle))

    assert result["statusCode"] == 200
    assert isinstance(table.item["auth_expires_at"], int)
    assert table.item["auth_expires_at"] < 10_000_000
    assert table.item["auth_expires_at"] - 1_100 == join.JOIN_AUTH_COMPLETION_TTL_SECONDS


def test_completion_boundary_rule_is_expired_at_exact_epoch(monkeypatch):
    now = 2_000
    handle = "jr_" + "b" * 43
    table = JoinTable({
        "join_resume_hash": join._sha(handle), "state": "awaiting_authorization",
        "expires_at": now, "device_binding_hash": join._installation_hash("installation-clock-1234"),
        "auth_state_hash": join._sha("s" * 24), "dpop_thumbprint": "t" * 43,
    })
    monkeypatch.setattr(join, "joins", table)
    monkeypatch.setattr(join, "epoch_now", lambda: now)
    monkeypatch.setattr(join, "invitations", object())
    monkeypatch.setattr(join, "principals", object())
    monkeypatch.setattr(join, "accounts", object())
    monkeypatch.setattr(join, "auth_identities", object())
    monkeypatch.setattr(join, "household_memberships", object())
    monkeypatch.setattr(join, "memberships", object())
    monkeypatch.setattr(join, "USER_POOL_ID", "pool")
    monkeypatch.setattr(join, "PUBLIC_API_BASE_URL", "https://api.example")
    monkeypatch.setattr(join, "_jwt_subject", lambda _event: "subject")

    result = join.complete({"body": json.dumps({
        "join_resume_handle": handle, "installation_id": "installation-clock-1234", "oauth_state": "s" * 24,
    })})

    assert result["statusCode"] == 410
    assert _payload(result)["state"] == "transaction_expired"


def test_source_declares_bounded_preauth_auth_and_absolute_deadlines():
    assert join.JOIN_PREAUTH_TTL_SECONDS == 15 * 60
    assert join.JOIN_AUTH_COMPLETION_TTL_SECONDS == 6 * 60
    assert join.JOIN_ABSOLUTE_MAX_TTL_SECONDS == 21 * 60
