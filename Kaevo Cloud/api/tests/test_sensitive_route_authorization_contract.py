from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_sensitive_route_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class FakeTable:
    def __init__(self, key_name: str):
        self.key_name = key_name
        self.items = {}

    def get_item(self, *, Key, **_):
        item = self.items.get(Key[self.key_name])
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item, **_):
        self.items[Item[self.key_name]] = dict(Item)


def identity_event(*, role="owner", profile_id="profile-1", auth_time=None, body=None, query=None):
    now = int(time.time())
    claims = {
        "sub": "owner-1",
        "custom:account_id": "account-1",
        "custom:household_id": "household-1",
        "custom:profile_id": profile_id,
        "custom:role": role,
        "custom:authz_version": "7",
        "custom:identity_schema_version": "1",
        "auth_time": str(auth_time if auth_time is not None else now),
        "iss": "https://issuer.example/pool",
        "client_id": "main-client",
        "token_use": "access",
        "iat": str(now),
        "exp": str(now + 900),
    }
    return {
        "requestContext": {"authorizer": {"jwt": {"claims": claims}}},
        "headers": {},
        "queryStringParameters": query or {},
        "body": json.dumps(body or {}),
    }


def principal(role="owner"):
    return {
        "principal_id": "owner-1",
        "account_id": "account-1",
        "household_id": "household-1",
        "role": role,
        "authz_version": 7,
        "profile_ids": ["profile-1", "child-1"],
        "state": "active",
        "revoked": False,
    }


def install_identity_tables(monkeypatch, *, role="owner"):
    principals = FakeTable("principal_id")
    principals.put_item(Item=principal(role))
    settings = FakeTable("profile_id")
    monkeypatch.setattr(handler, "principals_table", principals)
    monkeypatch.setattr(handler, "profile_settings_table", settings)
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    monkeypatch.setattr(handler, "DEV_API_KEY", "must-not-work-in-production")
    monkeypatch.setenv("EXPECTED_COGNITO_ISSUER", "https://issuer.example/pool")
    monkeypatch.setenv("EXPECTED_MAIN_CLIENT_ID", "main-client")
    return settings


def test_profile_session_cannot_change_provider_configuration(monkeypatch):
    install_identity_tables(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "record_type": "access", "profile_id": "profile-1", "role": "adult",
    })
    result = handler.put_provider_settings({
        "headers": {"authorization": "Bearer portable-profile-token"},
        "queryStringParameters": {"profile_id": "profile-1"},
        "body": json.dumps({"settings": {"request_provider": "seerr"}}),
    })
    assert result["statusCode"] == 401
    assert json.loads(result["body"])["state"] == "invalid_identity_claims"


def test_recently_authenticated_owner_can_update_provider_and_child_policy(monkeypatch):
    settings = install_identity_tables(monkeypatch)
    provider = handler.put_provider_settings(identity_event(
        query={"profile_id": "profile-1"},
        body={"settings": {"request_provider": "seerr"}},
    ))
    assert provider["statusCode"] == 200

    parental = handler.put_profile_settings(
        identity_event(body={"settings": {"parental_controls_sync_enabled": False}}),
        "/v1/profiles/child-1/settings",
    )
    assert parental["statusCode"] == 200
    assert "profile-1" in settings.items and "child-1" in settings.items


def test_stale_owner_auth_and_cross_household_profile_are_denied_opaquely(monkeypatch):
    install_identity_tables(monkeypatch)
    stale = handler.put_provider_settings(identity_event(
        auth_time=int(time.time()) - 301,
        query={"profile_id": "profile-1"},
        body={"settings": {"request_provider": "seerr"}},
    ))
    assert stale["statusCode"] == 401
    assert json.loads(stale["body"])["state"] == "recent_auth_required"

    cross_household = handler.put_provider_settings(identity_event(
        query={"profile_id": "another-household-profile"},
        body={"settings": {"request_provider": "seerr"}},
    ))
    assert cross_household["statusCode"] == 404
    assert json.loads(cross_household["body"])["state"] == "target_not_found"


def test_profile_session_cannot_queue_optimizer_execution(monkeypatch):
    monkeypatch.setattr(handler, "remote_requests_table", FakeTable("request_id"))
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    monkeypatch.setattr(handler, "require_profile_auth", lambda _event, _profile: True)
    result = handler.create_remote_command({
        "headers": {"authorization": "Bearer profile-token"},
        "body": json.dumps({
            "profile_id": "profile-1",
            "operation": "optimizer.execute_remux",
            "parameters": {"item_id": "a" * 32},
            "idempotency_key": "optimizer-execute-denied-1",
        }),
    })
    assert result["statusCode"] == 401


def test_bound_access_session_cannot_mint_grant_for_another_device(monkeypatch):
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: {
        "record_type": "access",
        "profile_id": "profile-1",
        "device_id": "device-1",
    })
    result = handler.create_playback_grant({
        "headers": {"authorization": "Bearer bound-token", "dpop": "verified-upstream"},
        "body": json.dumps({
            "profile_id": "profile-1",
            "device_id": "device-2",
            "item_id": "a" * 32,
            "media_source_id": "source-1",
            "playback_session_id": "session-1",
            "mode": "direct_play",
        }),
    })
    assert result["statusCode"] == 404
    assert json.loads(result["body"])["state"] == "target_not_found"


def test_development_key_is_rejected_in_production_even_when_configured(monkeypatch):
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    monkeypatch.setattr(handler, "DEV_API_KEY", "configured-by-mistake")
    assert not handler.require_dev_key({"headers": {"x-kaevo-dev-key": "configured-by-mistake"}})


def test_production_rejects_legacy_portable_sessions_and_trial_issuance(monkeypatch):
    sessions = FakeTable("token_hash")
    sessions.put_item(Item={
        "token_hash": handler.secret_hash("legacy-portable-token"),
        "record_type": "app_session",
        "state": "active",
        "profile_id": "profile-1",
        "revoked": False,
        "expires_at": handler.epoch_now() + 86_400,
    })
    monkeypatch.setattr(handler, "app_sessions_table", sessions)
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    legacy = {"headers": {"authorization": "Bearer legacy-portable-token"}}
    assert handler.authenticated_app_session(legacy) is None
    assert handler.start_cloud_trial({"headers": {}, "body": "{}"})["statusCode"] == 410
    assert handler.refresh_app_session(legacy)["statusCode"] == 410
