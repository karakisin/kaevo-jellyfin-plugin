from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_cloud_trial_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class FakeTable:
    def __init__(self, key_name: str):
        self.key_name = key_name
        self.items = {}

    def put_item(self, *, Item):
        self.items[Item[self.key_name]] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(Key[self.key_name])
        return {"Item": dict(item)} if item else {}


def event(body: dict | None = None, *, bearer: str | None = None, dev_key: str | None = None):
    headers = {}
    if bearer:
        headers["authorization"] = f"Bearer {bearer}"
    if dev_key:
        headers["x-kaevo-dev-key"] = dev_key
    return {"headers": headers, "body": json.dumps(body or {})}


def test_plugin_confirmed_trial_returns_one_time_hashed_app_session(monkeypatch):
    connectors = FakeTable("connector_id")
    sessions = FakeTable("token_hash")
    entitlements = FakeTable("profile_id")
    remote_requests = FakeTable("request_id")
    monkeypatch.setattr(handler, "home_connectors_table", connectors)
    monkeypatch.setattr(handler, "app_sessions_table", sessions)
    monkeypatch.setattr(handler, "entitlements_table", entitlements)
    monkeypatch.setattr(handler, "remote_requests_table", remote_requests)

    started = handler.start_cloud_trial(event({"installation_id": "ios-installation-1"}))
    started_body = json.loads(started["body"])
    assert started["statusCode"] == 201
    assert started_body["state"] == "trial_created"
    assert len(started_body["activation_token"]) >= 40
    assert started_body["activation_token"] not in str(sessions.items)

    pending = handler.activate_cloud_trial(event({"activation_token": started_body["activation_token"]}))
    assert pending["statusCode"] == 409

    paired = handler.exchange_connector_pairing(event({
        "connector_id": started_body["connector_id"],
        "pairing_code": started_body["pairing_code"],
    }))
    assert paired["statusCode"] == 200

    activated = handler.activate_cloud_trial(event({"activation_token": started_body["activation_token"]}))
    activated_body = json.loads(activated["body"])
    assert activated["statusCode"] == 200
    assert activated_body["state"] == "remote_access_ready"
    assert activated_body["entitlements"]["subscription_state"] == "trialing"
    assert activated_body["entitlements"]["cloud_enabled"] is True
    assert activated_body["session_token"] not in str(sessions.items)

    status = handler.get_app_session_status(event(bearer=activated_body["session_token"]))
    status_body = json.loads(status["body"])
    assert status["statusCode"] == 200
    assert status_body["profile_id"] == started_body["profile_id"]
    assert status_body["entitlements"]["subscription_state"] == "trialing"

    entitled = handler.get_entitlements({
        "headers": {"authorization": f"Bearer {activated_body['session_token']}"},
        "queryStringParameters": {"profile_id": started_body["profile_id"]},
    })
    assert entitled["statusCode"] == 200
    assert json.loads(entitled["body"])["entitlements"]["cloud_enabled"] is True

    cross_profile = handler.get_entitlements({
        "headers": {"authorization": f"Bearer {activated_body['session_token']}"},
        "queryStringParameters": {"profile_id": "another-profile"},
    })
    assert cross_profile["statusCode"] == 401

    assert handler.put_entitlements(event(bearer=activated_body["session_token"]))["statusCode"] == 401
    mutation = handler.create_remote_command(event({
        "profile_id": started_body["profile_id"],
        "operation": "jellyfin.favorite",
        "parameters": {"item_id": "a" * 32},
        "idempotency_key": "favorite-denied-1",
    }, bearer=activated_body["session_token"]))
    assert mutation["statusCode"] == 401
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {
        "connector_id": started_body["connector_id"],
        "auth_state": "active",
        "playback_grant_key": "h" * 48,
    })
    preparation = handler.create_remote_command(event({
        "profile_id": started_body["profile_id"],
        "operation": "jellyfin.prepare_playback",
        "parameters": {
            "item_id": "a" * 32,
            "device_id": "ios-installation-1",
            "max_bitrate": 20_000_000,
        },
        "idempotency_key": "playback-session-1",
    }, bearer=activated_body["session_token"]))
    assert preparation["statusCode"] == 202
    playback = handler.create_playback_grant(event({
        "profile_id": started_body["profile_id"],
        "device_id": "ios-installation-1",
        "item_id": "a" * 32,
        "media_source_id": "source-1",
        "playback_session_id": "session-1",
        "mode": "transcode",
    }, bearer=activated_body["session_token"]))
    assert playback["statusCode"] == 201

    replay = handler.activate_cloud_trial(event({"activation_token": started_body["activation_token"]}))
    assert replay["statusCode"] == 401

    revoked = handler.revoke_app_session(event(bearer=activated_body["session_token"]))
    assert revoked["statusCode"] == 200
    assert handler.get_app_session_status(event(bearer=activated_body["session_token"]))["statusCode"] == 401


def test_expired_or_wrong_app_session_is_rejected(monkeypatch):
    sessions = FakeTable("token_hash")
    monkeypatch.setattr(handler, "app_sessions_table", sessions)
    sessions.put_item(Item={
        "token_hash": handler.secret_hash("expired"),
        "record_type": "app_session",
        "state": "active",
        "profile_id": "profile-1",
        "revoked": False,
        "expires_at": handler.epoch_now() - 1,
    })
    assert handler.authenticated_app_session(event(bearer="expired")) is None
    assert handler.authenticated_app_session(event(bearer="wrong")) is None


def test_existing_online_plugin_migrates_and_rotates_session(monkeypatch):
    connectors = FakeTable("connector_id")
    sessions = FakeTable("token_hash")
    entitlements = FakeTable("profile_id")
    monkeypatch.setattr(handler, "home_connectors_table", connectors)
    monkeypatch.setattr(handler, "app_sessions_table", sessions)
    monkeypatch.setattr(handler, "entitlements_table", entitlements)
    monkeypatch.setattr(handler, "DEV_API_KEY", "migration-dev-key")

    profile_id = "profile_123"
    connector_id = "connector-existing-1"
    connectors.put_item(Item={
        "connector_id": connector_id,
        "profile_id": profile_id,
        "auth_state": "active",
        "revoked": False,
        "last_seen_epoch": handler.epoch_now(),
    })
    entitlement = {
        **handler.DEFAULT_ENTITLEMENTS,
        "plan": "family",
        "subscription_state": "active",
        "cloud_enabled": True,
    }
    entitlements.put_item(Item={
        "profile_id": profile_id,
        "entitlements_json": json.dumps(entitlement),
        "created_at": handler.utc_now_iso(),
        "updated_at": handler.utc_now_iso(),
    })

    unauthorized = handler.migrate_existing_app_session(event({
        "profile_id": profile_id,
        "connector_id": connector_id,
        "installation_id": "ios-existing-1",
    }))
    assert unauthorized["statusCode"] == 401

    migrated = handler.migrate_existing_app_session(event({
        "profile_id": profile_id,
        "connector_id": connector_id,
        "installation_id": "ios-existing-1",
    }, dev_key="migration-dev-key"))
    migrated_body = json.loads(migrated["body"])
    assert migrated["statusCode"] == 200
    assert migrated_body["state"] == "remote_access_ready"
    assert migrated_body["session_token"] not in str(sessions.items)

    old_token = migrated_body["session_token"]
    assert handler.get_app_session_status(event(bearer=old_token))["statusCode"] == 200

    refreshed = handler.refresh_app_session(event(bearer=old_token))
    refreshed_body = json.loads(refreshed["body"])
    assert refreshed["statusCode"] == 200
    assert refreshed_body["state"] == "session_refreshed"
    assert refreshed_body["session_token"] != old_token
    assert refreshed_body["session_token"] not in str(sessions.items)
    assert handler.get_app_session_status(event(bearer=old_token))["statusCode"] == 200
    assert handler.get_app_session_status(event(bearer=refreshed_body["session_token"]))["statusCode"] == 200
    assert handler.put_entitlements(event(bearer=refreshed_body["session_token"]))["statusCode"] == 401
