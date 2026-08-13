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
SPEC = importlib.util.spec_from_file_location("kaevo_cloud_playback_handler", HANDLER_PATH)
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


def event(body):
    return {"headers": {"x-kaevo-dev-key": "dev-key"}, "body": json.dumps(body)}


class Profiles:
    def __init__(self, records):
        self.records = {item["profile_id"]: dict(item) for item in records}

    def get_item(self, *, Key, ConsistentRead):
        assert ConsistentRead is True
        item = self.records.get(Key["profile_id"])
        return {"Item": dict(item)} if item else {}


def test_grant_is_short_lived_bound_and_contains_no_local_url_or_secret(monkeypatch):
    monkeypatch.setattr(handler, "DEV_API_KEY", "dev-key")
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.test")
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": True,
        "subscription_state": "trialing",
        "feature_flags": {},
    }, None))
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {"connector_id": "connector-1", "auth_state": "active", "playback_grant_key": "h" * 48})
    result = handler.create_playback_grant(event({
        "profile_id": "profile-1", "device_id": "device-1", "item_id": "a" * 32,
        "media_source_id": "source-1", "playback_session_id": "session-1", "mode": "transcode",
    }))
    body = json.loads(result["body"])
    assert result["statusCode"] == 201
    assert body["expires_at"] - handler.epoch_now() <= 120
    assert "http" not in body["grant"]
    assert "api_key" not in body
    grant_path = body["relay_base_url"].split("/v1/playback/", 1)[1]
    assert "".join(grant_path.split("/")) == body["grant"]
    assert max(map(len, grant_path.split("/"))) <= 180


def test_grant_reuses_one_verified_session_for_exact_switch_target(monkeypatch):
    monkeypatch.setattr(handler, "DEV_API_KEY", "")
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "PLAYBACK_RELAY_PUBLIC_URL", "https://relay.test")
    monkeypatch.setattr(handler, "identity_profiles_table", Profiles([
        {
            "profile_id": "profile-source",
            "household_id": "household-1",
            "state": "active",
            "switch_profile_ids": ["profile-target"],
        },
        {
            "profile_id": "profile-target",
            "household_id": "household-1",
            "state": "active",
        },
    ]))
    authentication_count = 0

    def authenticate_once(_event):
        nonlocal authentication_count
        authentication_count += 1
        assert authentication_count == 1
        return {
            "record_type": "access",
            "profile_id": "profile-source",
            "household_id": "household-1",
            "device_id": "device-1",
        }

    monkeypatch.setattr(handler, "authenticated_app_session", authenticate_once)
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": True,
        "subscription_state": "active",
    }, None))
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {
        "connector_id": "connector-1",
        "auth_state": "active",
        "playback_grant_key": "h" * 48,
    })

    result = handler.create_playback_grant({
        "headers": {"authorization": "Bearer protected"},
        "body": json.dumps({
            "profile_id": "profile-target",
            "device_id": "device-1",
            "item_id": "a" * 32,
            "media_source_id": "source-1",
            "playback_session_id": "session-1",
            "mode": "transcode",
        }),
    })

    assert result["statusCode"] == 201
    assert authentication_count == 1


def test_grant_requires_active_cloud_subscription(monkeypatch):
    monkeypatch.setattr(handler, "DEV_API_KEY", "dev-key")
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": False,
        "subscription_state": "expired",
        "feature_flags": {"remote_playback": True, "remote_playback_relay": True},
    }, None))
    result = handler.create_playback_grant(event({
        "profile_id": "profile-1", "device_id": "device-1", "item_id": "a" * 32,
        "media_source_id": "source-1", "playback_session_id": "session-1", "mode": "direct_play",
    }))
    assert result["statusCode"] == 403


def test_grant_rejects_paths_and_unknown_modes(monkeypatch):
    monkeypatch.setattr(handler, "DEV_API_KEY", "dev-key")
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": True,
        "subscription_state": "trialing",
        "feature_flags": {"remote_playback": True, "remote_playback_relay": True},
    }, None))
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {"connector_id": "connector-1", "auth_state": "active", "playback_grant_key": "h" * 48})
    result = handler.create_playback_grant(event({
        "profile_id": "profile-1", "device_id": "device-1", "item_id": "../../movie.mkv",
        "media_source_id": "source-1", "playback_session_id": "session-1", "mode": "proxy",
    }))
    assert result["statusCode"] == 400


def test_v3_connector_receives_cloud_signed_grant_without_legacy_secret(monkeypatch):
    monkeypatch.setattr(handler, "DEV_API_KEY", "dev-key")
    monkeypatch.setattr(handler, "PLAYBACK_GRANT_SIGNING_KEY", "x" * 48)
    monkeypatch.setattr(handler, "PAIRING_V3_AUTHORIZATION_SIGNING_SEED", handler.pairing_v3_b64url_encode(b"s" * 32))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _: ({
        "cloud_enabled": True,
        "subscription_state": "trialing",
        "feature_flags": {},
    }, None))
    monkeypatch.setattr(handler, "latest_online_connector_for_profile", lambda _: {
        "connector_id": "connector-v3-1",
        "protocol_version": handler.PAIRING_V3_PROTOCOL,
        "auth_state": "v3_active",
        "state": "active",
        "revoked": False,
    })
    result = handler.create_playback_grant(event({
        "profile_id": "profile-1", "device_id": "device-1", "item_id": "a" * 32,
        "media_source_id": "source-1", "playback_session_id": "session-1", "mode": "transcode",
    }))
    assert result["statusCode"] == 201
    payload = json.loads(handler.pairing_v3_b64url_decode(json.loads(result["body"])["grant"].split(".", 1)[0]))
    assert payload["protocol"] == handler.PAIRING_V3_PROTOCOL
    assert payload["home_sig"].count(".") == 2
    assert "playback_grant_key" not in payload
