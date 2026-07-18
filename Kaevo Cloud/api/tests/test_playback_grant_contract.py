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
