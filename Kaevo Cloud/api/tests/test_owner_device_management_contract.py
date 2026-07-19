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
SPEC = importlib.util.spec_from_file_location("kaevo_owner_devices_handler", HANDLER_PATH)
handler = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(handler)


class Installations:
    def __init__(self, items):
        self.items = {item["installation_id"]: dict(item) for item in items}

    def scan(self, **_kwargs):
        return {"Items": [dict(item) for item in self.items.values()]}

    def put_item(self, *, Item, **_kwargs):
        self.items[Item["installation_id"]] = dict(Item)


class Sessions:
    def __init__(self):
        self.revoked = []

    def query(self, **_kwargs):
        return {"Items": [{"family_id": "family-1"}]}


def bound(role="owner", household="household-1", installation="install-current"):
    return {
        "principal_id": "owner-1", "household_id": household, "role": role,
        "installation_id": installation, "record_type": "access",
    }


def devices():
    return [
        {"installation_id": "install-current", "management_handle": "handle-current", "principal_id": "owner-1", "household_id": "household-1", "device_label": "Jefferson iPhone", "device_class": "mobile", "state": "active", "revoked": False, "created_at": "2026-07-19T10:00:00Z"},
        {"installation_id": "install-control", "management_handle": "handle-control", "principal_id": "owner-1", "household_id": "household-1", "device_label": "Owner Control", "device_class": "desktop", "state": "active", "revoked": False, "created_at": "2026-07-19T11:00:00Z"},
        {"installation_id": "install-other", "management_handle": "handle-other", "principal_id": "owner-2", "household_id": "household-2", "device_label": "Other", "device_class": "mobile", "state": "active", "revoked": False, "created_at": "2026-07-19T12:00:00Z"},
    ]


def test_owner_list_is_privacy_safe_and_marks_current(monkeypatch):
    monkeypatch.setattr(handler, "installations_table", Installations(devices()))
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: bound())
    result = handler.list_owner_installations_v2({})
    body = json.loads(result["body"])
    assert result["statusCode"] == 200
    assert [item["device_label"] for item in body["devices"]] == ["Jefferson iPhone", "Owner Control"]
    assert body["devices"][0]["is_current"] is True
    encoded = json.dumps(body)
    assert "install-current" not in encoded and "install-other" not in encoded
    assert "key_thumbprint" not in encoded and "public_jwk" not in encoded


def test_non_owner_and_missing_dpop_session_are_denied(monkeypatch):
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: bound(role="adult"))
    assert handler.list_owner_installations_v2({})["statusCode"] == 403
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: None)
    assert handler.list_owner_installations_v2({})["statusCode"] == 401


def test_revoke_is_exact_household_scoped_and_idempotent(monkeypatch):
    table = Installations(devices())
    monkeypatch.setattr(handler, "installations_table", table)
    monkeypatch.setattr(handler, "app_sessions_table", Sessions())
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: bound(installation="install-control"))
    monkeypatch.setattr(handler, "prepare_security_audit", lambda *_args, **_kwargs: {"safe": True})
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    revoked = []
    monkeypatch.setattr(handler, "revoke_session_family", lambda family, reason: revoked.append((family, reason)))
    first = handler.revoke_installation_v2({}, "/v2/installations/handle-current/revoke")
    second = handler.revoke_installation_v2({}, "/v2/installations/handle-current/revoke")
    assert first["statusCode"] == second["statusCode"] == 200
    assert table.items["install-current"]["state"] == "revoked"
    assert revoked == [("family-1", "installation_revoked")]
    cross = handler.revoke_installation_v2({}, "/v2/installations/handle-other/revoke")
    assert cross["statusCode"] == 404


def test_release_template_has_no_fixture_route_and_device_routes_use_bound_sessions():
    template = (Path(__file__).resolve().parents[2] / "infra" / "template.yaml").read_text()
    assert "Path: /v1/app-sessions/status" in template
    assert "Path: /v1/app-sessions/revoke" in template
    assert "fixture" not in template.lower()
