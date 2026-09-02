import json
import time
from types import SimpleNamespace

import handler


class SessionTable:
    def __init__(self, refresh_record=None):
        self.refresh_record = refresh_record
        self.writes = []

    def get_item(self, **_kwargs):
        return {"Item": dict(self.refresh_record)} if self.refresh_record else {}

    def put_item(self, Item, **_kwargs):
        self.writes.append(dict(Item))


class InstallationTable:
    def __init__(self, item):
        self.item = dict(item)

    def get_item(self, **_kwargs):
        return {"Item": dict(self.item)}

    def scan(self, **_kwargs):
        return {"Items": [dict(self.item)]}


def installation():
    return {
        "installation_id": "installation-test",
        "device_id": "server-bound-device",
        "principal_id": "principal-test",
        "account_id": "account-test",
        "household_id": "household-test",
        "profile_id": "profile-test",
        "key_thumbprint": "thumbprint-test",
        "state": "active",
        "revoked": False,
    }


def configure(monkeypatch, session_table):
    monkeypatch.setattr(handler, "app_sessions_table", session_table)
    monkeypatch.setattr(handler, "installations_table", InstallationTable(installation()))
    monkeypatch.setattr(handler, "verify_dpop", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handler, "prepare_security_audit", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handler, "ensure_nonproduction_family_entitlement", lambda *_args, **_kwargs: None)


def test_bound_session_issue_returns_the_authoritative_device_binding(monkeypatch):
    sessions = SessionTable()
    configure(monkeypatch, sessions)
    monkeypatch.setattr(handler, "authoritative_identity", lambda *_args: (
        SimpleNamespace(
            subject="principal-test",
            account_id="account-test",
            household_id="household-test",
            profile_id="profile-test",
            role=SimpleNamespace(value="owner"),
            authz_version=1,
        ),
        None,
    ))
    event = {
        "body": json.dumps({"installation_id": "installation-test"}),
        "headers": {"dpop": "proof"},
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/v2/app-sessions",
    }

    result = handler.issue_bound_session_v2(event)
    body = json.loads(result["body"])

    assert result["statusCode"] == 201
    assert body["installation_id"] == "installation-test"
    assert body["device_id"] == "server-bound-device"


def test_bound_session_refresh_returns_the_preserved_device_binding(monkeypatch):
    refresh_record = {
        "token_hash": "refresh#test",
        "record_type": "refresh",
        "state": "active",
        "family_id": "family-test",
        "principal_id": "principal-test",
        "account_id": "account-test",
        "household_id": "household-test",
        "profile_id": "profile-test",
        "role": "owner",
        "authz_version": 1,
        "installation_id": "installation-test",
        "device_id": "server-bound-device",
        "key_thumbprint": "thumbprint-test",
        "created_at_epoch": int(time.time()) - 10,
        "expires_at": int(time.time()) + 3_600,
    }
    sessions = SessionTable(refresh_record)
    configure(monkeypatch, sessions)
    event = {
        "body": json.dumps({"refresh_token": "refresh-test"}),
        "headers": {"dpop": "proof"},
        "requestContext": {"http": {"method": "POST"}},
        "rawPath": "/v2/app-sessions/refresh",
    }

    result = handler.refresh_bound_session_v2(event)
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["installation_id"] == "installation-test"
    assert body["device_id"] == "server-bound-device"


def test_owner_device_status_projects_its_authenticated_device_binding(monkeypatch):
    session = {
        "record_type": "access",
        "role": "owner",
        "principal_id": "principal-test",
        "household_id": "household-test",
        "profile_id": "profile-test",
        "installation_id": "installation-test",
        "device_id": "server-bound-device",
        "expires_at": 1_800_000_000,
    }
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile_id: ({"plan": "local"}, None))
    monkeypatch.setattr(handler, "installations_table", InstallationTable({
        **installation(),
        "management_handle": "device-handle-test",
        "device_label": "Kaevo iPhone",
        "device_class": "mobile",
        "created_at": "2026-09-01T00:00:00Z",
        "last_seen_at": "2026-09-01T01:00:00Z",
    }))

    result = handler.list_owner_installations_v2({"headers": {}})
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["device_id"] == "server-bound-device"
    assert body["profile_id"] == "profile-test"
    assert body["connector_id"] == ""
    assert body["session_expires_at"] == 1_800_000_000
    assert body["entitlements"] == {"plan": "local"}
    assert body["devices"][0]["is_current"] is True
