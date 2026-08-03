from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest
from botocore.exceptions import ClientError


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

SRC = Path(__file__).resolve().parents[1] / "src"
SPEC = importlib.util.spec_from_file_location("kaevo_home_connector_binding_handler", SRC / "handler.py")
handler = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(handler)


class ConnectorTable:
    def __init__(self, items):
        self.items = {item["connector_id"]: dict(item) for item in items}
        self.query_calls = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return {"Items": [
            dict(item) for item in self.items.values()
            if item.get("profile_id") == "identity-profile-1"
        ]}


class TransactionClient:
    def __init__(self, connectors):
        self.connectors = connectors
        self.calls = []
        self.audit_items = []

    def transact_write_items(self, *, TransactItems):
        self.calls.append(TransactItems)
        update = TransactItems[0]["Update"]
        connector = self.connectors.items[update["Key"]["connector_id"]]
        values = update["ExpressionAttributeValues"]
        if connector.get("binding_status") or connector.get("account_id") or connector.get("household_id"):
            raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
        connector.update({
            "account_id": values[":account"],
            "household_id": values[":household"],
            "binding_status": values[":bound"],
            "bound_at": values[":now"],
            "bound_by_account_id": values[":account"],
            "binding_method": values[":method"],
            "binding_schema_version": values[":schema"],
            "binding_installation_id": values[":installation"],
            "binding_updated_at": values[":now"],
        })
        self.audit_items.append(dict(TransactItems[1]["Put"]["Item"]))


def body(result):
    return json.loads(result["body"])


def identity_response(*, account_status="active", household_status="active", profiles=True):
    return handler.response(200, {
        "account": {"account_id": "acct-1", "status": account_status},
        "household": {"household_id": "household-1", "membership_id": "membership-1", "status": household_status},
        "profile_access": [{"profile_id": "cloud-profile-1"}] if profiles else [],
    })


def connector(**overrides):
    record = {
        "connector_id": "connector-1",
        "profile_id": "identity-profile-1",
        "protocol_version": handler.PAIRING_V3_PROTOCOL,
        "auth_state": "v3_active",
        "state": "active",
        "revoked": False,
        "account_binding": handler.pairing_v3_sha256_b64url(b"acct-1"),
        "family_binding": handler.pairing_v3_sha256_b64url(b"household-1"),
        "plugin_instance_id": "plugin-instance-1",
        "plugin_public_key_fingerprint": "fingerprint-1",
        "plugin_key_id": "key-1",
        "last_seen_at": "2026-07-24T12:00:00Z",
        "last_seen_epoch": 1_785_000_000,
    }
    record.update(overrides)
    return record


def install(monkeypatch, records=(None,)):
    records = [connector() if item is None else item for item in records]
    table = ConnectorTable(records)
    client = TransactionClient(table)
    dynamo = type("Dynamo", (), {})()
    dynamo.meta = type("Meta", (), {"client": client})()
    session = {
        "record_type": "access", "account_id": "acct-1", "household_id": "household-1",
        "profile_id": "identity-profile-1", "principal_id": "principal-1",
        "installation_id": "installation-1", "device_id": "device-1",
    }
    monkeypatch.setattr(handler, "HOME_CONNECTORS_TABLE", "connectors")
    monkeypatch.setattr(handler, "SECURITY_AUDIT_TABLE", "audit")
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(handler, "security_audit_table", object())
    monkeypatch.setattr(handler, "dynamodb", dynamo)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "identity_me_v3", lambda _event, verified_session=None: identity_response())
    monkeypatch.setattr(
        handler, "_profile_binding_audit",
        lambda *_args, **_kwargs: {"event_id": "audit-1", "event_type": "home_connector_binding"},
    )
    monkeypatch.setattr(handler, "commit_security_audit", lambda _item: None)
    return table, client


def test_get_reports_binding_required_without_writing(monkeypatch):
    table, client = install(monkeypatch)

    result = handler.get_home_connector_binding_v3({})

    assert result["statusCode"] == 200
    payload = body(result)
    assert payload["state"] == "binding_required"
    assert payload["eligible"] is True
    assert client.calls == []
    assert "account_id" not in payload["account"]
    assert "household_id" not in payload["household"]
    assert "connector_id" not in payload["connector"]
    assert table.query_calls
    assert table.query_calls[0]["IndexName"] == handler.HOME_CONNECTORS_PROFILE_INDEX
    assert "KeyConditionExpression" in table.query_calls[0]
    assert not hasattr(table, "scan")


def test_bind_creates_only_authoritative_connector_fields_and_audit(monkeypatch):
    table, client = install(monkeypatch)

    result = handler.bind_home_connector_v3({"body": "{}"})

    assert result["statusCode"] == 200
    assert body(result)["state"] == "binding_completed"
    record = table.items["connector-1"]
    assert record["account_id"] == "acct-1"
    assert record["household_id"] == "household-1"
    assert record["binding_status"] == "bound"
    assert record["bound_by_account_id"] == "acct-1"
    assert record["binding_installation_id"] == "installation-1"
    assert record["binding_schema_version"] == 1
    assert len(client.calls) == 1
    assert len(client.audit_items) == 1
    assert all("plugin_public_key" not in json.dumps(item) for item in client.audit_items)


def test_bind_rejects_client_supplied_authority(monkeypatch):
    _table, client = install(monkeypatch)

    result = handler.bind_home_connector_v3({"body": json.dumps({"account_id": "other"})})

    assert result["statusCode"] == 400
    assert body(result)["state"] == "client_authority_input_forbidden"
    assert client.calls == []


def test_repeated_binding_is_idempotent(monkeypatch):
    table, client = install(monkeypatch)
    assert body(handler.bind_home_connector_v3({"body": "{}"}))["state"] == "binding_completed"

    result = handler.bind_home_connector_v3({"body": "{}"})

    assert result["statusCode"] == 200
    assert body(result)["state"] == "already_bound"
    assert len(client.calls) == 1
    assert table.items["connector-1"]["binding_status"] == "bound"


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (connector(protocol_version="Pairing V2"), "connector_not_v3"),
        (connector(state="inactive"), "connector_inactive"),
        (connector(revoked=True), "connector_revoked"),
        (connector(account_binding="different"), "connector_enrollment_mismatch"),
        (connector(plugin_key_id=""), "connector_enrollment_unverified"),
    ],
)
def test_binding_rejects_ineligible_connector_without_writing(monkeypatch, record, expected):
    _table, client = install(monkeypatch, (record,))

    result = handler.bind_home_connector_v3({"body": "{}"})

    assert result["statusCode"] == 409
    assert body(result)["state"] == expected
    assert client.calls == []


def test_binding_rejects_ambiguous_authority(monkeypatch):
    _table, client = install(monkeypatch, (connector(connector_id="connector-1"), connector(connector_id="connector-2")))

    result = handler.bind_home_connector_v3({"body": "{}"})

    assert result["statusCode"] == 409
    assert body(result)["state"] == "authority_ambiguous"
    assert client.calls == []


def test_binding_rejects_existing_conflicting_direct_binding(monkeypatch):
    record = connector(account_id="other-account", household_id="other-household", binding_status="bound")
    _table, client = install(monkeypatch, (record,))

    result = handler.bind_home_connector_v3({"body": "{}"})

    assert result["statusCode"] == 409
    assert body(result)["state"] == "existing_binding_conflict"
    assert client.calls == []
