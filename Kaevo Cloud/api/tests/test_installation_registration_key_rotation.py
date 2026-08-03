import json
from types import SimpleNamespace

from botocore.exceptions import ClientError

import handler


class InstallationTable:
    def __init__(self, existing):
        self.item = dict(existing)
        self.writes = []

    def put_item(self, Item, ConditionExpression=None, **kwargs):
        if ConditionExpression == "attribute_not_exists(installation_id)" and self.item:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException"}},
                "PutItem",
            )
        self.item = dict(Item)
        self.writes.append({"item": dict(Item), "condition": ConditionExpression, **kwargs})

    def get_item(self, **_kwargs):
        return {"Item": dict(self.item)} if self.item else {}

    def update_item(
        self,
        Key,
        UpdateExpression,
        ConditionExpression,
        ExpressionAttributeNames,
        ExpressionAttributeValues,
    ):
        assert Key == {"installation_id": self.item["installation_id"]}
        self.item.update({
            "account_id": ExpressionAttributeValues[":account"],
            "household_id": ExpressionAttributeValues[":household"],
            "device_id": ExpressionAttributeValues[":device"],
            "device_label": ExpressionAttributeValues[":device_label"],
            "device_class": ExpressionAttributeValues[":device_class"],
            "public_jwk_json": ExpressionAttributeValues[":jwk"],
            "key_thumbprint": ExpressionAttributeValues[":thumbprint"],
            "last_seen_at": ExpressionAttributeValues[":last_seen"],
            "key_rotated_at": ExpressionAttributeValues[":rotated"],
        })
        self.writes.append({
            "item": dict(self.item),
            "update": UpdateExpression,
            "condition": ConditionExpression,
            "names": ExpressionAttributeNames,
            "values": ExpressionAttributeValues,
        })


def request_event():
    return {
        "body": json.dumps({
            "installation_id": "installation-test",
            "device_id": "device-test",
            "device_label": "Kaevo iPhone",
            "device_class": "mobile",
            "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        }),
        "headers": {"dpop": "proof"},
        "requestContext": {"requestId": "request-test", "http": {"method": "POST"}},
        "rawPath": "/v2/installations",
    }


def configure(monkeypatch, table, *, subject="principal-test"):
    monkeypatch.setattr(handler, "installations_table", table)
    monkeypatch.setattr(handler, "authoritative_identity", lambda *_args: (
        SimpleNamespace(
            subject=subject,
            account_id="account-test",
            household_id="household-test",
        ),
        None,
    ))
    monkeypatch.setattr(handler, "validate_public_jwk", lambda value: value)
    monkeypatch.setattr(handler, "jwk_thumbprint", lambda _value: "new-thumbprint")
    monkeypatch.setattr(handler, "verify_dpop", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handler, "prepare_security_audit", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(handler, "utc_now_iso", lambda: "2026-07-30T17:30:00Z")


def existing_installation(**changes):
    item = {
        "installation_id": "installation-test",
        "device_id": "device-test",
        "principal_id": "principal-test",
        "account_id": "account-test",
        "household_id": "household-test",
        "state": "active",
        "revoked": False,
        "key_thumbprint": "old-thumbprint",
        "public_jwk_json": "old-jwk",
        "management_handle": "retained-management-handle",
        "created_at": "2026-07-29T17:30:00Z",
    }
    item.update(changes)
    return item


def test_exact_active_device_binding_can_rotate_its_dpop_key(monkeypatch):
    table = InstallationTable(existing_installation(
        account_id="pre-migration-account",
        household_id="pre-migration-household",
        device_id="pre-reinstall-device",
        key_thumbprint=None,
    ))
    configure(monkeypatch, table)

    result = handler.register_installation_v2(request_event())

    assert result["statusCode"] == 201
    assert json.loads(result["body"])["state"] == "installation_registered"
    assert table.item["key_thumbprint"] == "new-thumbprint"
    assert table.item["account_id"] == "account-test"
    assert table.item["household_id"] == "household-test"
    assert table.item["device_id"] == "device-test"
    assert table.item["management_handle"] == "retained-management-handle"
    assert table.writes[-1]["condition"].startswith("#state = :active")
    assert "#principal = :principal" in table.writes[-1]["condition"]
    assert "#device = :device" not in table.writes[-1]["condition"]
    assert "key_thumbprint" not in table.writes[-1]["condition"]
    assert table.writes[-1]["names"]["#principal"] == "principal_id"
    assert table.writes[-1]["names"]["#device"] == "device_id"


def test_unrelated_identity_can_never_rotate_an_existing_binding(monkeypatch):
    table = InstallationTable(existing_installation(principal_id="unrelated-principal"))
    configure(monkeypatch, table)

    result = handler.register_installation_v2(request_event())

    assert result["statusCode"] == 409
    assert json.loads(result["body"]) == {"state": "installation_binding_conflict"}
    assert table.item["key_thumbprint"] == "old-thumbprint"
    assert table.writes == []


def test_inactive_installation_can_never_be_reactivated(monkeypatch):
    table = InstallationTable(existing_installation(state="revoked", revoked=True))
    configure(monkeypatch, table)

    result = handler.register_installation_v2(request_event())

    assert result["statusCode"] == 409
    assert table.item["key_thumbprint"] == "old-thumbprint"
    assert table.writes == []
