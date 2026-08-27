from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "migrate-v3-connector-profile-binding.py"
SPEC = importlib.util.spec_from_file_location("v3_connector_profile_migration", SCRIPT)
assert SPEC and SPEC.loader
MIGRATION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MIGRATION
SPEC.loader.exec_module(MIGRATION)


def binding(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")


class Table:
    def __init__(self, item):
        self.item = dict(item)
        self.updated = 0

    def get_item(self, **_):
        return {"Item": dict(self.item)}

    def update_item(self, **kwargs):
        assert "attribute_not_exists(profile_id) OR profile_id = :profile" in kwargs["ConditionExpression"]
        assert "attribute_not_exists(household_id) OR household_id = :household_id" in kwargs["ConditionExpression"]
        assert kwargs["UpdateExpression"].startswith("SET profile_id = if_not_exists")
        self.item["profile_id"] = self.item.get("profile_id") or kwargs["ExpressionAttributeValues"][":profile"]
        self.item["plugin_key_id"] = self.item.get("plugin_key_id") or kwargs["ExpressionAttributeValues"][":plugin_key_id"]
        self.item["account_id"] = self.item.get("account_id") or kwargs["ExpressionAttributeValues"][":account_id"]
        self.item["household_id"] = self.item.get("household_id") or kwargs["ExpressionAttributeValues"][":household_id"]
        self.item["binding_status"] = self.item.get("binding_status") or kwargs["ExpressionAttributeValues"][":bound"]
        self.updated += 1


class Session:
    def __init__(self, connectors, profiles):
        self.connectors = connectors
        self.profiles = profiles

    def resource(self, _):
        outer = self
        class Resource:
            def Table(self, name):
                return outer.connectors if name == "connectors" else outer.profiles
        return Resource()


def args(*extra):
    return [
        "migration", "--profile", "test", "--region", "us-west-2",
        "--connectors-table", "connectors", "--profiles-table", "profiles",
        "--connector-id", "connector-1", "--profile-id", "profile-1",
        "--account-id", "account-1", "--household-id", "family-1",
        "--plugin-instance-id", "plugin-1", "--server-id", "server-1",
        "--fingerprint", "sha256:" + "A" * 43,
        "--account-binding", binding("account-1"), "--family-binding", binding("family-1"),
        *extra,
    ]


@pytest.fixture
def target(monkeypatch):
    connectors = Table({
        "connector_id": "connector-1", "protocol_version": "kaevo-pairing-v3",
        "plugin_instance_id": "plugin-1", "server_id": "server-1",
        "plugin_public_key_fingerprint": "sha256:" + "A" * 43,
        "account_binding": binding("account-1"), "family_binding": binding("family-1"),
        "state": "active", "auth_state": "v3_active",
    })
    profiles = Table({
        "profile_id": "profile-1", "account_id": "account-1",
        "household_id": "family-1", "state": "active",
    })
    monkeypatch.setattr(MIGRATION.boto3, "Session", lambda **_: Session(connectors, profiles))
    return connectors, profiles


def test_migration_dry_run_is_ready_and_never_writes(target, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", args())
    MIGRATION.main()
    result = json.loads(capsys.readouterr().out)
    assert result["result"] == "ready"
    assert result["operation"] == "conditional_profile_and_household_bind"
    assert result["creates_connector"] is False
    assert target[0].updated == 0


def test_migration_refuses_conflicting_profile(target, monkeypatch, capsys):
    target[0].item["profile_id"] = "other-profile"
    monkeypatch.setattr(sys, "argv", args())
    with pytest.raises(SystemExit) as error:
        MIGRATION.main()
    assert error.value.code == 2
    assert "conflicting_profile_id" in json.loads(capsys.readouterr().out)["mismatches"]
    assert target[0].updated == 0


def test_migration_apply_requires_exact_confirmation_and_is_idempotent(target, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", args("--apply"))
    with pytest.raises(SystemExit, match="explicit_connector_confirmation_required"):
        MIGRATION.main()
    monkeypatch.setattr(sys, "argv", args("--apply", "--confirm-connector-id", "connector-1"))
    MIGRATION.main()
    assert json.loads(capsys.readouterr().out)["result"] == "updated"
    assert target[0].item["profile_id"] == "profile-1"
    assert target[0].item["plugin_key_id"] == "1"
    assert target[0].item["account_id"] == "account-1"
    assert target[0].item["household_id"] == "family-1"
    assert target[0].item["binding_status"] == "bound"
    assert target[0].updated == 1


def test_migration_refuses_conflicting_household_binding(target, monkeypatch, capsys):
    target[0].item["household_id"] = "other-family"
    monkeypatch.setattr(sys, "argv", args())
    with pytest.raises(SystemExit) as error:
        MIGRATION.main()
    assert error.value.code == 2
    assert "conflicting_household_id" in json.loads(capsys.readouterr().out)["mismatches"]
    assert target[0].updated == 0
