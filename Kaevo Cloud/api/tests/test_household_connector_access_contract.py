from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(
    os.environ.get(
        "KAEVO_HANDLER_PATH",
        Path(__file__).resolve().parents[1] / "src" / "handler.py",
    )
)
TEMPLATE_PATH = Path(
    os.environ.get(
        "KAEVO_TEMPLATE_PATH",
        Path(__file__).resolve().parents[2] / "infra" / "template.yaml",
    )
)
SPEC = importlib.util.spec_from_file_location(
    "kaevo_household_connector_access_handler",
    HANDLER_PATH,
)
handler = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(handler)


class ConnectorTable:
    def __init__(self, *, direct=(), household=()):
        self.direct = [dict(item) for item in direct]
        self.household = [dict(item) for item in household]
        self.direct_queries = 0
        self.household_queries = 0

    def query(self, *, IndexName, **_kwargs):
        if IndexName == handler.HOME_CONNECTORS_PROFILE_INDEX:
            self.direct_queries += 1
            return {"Items": [dict(item) for item in self.direct]}
        if IndexName == handler.HOME_CONNECTORS_HOUSEHOLD_INDEX:
            self.household_queries += 1
            return {"Items": [dict(item) for item in self.household]}
        raise AssertionError(f"unexpected index: {IndexName}")


class LookupTable:
    def __init__(self, key_name, items):
        self.key_name = key_name
        self.items = {item[key_name]: dict(item) for item in items}

    def get_item(self, *, Key, **_kwargs):
        item = self.items.get(Key[self.key_name])
        return {"Item": dict(item)} if item else {}


def connector(*, household_id="household-1", profile_id="profile-owner"):
    return {
        "connector_id": "connector-owner",
        "household_id": household_id,
        "profile_id": profile_id,
        "protocol_version": handler.PAIRING_V3_PROTOCOL,
        "auth_state": "v3_active",
        "state": "active",
        "binding_status": "bound",
        "revoked": False,
        "last_seen_epoch": 1_000,
        "provider_status_json": "{}",
        "capabilities_json": "[]",
    }


def test_active_member_uses_household_connector_without_owner_profile_leak(monkeypatch):
    table = ConnectorTable(household=[connector()])
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(
        handler,
        "_authorized_household_connector_context",
        lambda profile_id: (
            "authorized",
            {
                "account_id": "account-member",
                "household_id": "household-1",
                "profile_id": profile_id,
                "role": handler.CanonicalRole.ADULT.value,
            },
        ),
    )
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    resolved = handler._home_connectors_for_profile_access("profile-member")

    assert [item["connector_id"] for item in resolved] == ["connector-owner"]
    assert table.household_queries == 1
    assert table.direct_queries == 0
    public = handler.public_connector_item(
        resolved[0],
        requesting_profile_id="profile-member",
    )
    assert public["profile_id"] == "profile-member"
    assert "profile-owner" not in str(public)


def test_parent_managed_kid_inherits_connector_through_exact_owner_graph(monkeypatch):
    kid = {
        "profile_id": "profile-kid",
        "profile_type": "kid",
        "managed_by_owner": True,
        "owner_principal_id": "principal-owner",
        "account_id": "account-owner",
        "household_id": "household-1",
        "state": "active",
        "revoked": False,
    }
    owner = {
        "profile_id": "profile-owner",
        "account_id": "account-owner",
        "household_id": "household-1",
        "state": "active",
    }
    principal = {
        "principal_id": "principal-owner",
        "account_id": "account-owner",
        "household_id": "household-1",
        "role": "owner",
        "state": "active",
        "revoked": False,
        "profile_ids": ["profile-owner", "profile-kid"],
    }
    legacy_membership = {
        "principal_id": "principal-owner",
        "profile_id": "profile-owner",
    }
    normalized_membership = {
        "membership_id": handler.household_membership_id("account-owner", "household-1"),
        "profile_id": "profile-owner",
    }
    connector_table = ConnectorTable(household=[connector()])
    monkeypatch.setattr(handler, "home_connectors_table", connector_table)
    monkeypatch.setattr(handler, "principals_table", LookupTable("principal_id", [principal]))
    monkeypatch.setattr(
        handler, "identity_memberships_table",
        LookupTable("principal_id", [legacy_membership]),
    )
    monkeypatch.setattr(
        handler, "identity_households_table",
        LookupTable("household_id", [{"household_id": "household-1"}]),
    )
    monkeypatch.setattr(handler, "identity_profiles_table", LookupTable("profile_id", [kid, owner]))
    monkeypatch.setattr(
        handler, "household_memberships_table",
        LookupTable("membership_id", [normalized_membership]),
    )
    monkeypatch.setattr(
        handler, "_repair_legacy_active_membership_profile_pointer",
        lambda item, **_kwargs: item,
    )
    monkeypatch.setattr(
        handler, "resolve_household_membership",
        lambda **_kwargs: (
            SimpleNamespace(
                profile_id="profile-owner",
                account_id="account-owner",
                household_id="household-1",
            ),
            handler.CanonicalRole.OWNER,
            normalized_membership,
        ),
    )
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    mode, context = handler._authorized_household_connector_context("profile-kid")
    resolved = handler._home_connectors_for_profile_access("profile-kid")

    assert mode == "authorized"
    assert context["profile_id"] == "profile-kid"
    assert context["role"] == handler.CanonicalRole.CHILD.value
    assert [item["connector_id"] for item in resolved] == ["connector-owner"]
    assert connector_table.household_queries == 1
    assert connector_table.direct_queries == 0


def test_cross_household_connector_is_rejected(monkeypatch):
    table = ConnectorTable(
        household=[connector(household_id="household-other")],
    )
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(
        handler,
        "_authorized_household_connector_context",
        lambda _profile_id: (
            "authorized",
            {
                "account_id": "account-member",
                "household_id": "household-1",
                "profile_id": "profile-member",
                "role": handler.CanonicalRole.ADULT.value,
            },
        ),
    )

    assert handler._home_connectors_for_profile_access("profile-member") == []
    assert table.household_queries == 1
    assert table.direct_queries == 0


def test_invalid_membership_never_falls_back_to_owner_connector(monkeypatch):
    table = ConnectorTable(
        direct=[connector(profile_id="profile-member")],
        household=[connector()],
    )
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(
        handler,
        "_authorized_household_connector_context",
        lambda _profile_id: ("invalid", None),
    )

    assert handler._home_connectors_for_profile_access("profile-member") == []
    assert table.household_queries == 0
    assert table.direct_queries == 0


def test_legacy_owner_keeps_exact_profile_connector(monkeypatch):
    table = ConnectorTable(direct=[connector()])
    monkeypatch.setattr(handler, "home_connectors_table", table)
    monkeypatch.setattr(
        handler,
        "_authorized_household_connector_context",
        lambda _profile_id: ("legacy", None),
    )

    resolved = handler._home_connectors_for_profile_access("profile-owner")

    assert [item["connector_id"] for item in resolved] == ["connector-owner"]
    assert table.direct_queries == 1
    assert table.household_queries == 0


def test_household_connector_index_belongs_only_to_home_connectors_resource():
    template = TEMPLATE_PATH.read_text()
    devices = template.split("  KaevoDevicesTable:", 1)[1].split(
        "  KaevoEntitlementsTable:",
        1,
    )[0]
    connectors = template.split("  KaevoHomeConnectorsTable:", 1)[1].split(
        "  KaevoRemoteRequestsTable:",
        1,
    )[0]

    assert "household_id-updated_at-index" not in devices
    assert "household_id-updated_at-index" in connectors
    assert "- AttributeName: household_id" in connectors
