#!/usr/bin/env python3
"""Runtime contract for the surgical household-connector candidate."""

from __future__ import annotations

import importlib


handler = importlib.import_module("handler")


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


def set_authorized(profile_id: str = "profile-member") -> None:
    handler._authorized_household_connector_context = lambda _profile_id: (
        "authorized",
        {
            "account_id": "account-member",
            "household_id": "household-1",
            "profile_id": profile_id,
            "role": handler.CanonicalRole.ADULT.value,
        },
    )


def verify_member_household_connector() -> None:
    table = ConnectorTable(household=[connector()])
    handler.home_connectors_table = table
    set_authorized()
    handler.epoch_now = lambda: 1_000

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


def verify_cross_household_rejected() -> None:
    table = ConnectorTable(household=[connector(household_id="household-other")])
    handler.home_connectors_table = table
    set_authorized()

    assert handler._home_connectors_for_profile_access("profile-member") == []
    assert table.household_queries == 1
    assert table.direct_queries == 0


def verify_invalid_membership_fails_closed() -> None:
    table = ConnectorTable(
        direct=[connector(profile_id="profile-member")],
        household=[connector()],
    )
    handler.home_connectors_table = table
    handler._authorized_household_connector_context = lambda _profile_id: (
        "invalid",
        None,
    )

    assert handler._home_connectors_for_profile_access("profile-member") == []
    assert table.household_queries == 0
    assert table.direct_queries == 0


def verify_legacy_owner_keeps_direct_connector() -> None:
    table = ConnectorTable(direct=[connector()])
    handler.home_connectors_table = table
    handler._authorized_household_connector_context = lambda _profile_id: (
        "legacy",
        None,
    )

    resolved = handler._home_connectors_for_profile_access("profile-owner")
    assert [item["connector_id"] for item in resolved] == ["connector-owner"]
    assert table.direct_queries == 1
    assert table.household_queries == 0


if __name__ == "__main__":
    verify_member_household_connector()
    verify_cross_household_rejected()
    verify_invalid_membership_fails_closed()
    verify_legacy_owner_keeps_direct_connector()
    print("household connector candidate contract: PASS")
