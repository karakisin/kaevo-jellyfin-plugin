from __future__ import annotations

import os

from scripts.household_join_live import runner


def test_fixture_b_owner_graph_is_marker_bound_and_has_exact_support_records():
    marker = "fixture-b-0123456789abcdef"

    graph, refs = runner._owner_graph(marker)

    assert set(graph) == {
        "owner_account", "owner_household", "owner_identity_profile", "owner_cloud_profile",
        "owner_profile_binding", "owner_entitlement", "owner_principal",
        "owner_identity_membership", "owner_membership", "owner_account_guard", "owner_guard",
    }
    assert refs["household_id"] == graph["owner_household"]["household_id"]
    assert refs["owner_profile_id"] == graph["owner_cloud_profile"]["profile_id"]
    assert all(item["fixture_marker"] == marker for item in graph.values())
    assert graph["owner_membership"]["status"] == "active"
    assert graph["owner_guard"]["entity_type"] == "HouseholdMembershipOwnerGuard"


def test_private_credentials_are_created_once_with_mode_0600(tmp_path):
    path = tmp_path / "credentials.json"

    runner._private_json_write(path, {"email": "fixture@example.test", "password": "not-a-real-secret"})

    assert os.stat(path).st_mode & 0o777 == 0o600
    try:
        runner._private_json_write(path, {"email": "other@example.test", "password": "different"})
    except Exception as error:
        assert getattr(error, "code", "") == "FIXTURE_CREDENTIAL_PATH_EXISTS"
    else:
        raise AssertionError("existing credential path must be refused")
