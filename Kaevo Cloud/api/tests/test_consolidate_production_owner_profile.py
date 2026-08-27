import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "consolidate-production-owner-profile.py"
SPEC = importlib.util.spec_from_file_location("consolidate_production_owner_profile", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


ACCOUNT = "account-1"
HOUSEHOLD = "household-1"
OWNER = "subject-1"
SURVIVOR = "profile-survivor"
DUPLICATE = "profile-duplicate"
CONNECTOR = "connector-1"
JELLYFIN = "jellyfin-user-1"
INSTALLATION = "installation-1"
SOURCE = "lps1_" + "a" * 64


def records():
    old_guard_source = MODULE.mapping_guard_source_id(DUPLICATE)
    return {
        "identity_profile": {
            "profile_id": SURVIVOR, "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "display_name": "My Profile",
            "state": "active", "jellyfin_binding_state": "active",
            "jellyfin_connector_id": CONNECTOR, "jellyfin_user_id": JELLYFIN,
            "created_at": "2026-08-21T19:37:20Z",
        },
        "principal": {
            "principal_id": OWNER, "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "state": "active", "profile_ids": [SURVIVOR],
        },
        "identity_membership": {
            "principal_id": OWNER, "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "profile_id": SURVIVOR, "state": "active",
        },
        "identity_household": {
            "household_id": HOUSEHOLD, "account_id": ACCOUNT,
            "owner_principal_id": OWNER, "state": "active",
        },
        "connector": {
            "connector_id": CONNECTOR, "profile_id": SURVIVOR,
            "state": "active", "revoked": False,
        },
        "duplicate_profile": {
            "profile_id": DUPLICATE, "household_id": HOUSEHOLD,
            "entity_type": "Profile", "status": "active",
        },
        "duplicate_binding": {
            "account_id": ACCOUNT, "profile_id": DUPLICATE, "household_id": HOUSEHOLD,
            "entity_type": "ProfileBinding", "status": "active",
        },
        "mapping": {
            "installation_id": INSTALLATION, "local_profile_source_id": SOURCE,
            "mapping_id": "mapping-1", "entity_type": "LocalProfileMapping",
            "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "cloud_profile_id": DUPLICATE, "mapping_state": "confirmed",
        },
        "old_guard": {
            "installation_id": INSTALLATION, "local_profile_source_id": old_guard_source,
            "mapping_id": "guard-1", "entity_type": "LocalProfileMappingGuard",
            "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "cloud_profile_id": DUPLICATE, "current_local_profile_source_id": SOURCE,
            "mapping_state": "active",
        },
        "survivor_profile": None,
        "survivor_binding": None,
        "new_guard": None,
    }


def build(**changes):
    current = records()
    current.update(changes)
    return MODULE.build_consolidation_transaction(
        **current,
        account_id=ACCOUNT,
        household_id=HOUSEHOLD,
        owner_subject=OWNER,
        survivor_profile_id=SURVIVOR,
        duplicate_profile_id=DUPLICATE,
        connector_id=CONNECTOR,
        jellyfin_user_id=JELLYFIN,
        installation_id=INSTALLATION,
        local_profile_source_id=SOURCE,
        display_name="Jefferson",
        identity_profiles_table="identity-profiles",
        profiles_table="profiles",
        profile_bindings_table="profile-bindings",
        profile_mappings_table="profile-mappings",
        lifecycle_table="lifecycle",
        security_audit_table="audit",
        audit_item={"event_id": "event-1"},
        now_iso="2026-08-25T08:00:00+00:00",
        now_epoch=1787644800,
    )


def test_phase_one_preserves_duplicate_until_readback_and_moves_only_exact_mapping():
    transaction = build()

    assert len(transaction) == 9
    assert transaction[0]["Put"]["Item"]["profile_id"] == SURVIVOR
    assert transaction[0]["Put"]["Item"]["display_name"] == "Jefferson"
    assert transaction[1]["Put"]["Item"]["profile_id"] == SURVIVOR
    assert transaction[2]["Update"]["Key"] == {"profile_id": SURVIVOR}
    assert transaction[3]["Update"]["Key"]["local_profile_source_id"] == SOURCE
    assert transaction[3]["Update"]["ExpressionAttributeValues"][":survivor"] == SURVIVOR
    assert transaction[4]["Delete"]["Key"]["local_profile_source_id"] == MODULE.mapping_guard_source_id(DUPLICATE)
    assert transaction[5]["Put"]["Item"]["cloud_profile_id"] == SURVIVOR
    assert all(
        not ("Delete" in action and action["Delete"]["TableName"] in {"profiles", "profile-bindings"})
        for action in transaction
    )


def test_phase_one_fails_closed_if_provider_authority_changed():
    changed = records()["identity_profile"] | {"jellyfin_user_id": "other-user"}
    with pytest.raises(MODULE.ConsolidationError, match="provider authority changed"):
        build(identity_profile=changed)


def test_phase_one_fails_closed_if_survivor_is_already_materialized():
    with pytest.raises(MODULE.ConsolidationError, match="already exists"):
        build(survivor_profile={"profile_id": SURVIVOR})


def test_phase_one_fails_closed_if_mapping_no_longer_targets_duplicate():
    changed = records()["mapping"] | {"cloud_profile_id": SURVIVOR}
    with pytest.raises(MODULE.ConsolidationError, match="iPhone mapping changed"):
        build(mapping=changed)


def test_low_level_serialization_covers_items_keys_and_condition_values():
    serialized = MODULE._serialize_transaction(build())

    assert serialized[0]["Put"]["Item"]["profile_id"] == {"S": SURVIVOR}
    assert serialized[2]["Update"]["Key"]["profile_id"] == {"S": SURVIVOR}
    assert serialized[3]["Update"]["ExpressionAttributeValues"][":survivor"] == {"S": SURVIVOR}
