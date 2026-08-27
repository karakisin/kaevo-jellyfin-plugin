import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "retire-production-duplicate-owner-profile.py"
SPEC = importlib.util.spec_from_file_location("retire_production_duplicate_owner_profile", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


ACCOUNT = "account-1"
HOUSEHOLD = "household-1"
SURVIVOR = "profile-survivor"
SURVIVOR_BINDING = "binding-survivor"
DUPLICATE = "profile-duplicate"
DUPLICATE_BINDING = "binding-duplicate"
INSTALLATION = "installation-1"
SOURCE = "lps1_" + "a" * 64


def records():
    old_guard_source = MODULE.mapping_guard_source_id(DUPLICATE)
    return {
        "survivor_profile": {
            "profile_id": SURVIVOR, "household_id": HOUSEHOLD,
            "entity_type": "Profile", "status": "active",
        },
        "survivor_binding": {
            "account_id": ACCOUNT, "profile_id": SURVIVOR,
            "binding_id": SURVIVOR_BINDING, "household_id": HOUSEHOLD,
            "entity_type": "ProfileBinding", "status": "active",
        },
        "survivor_identity_profile": {
            "profile_id": SURVIVOR, "account_id": ACCOUNT,
            "household_id": HOUSEHOLD, "state": "active",
            "jellyfin_binding_state": "active",
        },
        "survivor_profile_registry": {
            "account_id": ACCOUNT,
            "record_key": MODULE._resource_key("cloud_profile", SURVIVOR),
            "resource_type": "cloud_profile", "resource_id": SURVIVOR, "state": "active",
        },
        "survivor_binding_registry": {
            "account_id": ACCOUNT,
            "record_key": MODULE._resource_key("profile_binding", SURVIVOR_BINDING),
            "resource_type": "profile_binding", "resource_id": SURVIVOR_BINDING, "state": "active",
        },
        "duplicate_profile": {
            "profile_id": DUPLICATE, "household_id": HOUSEHOLD,
            "display_name": "My Profile", "entity_type": "Profile", "status": "active",
        },
        "duplicate_binding": {
            "account_id": ACCOUNT, "profile_id": DUPLICATE,
            "binding_id": DUPLICATE_BINDING, "household_id": HOUSEHOLD,
            "entity_type": "ProfileBinding", "status": "active",
        },
        "duplicate_identity_profile": None,
        "duplicate_profile_registry": {
            "account_id": ACCOUNT,
            "record_key": MODULE._resource_key("cloud_profile", DUPLICATE),
            "resource_type": "cloud_profile", "resource_id": DUPLICATE, "state": "active",
        },
        "duplicate_binding_registry": {
            "account_id": ACCOUNT,
            "record_key": MODULE._resource_key("profile_binding", DUPLICATE_BINDING),
            "resource_type": "profile_binding", "resource_id": DUPLICATE_BINDING, "state": "active",
        },
        "mapping": {
            "installation_id": INSTALLATION, "local_profile_source_id": SOURCE,
            "mapping_id": "mapping-1", "entity_type": "LocalProfileMapping",
            "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "cloud_profile_id": DUPLICATE, "mapping_state": "confirmed",
        },
        "old_guard": {
            "installation_id": INSTALLATION,
            "local_profile_source_id": old_guard_source,
            "mapping_id": "guard-1", "entity_type": "LocalProfileMappingGuard",
            "account_id": ACCOUNT, "household_id": HOUSEHOLD,
            "cloud_profile_id": DUPLICATE, "current_local_profile_source_id": SOURCE,
            "mapping_state": "active",
        },
        "new_guard": None,
        "duplicate_mapping_records": [
            {
                "installation_id": INSTALLATION,
                "local_profile_source_id": SOURCE,
                "mapping_state": "confirmed",
            },
            {
                "installation_id": INSTALLATION,
                "local_profile_source_id": old_guard_source,
                "mapping_state": "active",
            },
            {
                "installation_id": "old-installation",
                "local_profile_source_id": "lps1_" + "b" * 64,
                "mapping_state": "revoked",
            },
        ],
    }


def build(**changes):
    current = records()
    current.update(changes)
    return MODULE.build_retirement_transaction(
        **current,
        account_id=ACCOUNT,
        household_id=HOUSEHOLD,
        survivor_profile_id=SURVIVOR,
        survivor_binding_id=SURVIVOR_BINDING,
        duplicate_profile_id=DUPLICATE,
        duplicate_binding_id=DUPLICATE_BINDING,
        installation_id=INSTALLATION,
        local_profile_source_id=SOURCE,
        profiles_table="profiles",
        profile_bindings_table="profile-bindings",
        profile_mappings_table="profile-mappings",
        lifecycle_table="lifecycle",
        security_audit_table="audit",
        audit_item={"event_id": "event-1"},
        now_iso="2026-08-25T09:00:00+00:00",
        now_epoch=1787648400,
    )


def test_retirement_moves_exact_mapping_and_deletes_only_duplicate_records():
    transaction = build()

    assert len(transaction) == 8
    assert transaction[0]["Update"]["ExpressionAttributeValues"][":survivor"] == SURVIVOR
    assert transaction[1]["Delete"]["Key"]["local_profile_source_id"] == MODULE.mapping_guard_source_id(DUPLICATE)
    assert transaction[2]["Put"]["Item"]["cloud_profile_id"] == SURVIVOR
    assert transaction[3]["Delete"]["Key"] == {"profile_id": DUPLICATE}
    assert transaction[4]["Delete"]["Key"] == {"account_id": ACCOUNT, "profile_id": DUPLICATE}
    deleted_tables = [action["Delete"]["TableName"] for action in transaction if "Delete" in action]
    assert deleted_tables == ["profile-mappings", "profiles", "profile-bindings", "lifecycle", "lifecycle"]
    assert all(SURVIVOR not in str(action.get("Delete", {}).get("Key", {})) for action in transaction)


def test_retirement_fails_if_duplicate_has_another_active_mapping():
    current = records()["duplicate_mapping_records"] + [{
        "installation_id": "other-installation",
        "local_profile_source_id": "lps1_" + "c" * 64,
        "mapping_state": "confirmed",
    }]
    with pytest.raises(MODULE.RetirementError, match="another active installation"):
        build(duplicate_mapping_records=current)


def test_retirement_fails_if_duplicate_owns_provider_authority():
    with pytest.raises(MODULE.RetirementError, match="provider authority"):
        build(duplicate_identity_profile={"profile_id": DUPLICATE})


def test_retirement_fails_if_survivor_authority_changes():
    changed = records()["survivor_identity_profile"] | {"jellyfin_binding_state": "missing"}
    with pytest.raises(MODULE.RetirementError, match="provider authority changed"):
        build(survivor_identity_profile=changed)


def test_serialization_covers_conditional_transaction_fields():
    serialized = MODULE._serialize_transaction(build())

    assert serialized[0]["Update"]["Key"]["installation_id"] == {"S": INSTALLATION}
    assert serialized[0]["Update"]["ExpressionAttributeValues"][":survivor"] == {"S": SURVIVOR}
    assert serialized[3]["Delete"]["ExpressionAttributeNames"] == {"#status": "status"}
