import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "rebind-production-profile-mapping.py"
SPEC = importlib.util.spec_from_file_location("rebind_production_profile_mapping", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


INSTALLATION = "installation-1"
ACCOUNT = "acct_1"
HOUSEHOLD = "household-1"
CLOUD = "prf1_cloud"
OLD_ONE = "lps1_" + "1" * 64
OLD_TWO = "lps1_" + "2" * 64
NEW = "lps1_" + "3" * 64


def record(source, mapping_id):
    return {
        "installation_id": INSTALLATION,
        "local_profile_source_id": source,
        "mapping_id": mapping_id,
        "entity_type": "LocalProfileMapping",
        "account_id": ACCOUNT,
        "household_id": HOUSEHOLD,
        "cloud_profile_id": CLOUD,
        "mapping_state": "confirmed",
    }


def build(records, expected):
    return MODULE.build_rebind_transaction(
        records,
        profile_mappings_table="mappings",
        security_audit_table="audit",
        installation_id=INSTALLATION,
        account_id=ACCOUNT,
        household_id=HOUSEHOLD,
        cloud_profile_id=CLOUD,
        new_source=NEW,
        expected_old_sources=expected,
        audit_item={"event_id": "event-1"},
        now_iso="2026-08-24T00:00:00Z",
        now_epoch=1,
    )


def test_repair_rebinds_only_the_frozen_confirmed_source_set():
    transaction = build(
        [record(OLD_ONE, "mapping-1"), record(OLD_TWO, "mapping-2")],
        {OLD_ONE, OLD_TWO},
    )

    assert len(transaction) == 5
    assert transaction[0]["Put"]["Item"]["local_profile_source_id"] == NEW
    revoked = [item["Update"]["Key"]["local_profile_source_id"] for item in transaction[1:3]]
    assert revoked == [OLD_ONE, OLD_TWO]
    assert transaction[3]["Put"]["Item"]["current_local_profile_source_id"] == NEW
    assert transaction[4]["Put"]["TableName"] == "audit"


def test_repair_rejects_an_unplanned_confirmed_source():
    with pytest.raises(MODULE.RepairError, match="frozen plan"):
        build(
            [record(OLD_ONE, "mapping-1"), record(OLD_TWO, "mapping-2")],
            {OLD_ONE},
        )


def test_repair_rejects_an_existing_guard():
    guard = {
        "installation_id": INSTALLATION,
        "local_profile_source_id": MODULE.mapping_guard_source_id(CLOUD),
        "entity_type": "LocalProfileMappingGuard",
    }
    with pytest.raises(MODULE.RepairError, match="guard already exists"):
        build([record(OLD_ONE, "mapping-1"), guard], {OLD_ONE})
