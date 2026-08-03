import json
import os

import pytest

from household_join_fixture import (
    canonical_invitation_code,
    invitation_code_hash,
    ProtectedFixtureManifest,
    record_fixture_transaction_key,
)


def test_fixture_code_is_trimmed_and_canonicalized_before_hashing():
    assert canonical_invitation_code("  ab12c-de34f  ") == "AB12C-DE34F"
    assert invitation_code_hash("  ab12c-de34f  ") == invitation_code_hash("AB12C-DE34F")


def test_fixture_hash_known_vector_uses_utf8_without_a_newline():
    assert invitation_code_hash("ab12c-de34f") == "ce8ebd893dbd1ff9a92777dc9dcc465e3a7535542f3414e2ebdb09b14a64d7c8"


@pytest.mark.parametrize("value", ["AB12C–DE34F", "AB12C-DE34", "AB12C_DE34F", "ＡＢ１２Ｃ-DE34F"])
def test_fixture_code_rejects_noncanonical_characters(value):
    with pytest.raises(ValueError):
        canonical_invitation_code(value)


def test_fixture_records_each_exact_transaction_key_immediately_and_deduplicates_retries():
    manifest = {}
    first_key = "a" * 64
    second_key = "b" * 64

    record_fixture_transaction_key(manifest, first_key)
    record_fixture_transaction_key(manifest, second_key)
    record_fixture_transaction_key(manifest, first_key)

    assert manifest["dynamic"]["transaction_keys"] == [first_key, second_key]


@pytest.mark.parametrize("transaction_key", ["", "A" * 64, "a" * 63, "not-a-key"])
def test_fixture_rejects_nonopaque_transaction_keys(transaction_key):
    with pytest.raises(ValueError):
        record_fixture_transaction_key({}, transaction_key)


def test_durable_manifest_journals_every_resource_and_multiple_transactions(tmp_path):
    root = tmp_path / "fixtures"
    manifest = ProtectedFixtureManifest.create(
        root, marker="fixture-a-01234567", account_id="123", region="us-west-2", table_arn_fingerprints={"joins": "fingerprint"},
    )
    manifest.record_resource("invitation", {"code_hash": "h"}, source_operation="invitation_create", bindings={"marker": "fixture-a-01234567"})
    manifest.record_transaction_key("a" * 64)
    manifest.record_transaction_key("b" * 64)
    manifest.mark_active_transaction("b" * 64)

    reloaded = ProtectedFixtureManifest.load(manifest.path, account_id="123", region="us-west-2")
    assert reloaded.payload["resources"]["transactions"]["keys"] == ["a" * 64, "b" * 64]
    assert reloaded.payload["resources"]["transactions"]["active_key"] == "b" * 64
    assert len(reloaded.payload["journal"]) == 5
    assert os.stat(manifest.path).st_mode & 0o077 == 0


def test_manifest_rejects_overwrite_and_stale_account_or_region(tmp_path):
    manifest = ProtectedFixtureManifest.create(tmp_path, marker="fixture-a-01234567", account_id="123", region="us-west-2", table_arn_fingerprints={"joins": "fingerprint"})
    manifest.record_resource("household", {"household_id": "h"}, source_operation="household_create", bindings={"marker": "fixture-a-01234567"})
    with pytest.raises(ValueError):
        manifest.record_resource("household", {"household_id": "other"}, source_operation="household_create", bindings={})
    with pytest.raises(ValueError):
        ProtectedFixtureManifest.load(manifest.path, account_id="other", region="us-west-2")
    with pytest.raises(ValueError):
        ProtectedFixtureManifest.load(manifest.path, account_id="123", region="eu-west-1")


def test_manifest_detects_directory_disappearance_and_binding_mismatch_without_cleanup(tmp_path):
    manifest = ProtectedFixtureManifest.create(tmp_path, marker="fixture-a-01234567", account_id="123", region="us-west-2", table_arn_fingerprints={"joins": "fingerprint"})
    manifest.record_resource("invitation", {"code_hash": "h"}, source_operation="invitation_create", bindings={"id": "expected", "household": "expected"})
    with pytest.raises(ValueError):
        manifest.cleanup_plan(observed_bindings={"invitation": {"id": "different", "household": "expected"}})
    manifest.path.unlink()
    with pytest.raises(ValueError):
        ProtectedFixtureManifest.load(manifest.path, account_id="123", region="us-west-2")


def test_manifest_cleanup_plan_returns_only_exact_previously_recorded_keys(tmp_path):
    manifest = ProtectedFixtureManifest.create(tmp_path, marker="fixture-a-01234567", account_id="123", region="us-west-2", table_arn_fingerprints={"joins": "fingerprint"})
    bindings = {"marker": "fixture-a-01234567", "household": "expected"}
    manifest.record_resource("invitation", {"code_hash": "known"}, source_operation="invitation_create", bindings=bindings)
    manifest.record_transaction_key("a" * 64)
    plan = manifest.cleanup_plan(observed_bindings={"invitation": bindings, "transactions": {}})
    assert plan["invitation"]["key"] == {"code_hash": "known"}
    assert plan["transactions"]["keys"] == ["a" * 64]


def test_manifest_replaces_only_the_exact_previously_journaled_resource(tmp_path):
    manifest = ProtectedFixtureManifest.create(tmp_path, marker="fixture-b-01234567", account_id="123", region="us-west-2", table_arn_fingerprints={"joins": "fingerprint"})
    manifest.record_resource("invitation", {"code_hash": "before"}, source_operation="invitation_create", bindings={"marker": "fixture-b-01234567"})

    manifest.replace_resource(
        "invitation",
        expected_key={"code_hash": "before"},
        replacement_key={"code_hash": "after"},
        source_operation="invitation_rotate",
        bindings={"marker": "fixture-b-01234567"},
    )

    assert manifest.payload["resources"]["invitation"]["key"] == {"code_hash": "after"}
    with pytest.raises(ValueError):
        manifest.replace_resource(
            "invitation",
            expected_key={"code_hash": "before"},
            replacement_key={"code_hash": "other"},
            source_operation="wrong",
            bindings={"marker": "fixture-b-01234567"},
        )


def test_manifest_cleanup_state_is_journaled_without_mutating_exact_resources(tmp_path):
    manifest = ProtectedFixtureManifest.create(
        tmp_path, marker="fixture-b-01234567", account_id="123", region="us-west-2", table_arn_fingerprints={"joins": "fingerprint"},
    )
    manifest.record_resource("invitation", {"code_hash": "known"}, source_operation="invitation_create", bindings={"marker": "fixture-b-01234567"})
    manifest.transition_cleanup_state("CLEANED", source_operation="exact_cleanup_complete")

    assert manifest.payload["cleanup"]["state"] == "CLEANED"
    assert manifest.payload["resources"]["invitation"]["key"] == {"code_hash": "known"}
