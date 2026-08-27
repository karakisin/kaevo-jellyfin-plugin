import copy
import importlib.util
from pathlib import Path
import zipfile

import pytest


SCRIPT = (
    Path(__file__).parents[2] / "scripts"
    / "prepare-account-lifecycle-v2-confirm-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_lifecycle_v2_confirm_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {"Resources": {
        "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
        MODULE.API_FUNCTION: {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "Handler": "account_lifecycle_v2_api.lambda_handler",
                "Code": {"S3Bucket": "old", "S3Key": "old"},
                "Environment": {"Variables": {
                    "PROFILE_MAPPINGS_TABLE": {"Ref": MODULE.PROFILE_MAPPINGS_TABLE},
                }},
            },
        },
    }}


def test_preparer_changes_only_exact_v2_api_runtime():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(deployed, code_bucket="new", code_key="artifact")

    assert prepared["Resources"][MODULE.API_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "new", "S3Key": "artifact",
    }
    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]


def test_preparer_fails_closed_if_environment_boundary_changed():
    deployed = deployed_template()
    deployed["Resources"][MODULE.API_FUNCTION]["Properties"]["Environment"][
        "Variables"
    ].pop("PROFILE_MAPPINGS_TABLE")

    with pytest.raises(MODULE.ScopeError, match="environment boundary changed"):
        MODULE.prepare_template(deployed, code_bucket="new", code_key="artifact")


def test_preparer_never_mutates_input_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)
    MODULE.prepare_template(deployed, code_bucket="new", code_key="artifact")
    assert deployed == original


def test_artifact_requires_reserved_scope_alias_and_failure_classification(tmp_path):
    incomplete = tmp_path / "incomplete.zip"
    with zipfile.ZipFile(incomplete, "w") as archive:
        archive.writestr(
            "account_lifecycle_v2.py",
            '''digest_payload = {
    "lifecycle_revision": int(root["revision"]),
}
plan_digest=_canonical_digest(digest_payload)
''',
        )
        archive.writestr("account_lifecycle_v2_api.py", "def lambda_handler(): pass")
        archive.writestr("account_lifecycle_v2_service.py", "pass")

    with pytest.raises(MODULE.ScopeError, match="artifact contract missing"):
        MODULE.validate_runtime_artifact(incomplete)


def test_artifact_rejects_operation_bound_plan_digest(tmp_path):
    artifact = tmp_path / "operation-bound.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "account_lifecycle_v2.py",
            '''digest_payload = {
    "operation_id": operation_id,
    "lifecycle_revision": int(root["revision"]),
}
plan_digest=_canonical_digest(digest_payload)
''',
        )
        archive.writestr("account_lifecycle_v2_api.py", "def lambda_handler(): pass")
        archive.writestr(
            "account_lifecycle_v2_service.py",
            '''"#scope": "scope"
"AND #phase = :awaiting AND #scope = :everything "
"AND provider_capability IN (:enabled, :not_applicable)"
LifecycleV2StorageError("operation_queue_failed")
''',
        )

    with pytest.raises(MODULE.ScopeError, match="binds semantic plan digest"):
        MODULE.validate_runtime_artifact(artifact)
