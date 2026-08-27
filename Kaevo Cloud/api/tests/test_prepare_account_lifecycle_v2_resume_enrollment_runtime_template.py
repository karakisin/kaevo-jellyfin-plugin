import copy
import importlib.util
from pathlib import Path
import zipfile

import pytest


SCRIPT = (
    Path(__file__).parents[2] / "scripts"
    / "prepare-account-lifecycle-v2-resume-enrollment-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location(
    "prepare_lifecycle_v2_resume_enrollment_runtime", SCRIPT,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            MODULE.WORKER_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "old", "S3Key": "worker-old"},
                    "Handler": "account_lifecycle_v2_worker.lambda_handler",
                },
            },
            MODULE.ENROLLMENT_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "old", "S3Key": "enrollment-old"},
                    "Handler": "account_lifecycle_v2_enrollment.lambda_handler",
                },
            },
        },
    }


def test_preparer_changes_only_worker_and_enrollment_code():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(
        deployed,
        code_bucket="new-bucket",
        worker_code_key="worker-new",
        enrollment_code_key="enrollment-new",
    )

    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]
    assert prepared["Resources"][MODULE.WORKER_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "new-bucket", "S3Key": "worker-new",
    }
    assert prepared["Resources"][MODULE.ENROLLMENT_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "new-bucket", "S3Key": "enrollment-new",
    }


def test_preparer_fails_closed_if_handler_boundary_changed():
    deployed = deployed_template()
    deployed["Resources"][MODULE.WORKER_FUNCTION]["Properties"]["Handler"] = "other.handler"

    with pytest.raises(MODULE.ScopeError, match="function boundary changed"):
        MODULE.prepare_template(
            deployed,
            code_bucket="bucket",
            worker_code_key="worker",
            enrollment_code_key="enrollment",
        )


def test_artifact_validators_require_resume_and_exact_profile_contracts(tmp_path):
    worker = tmp_path / "worker.zip"
    with zipfile.ZipFile(worker, "w") as archive:
        archive.writestr("account_lifecycle_v2_worker.py", "EXECUTABLE_PHASES")
        archive.writestr(
            "account_lifecycle_v2_executor.py",
            "resume_phase OperationPhase.DELETING_KAEVO_GRAPH",
        )
        archive.writestr(
            "account_lifecycle_v2_aws.py",
            "resume_phase = :resume REMOVE failure_reason, resume_phase "
            "def _lifecycle_partition(): record_key != current_operation_key",
        )
        archive.writestr(
            "account_lifecycle_v2.py",
            "OperationPhase.RETRY_REQUIRED OperationPhase.VERIFYING_KAEVO_ABSENCE",
        )
    enrollment = tmp_path / "enrollment.zip"
    with zipfile.ZipFile(enrollment, "w") as archive:
        archive.writestr(
            "account_lifecycle_v2_enrollment.py",
            'Key={"principal_id": subject} '
            'active_by_type.get("identity_profile", set())',
        )

    MODULE.validate_worker_artifact(worker)
    MODULE.validate_enrollment_artifact(enrollment)

    with zipfile.ZipFile(enrollment, "w") as archive:
        archive.writestr(
            "account_lifecycle_v2_enrollment.py",
            'by_type.get("cloud_profile", "")',
        )
    with pytest.raises(MODULE.ScopeError, match="exact-subject profile contract"):
        MODULE.validate_enrollment_artifact(enrollment)


def test_preparer_never_mutates_input_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)

    MODULE.prepare_template(
        deployed,
        code_bucket="bucket",
        worker_code_key="worker",
        enrollment_code_key="enrollment",
    )

    assert deployed == original


def test_preparer_can_update_worker_while_retaining_current_enrollment_code():
    deployed = deployed_template()
    enrollment_code = copy.deepcopy(
        deployed["Resources"][MODULE.ENROLLMENT_FUNCTION]["Properties"]["Code"],
    )

    prepared = MODULE.prepare_template(
        deployed,
        code_bucket="old",
        worker_code_key="worker-new",
        enrollment_code_key=enrollment_code["S3Key"],
    )

    assert prepared["Resources"][MODULE.WORKER_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "old", "S3Key": "worker-new",
    }
    assert (
        prepared["Resources"][MODULE.ENROLLMENT_FUNCTION]["Properties"]["Code"]
        == enrollment_code
    )
