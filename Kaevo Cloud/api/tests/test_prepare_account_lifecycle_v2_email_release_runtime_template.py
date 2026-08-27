import copy
import importlib.util
from pathlib import Path
import zipfile

import pytest


SCRIPT = (
    Path(__file__).parents[2]
    / "scripts"
    / "prepare-account-lifecycle-v2-email-release-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location(
    "prepare_lifecycle_v2_email_release_runtime", SCRIPT
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            MODULE.API_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "account_lifecycle_v2_api.lambda_handler",
                    "Code": {"S3Bucket": "old", "S3Key": "old-api"},
                },
            },
            MODULE.WORKER_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "account_lifecycle_v2_worker.lambda_handler",
                    "Code": {"S3Bucket": "old", "S3Key": "old-worker"},
                    "Environment": {
                        "Variables": {
                            "AUTH_IDENTITIES_TABLE": {"Ref": MODULE.AUTH_IDENTITIES_TABLE},
                            "COGNITO_USER_POOL_ID": {"Ref": MODULE.USER_POOL},
                        }
                    },
                },
            },
        }
    }


def test_preparer_changes_only_exact_api_and_worker_code():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(
        deployed,
        code_bucket="new",
        api_code_key="api-artifact",
        worker_code_key="worker-artifact",
    )

    assert prepared["Resources"][MODULE.API_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "new",
        "S3Key": "api-artifact",
    }
    assert prepared["Resources"][MODULE.WORKER_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "new",
        "S3Key": "worker-artifact",
    }
    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]


def test_preparer_fails_closed_if_worker_authority_boundary_changed():
    deployed = deployed_template()
    deployed["Resources"][MODULE.WORKER_FUNCTION]["Properties"]["Environment"][
        "Variables"
    ].pop("AUTH_IDENTITIES_TABLE")

    with pytest.raises(MODULE.ScopeError, match="AuthIdentity boundary changed"):
        MODULE.prepare_template(
            deployed,
            code_bucket="new",
            api_code_key="api-artifact",
            worker_code_key="worker-artifact",
        )


def test_preparer_allows_api_only_followup_without_rewriting_worker():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(
        deployed,
        code_bucket="old",
        api_code_key="new-api",
        worker_code_key="old-worker",
    )

    assert prepared["Resources"][MODULE.API_FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "old",
        "S3Key": "new-api",
    }
    assert prepared["Resources"][MODULE.WORKER_FUNCTION] == deployed["Resources"][
        MODULE.WORKER_FUNCTION
    ]


def test_preparer_never_mutates_input_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)
    MODULE.prepare_template(
        deployed,
        code_bucket="new",
        api_code_key="api-artifact",
        worker_code_key="worker-artifact",
    )
    assert deployed == original


def test_artifacts_require_email_absence_contract(tmp_path):
    api = tmp_path / "api.zip"
    worker = tmp_path / "worker.zip"
    with zipfile.ZipFile(api, "w") as archive:
        archive.writestr("account_lifecycle_v2_api.py", "def lambda_handler(): pass")
        archive.writestr("account_lifecycle_v2_service.py", "pass")
        archive.writestr("account_lifecycle_v2_status_token.py", "pass")
    with zipfile.ZipFile(worker, "w") as archive:
        archive.writestr("account_lifecycle_v2_aws.py", "pass")
        archive.writestr("account_lifecycle_v2_executor.py", "pass")
        archive.writestr("account_lifecycle_v2_worker.py", "pass")

    with pytest.raises(MODULE.ScopeError, match="email-absence proof"):
        MODULE.validate_api_artifact(api)
    with pytest.raises(MODULE.ScopeError, match="runtime contract is missing"):
        MODULE.validate_worker_artifact(worker)
