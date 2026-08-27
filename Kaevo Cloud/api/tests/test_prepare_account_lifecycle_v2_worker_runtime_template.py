import copy
import importlib.util
from pathlib import Path
import zipfile

import pytest


SCRIPT = (
    Path(__file__).parents[2] / "scripts"
    / "prepare-account-lifecycle-v2-worker-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_lifecycle_v2_worker_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            "KaevoAccountLifecycleV2WorkerFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "old-bucket", "S3Key": "old-key"},
                    "Handler": "account_lifecycle_v2_worker.lambda_handler",
                    "Environment": {"Variables": {"EXISTING": "same"}},
                    "Role": {"Fn::GetAtt": ["KaevoAccountLifecycleV2WorkerFunctionRole", "Arn"]},
                },
            },
            "KaevoAccountLifecycleV2ApiFunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"Policies": [{
                    "PolicyName": "KaevoAccountLifecycleV2ApiFunctionRolePolicy1",
                    "PolicyDocument": {"Statement": [copy.deepcopy(MODULE.ENUMERATION_STATEMENT)]},
                }]},
            },
            "KaevoAccountLifecycleV2EnrollmentFunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"Policies": [{
                    "PolicyName": "KaevoAccountLifecycleV2EnrollmentFunctionRolePolicy0",
                    "PolicyDocument": {"Statement": [{
                        "Sid": "CreateAccountLifecycleV2Atomically",
                        "Action": ["dynamodb:TransactWriteItems"],
                    }]},
                }]},
            },
        },
    }


def test_preparer_changes_only_worker_code_after_exact_enumeration_is_owned():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(
        deployed, code_bucket="new-bucket", code_key="new-key",
    )

    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]
    worker = prepared["Resources"]["KaevoAccountLifecycleV2WorkerFunction"]
    assert worker["Properties"]["Code"] == {
        "S3Bucket": "new-bucket", "S3Key": "new-key",
    }
    assert worker["Properties"]["Environment"] == {"Variables": {"EXISTING": "same"}}
    role = prepared["Resources"]["KaevoAccountLifecycleV2EnrollmentFunctionRole"]
    statements = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements[-1] == MODULE.ENROLLMENT_PUT_STATEMENT


def test_preparer_fails_closed_without_paired_runtime_enumeration_contract():
    deployed = deployed_template()
    role = deployed["Resources"]["KaevoAccountLifecycleV2ApiFunctionRole"]
    role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"] = []

    with pytest.raises(MODULE.ScopeError, match="enumeration contract is missing"):
        MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")


def test_preparer_fails_closed_if_worker_handler_changed():
    deployed = deployed_template()
    worker = deployed["Resources"]["KaevoAccountLifecycleV2WorkerFunction"]
    worker["Properties"]["Handler"] = "other.handler"

    with pytest.raises(MODULE.ScopeError, match="worker handler changed"):
        MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")


def test_preparer_fails_closed_if_transactional_put_statement_already_exists():
    deployed = deployed_template()
    role = deployed["Resources"]["KaevoAccountLifecycleV2EnrollmentFunctionRole"]
    role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
        copy.deepcopy(MODULE.ENROLLMENT_PUT_STATEMENT)
    )

    with pytest.raises(MODULE.ScopeError, match="already exists"):
        MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")


def test_worker_artifact_requires_refresh_execution_contract(tmp_path):
    incomplete = tmp_path / "incomplete.zip"
    with zipfile.ZipFile(incomplete, "w") as archive:
        archive.writestr("account_lifecycle_v2_worker.py", "def lambda_handler(): pass")
        archive.writestr("account_lifecycle_v2.py", 'RESOURCE_TYPES = {"account"}')
        archive.writestr("account_lifecycle_v2_aws.py", "class Graph: pass")

    with pytest.raises(MODULE.ScopeError, match="artifact contract missing"):
        MODULE.validate_worker_artifact(incomplete)


def test_worker_artifact_accepts_exact_refresh_execution_contract(tmp_path):
    complete = tmp_path / "complete.zip"
    with zipfile.ZipFile(complete, "w") as archive:
        archive.writestr("account_lifecycle_v2_worker.py", "def lambda_handler(): pass")
        archive.writestr("account_lifecycle_v2.py", 'RESOURCE_TYPES = {"app_session_refresh"}')
        archive.writestr(
            "account_lifecycle_v2_aws.py",
            '_PRIORITY = {"app_session_refresh": 5}\n'
            'KINDS = {"app_session_access", "app_session_refresh"}',
        )

    MODULE.validate_worker_artifact(complete)


def test_preparer_never_mutates_input_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)

    MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")

    assert deployed == original
