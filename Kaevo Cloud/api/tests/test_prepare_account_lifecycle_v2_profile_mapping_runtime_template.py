import copy
import importlib.util
from pathlib import Path
import zipfile

import pytest


SCRIPT = (
    Path(__file__).parents[2] / "scripts"
    / "prepare-account-lifecycle-v2-profile-mapping-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_lifecycle_v2_mapping_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def policy(name, statements):
    return {"PolicyName": name, "PolicyDocument": {"Statement": statements}}


def function(handler):
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "Handler": handler,
            "Code": {"S3Bucket": "old", "S3Key": "old"},
            "Environment": {"Variables": {"EXISTING": "same"}},
        },
    }


def deployed_template():
    return {"Resources": {
        "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
        MODULE.API_FUNCTION: function("account_lifecycle_v2_api.lambda_handler"),
        MODULE.WORKER_FUNCTION: function("account_lifecycle_v2_worker.lambda_handler"),
        MODULE.API_ROLE: {
            "Type": "AWS::IAM::Role",
            "Properties": {"Policies": [policy(MODULE.API_POLICY, [{
                "Sid": MODULE.ENUMERATION_SID,
                "Effect": "Allow",
                "Action": ["dynamodb:Scan"],
                "Resource": [
                    MODULE._table_arn("KaevoInstallationsTable"),
                    MODULE._table_arn("KaevoAppSessionsTable"),
                ],
            }])]},
        },
        MODULE.WORKER_ROLE: {
            "Type": "AWS::IAM::Role",
            "Properties": {"Policies": [policy(MODULE.WORKER_POLICY, [{
                "Sid": MODULE.WORKER_GRAPH_SID,
                "Effect": "Allow",
                "Action": ["dynamodb:DeleteItem"],
                "Resource": [MODULE._table_arn("KaevoAccountsTable")],
            }])]},
        },
        MODULE.ENROLLMENT_ROLE: {
            "Type": "AWS::IAM::Role",
            "Properties": {"Policies": [policy(MODULE.ENROLLMENT_POLICY, [{
                "Sid": MODULE.ENROLLMENT_PUT_SID,
                "Effect": "Allow",
            }])]},
        },
    }}


def test_preparer_changes_only_exact_api_and_worker_runtime_boundary():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(deployed, code_bucket="new", code_key="artifact")
    resources = prepared["Resources"]

    assert resources["Unrelated"] == deployed["Resources"]["Unrelated"]
    for logical_id in (MODULE.API_FUNCTION, MODULE.WORKER_FUNCTION):
        function_resource = resources[logical_id]
        assert function_resource["Properties"]["Code"] == {
            "S3Bucket": "new", "S3Key": "artifact",
        }
        assert function_resource["Properties"]["Environment"]["Variables"][
            "PROFILE_MAPPINGS_TABLE"
        ] == {"Ref": MODULE.PROFILE_MAPPINGS_TABLE}
    enumeration = MODULE._statement(
        MODULE._policy(resources, MODULE.API_ROLE, MODULE.API_POLICY),
        MODULE.ENUMERATION_SID,
    )
    assert enumeration["Resource"][-1] == MODULE._table_arn(MODULE.PROFILE_MAPPINGS_TABLE)
    graph = MODULE._statement(
        MODULE._policy(resources, MODULE.WORKER_ROLE, MODULE.WORKER_POLICY),
        MODULE.WORKER_GRAPH_SID,
    )
    assert graph["Resource"][-1] == MODULE._table_arn(MODULE.PROFILE_MAPPINGS_TABLE)


def test_preparer_fails_closed_if_existing_scan_boundary_changed():
    deployed = deployed_template()
    statement = MODULE._statement(
        MODULE._policy(deployed["Resources"], MODULE.API_ROLE, MODULE.API_POLICY),
        MODULE.ENUMERATION_SID,
    )
    statement["Resource"].append(MODULE._table_arn("UnexpectedTable"))

    with pytest.raises(MODULE.ScopeError, match="resource boundary changed"):
        MODULE.prepare_template(deployed, code_bucket="new", code_key="artifact")


def test_preparer_never_mutates_input_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)
    MODULE.prepare_template(deployed, code_bucket="new", code_key="artifact")
    assert deployed == original


def test_artifact_requires_profile_mapping_api_and_worker_contract(tmp_path):
    incomplete = tmp_path / "incomplete.zip"
    with zipfile.ZipFile(incomplete, "w") as archive:
        for name in (
            "account_lifecycle_v2.py",
            "account_lifecycle_v2_service.py",
            "account_lifecycle_v2_api.py",
            "account_lifecycle_v2_aws.py",
            "account_lifecycle_v2_worker.py",
        ):
            archive.writestr(name, "pass")
    with pytest.raises(MODULE.ScopeError, match="artifact contract missing"):
        MODULE.validate_runtime_artifact(incomplete)
