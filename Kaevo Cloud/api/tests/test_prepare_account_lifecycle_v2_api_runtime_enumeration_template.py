import copy
import importlib.util
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[2] / "scripts"
    / "prepare-account-lifecycle-v2-api-runtime-enumeration-template.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_lifecycle_v2_api_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            "KaevoAccountLifecycleV2ApiFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "old-bucket", "S3Key": "old-key"},
                    "Environment": {"Variables": {"EXISTING": "same"}},
                    "Role": {"Fn::GetAtt": ["KaevoAccountLifecycleV2ApiFunctionRole", "Arn"]},
                },
            },
            "KaevoAccountLifecycleV2ApiFunctionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"Policies": [
                    {"PolicyName": "Other", "PolicyDocument": {"Statement": []}},
                    {
                        "PolicyName": "KaevoAccountLifecycleV2ApiFunctionRolePolicy1",
                        "PolicyDocument": {"Statement": [{
                            "Sid": "VerifyDPoPBoundLifecycleV2Session",
                            "Effect": "Allow",
                            "Action": ["dynamodb:GetItem"],
                            "Resource": ["same"],
                        }]},
                    },
                ]},
            },
        },
    }


def test_preparer_changes_only_v2_api_code_and_exact_scan_policy():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(
        deployed, code_bucket="new-bucket", code_key="new-key",
    )

    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]
    function = prepared["Resources"]["KaevoAccountLifecycleV2ApiFunction"]
    assert function["Properties"]["Code"] == {
        "S3Bucket": "new-bucket", "S3Key": "new-key",
    }
    assert function["Properties"]["Environment"] == {"Variables": {"EXISTING": "same"}}
    policy = MODULE._policy(prepared["Resources"]["KaevoAccountLifecycleV2ApiFunctionRole"])
    statement = policy["PolicyDocument"]["Statement"][-1]
    assert statement == {
        "Sid": "EnumerateExactAccountLifecycleV2RuntimeResources",
        "Effect": "Allow",
        "Action": ["dynamodb:Scan"],
        "Resource": [
            {"Fn::GetAtt": ["KaevoInstallationsTable", "Arn"]},
            {"Fn::GetAtt": ["KaevoAppSessionsTable", "Arn"]},
        ],
    }


def test_preparer_fails_closed_if_scan_statement_already_exists():
    deployed = deployed_template()
    policy = MODULE._policy(deployed["Resources"]["KaevoAccountLifecycleV2ApiFunctionRole"])
    policy["PolicyDocument"]["Statement"].append({
        "Sid": "EnumerateExactAccountLifecycleV2RuntimeResources",
    })

    with pytest.raises(MODULE.ScopeError, match="already exists"):
        MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")


def test_preparer_never_mutates_input_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)

    MODULE.prepare_template(deployed, code_bucket="bucket", code_key="key")

    assert deployed == original
