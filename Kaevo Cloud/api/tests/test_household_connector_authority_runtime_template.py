from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "prepare-household-connector-authority-runtime-template.py"
)
SPEC = importlib.util.spec_from_file_location(
    "prepare_household_connector_authority_runtime_template", SCRIPT
)
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)


def baseline() -> dict:
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Conditions": {},
        "Resources": {
            module.API_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "immutable", "S3Key": "api.zip"},
                    "Environment": {"Variables": {"HOME_CONNECTORS_TABLE": "connectors"}},
                },
            },
            module.API_ROLE: {
                "Type": "AWS::IAM::Role",
                "Properties": {"Policies": [{
                    "PolicyName": "ExistingPolicy",
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": []},
                }]},
            },
            module.MEMBERSHIPS_TABLE: {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {},
            },
            "Unrelated": {"Type": "AWS::S3::Bucket", "Properties": {}},
        },
    }


def test_adds_only_exact_membership_environment_and_read_permission():
    deployed = baseline()
    candidate = module.prepare_template(deployed)

    variables = candidate["Resources"][module.API_FUNCTION]["Properties"]["Environment"]["Variables"]
    assert variables[module.ENVIRONMENT_KEY] == {"Ref": module.MEMBERSHIPS_TABLE}
    policies = candidate["Resources"][module.API_ROLE]["Properties"]["Policies"]
    policy = next(item for item in policies if item["PolicyName"] == module.POLICY_NAME)
    assert policy["PolicyDocument"]["Statement"] == [{
        "Sid": "ReadCanonicalHouseholdMembershipForConnectorAccess",
        "Effect": "Allow",
        "Action": ["dynamodb:GetItem"],
        "Resource": {"Fn::GetAtt": [module.MEMBERSHIPS_TABLE, "Arn"]},
    }]
    assert candidate["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]


@pytest.mark.parametrize("existing", ["environment", "policy"])
def test_refuses_to_reapply_over_existing_runtime_binding(existing):
    deployed = baseline()
    if existing == "environment":
        deployed["Resources"][module.API_FUNCTION]["Properties"]["Environment"]["Variables"][module.ENVIRONMENT_KEY] = {
            "Ref": module.MEMBERSHIPS_TABLE
        }
    else:
        deployed["Resources"][module.API_ROLE]["Properties"]["Policies"].append(
            module._membership_read_policy()
        )

    with pytest.raises(ValueError, match="already exists"):
        module.prepare_template(deployed)
