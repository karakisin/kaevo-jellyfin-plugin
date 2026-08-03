from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "prepare-household-connector-access-template.py"
)
SPEC = importlib.util.spec_from_file_location(
    "prepare_household_connector_access_template", SCRIPT
)
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)


def test_candidate_includes_every_runtime_dependency_for_member_inheritance():
    deployed = {
        "Parameters": {},
        "Conditions": {},
        "Resources": {
            module.API_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "immutable", "S3Key": "old.zip"},
                    "Environment": {"Variables": {"HOME_CONNECTORS_TABLE": "connectors"}},
                },
            },
            module.API_ROLE: {
                "Type": "AWS::IAM::Role",
                "Properties": {"Policies": []},
            },
            module.MEMBERSHIPS_TABLE: {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {},
            },
            module.CONNECTORS_TABLE: {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "BillingMode": "PAY_PER_REQUEST",
                    "KeySchema": [{"AttributeName": "connector_id", "KeyType": "HASH"}],
                    "AttributeDefinitions": [
                        {"AttributeName": "connector_id", "AttributeType": "S"},
                        {"AttributeName": "profile_id", "AttributeType": "S"},
                        {"AttributeName": "updated_at", "AttributeType": "S"},
                    ],
                    "GlobalSecondaryIndexes": [{
                        "IndexName": module.PROFILE_INDEX,
                        "KeySchema": [
                            {"AttributeName": "profile_id", "KeyType": "HASH"},
                            {"AttributeName": "updated_at", "KeyType": "RANGE"},
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                    }],
                },
            },
        },
    }

    candidate = module.prepare_template(
        deployed,
        artifact_uri="s3://immutable/new.zip",
    )

    variables = candidate["Resources"][module.API_FUNCTION]["Properties"]["Environment"]["Variables"]
    assert variables[module.MEMBERSHIP_ENVIRONMENT_KEY] == {"Ref": module.MEMBERSHIPS_TABLE}
    policies = candidate["Resources"][module.API_ROLE]["Properties"]["Policies"]
    assert policies[-1]["PolicyDocument"]["Statement"][0]["Action"] == ["dynamodb:GetItem"]
    assert policies[-1]["PolicyDocument"]["Statement"][0]["Resource"] == {
        "Fn::GetAtt": [module.MEMBERSHIPS_TABLE, "Arn"]
    }
    connectors = candidate["Resources"][module.CONNECTORS_TABLE]["Properties"]
    assert any(index["IndexName"] == module.HOUSEHOLD_INDEX for index in connectors["GlobalSecondaryIndexes"])
