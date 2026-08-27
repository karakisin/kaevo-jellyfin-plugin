import copy
import importlib.util
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[2]
    / "scripts"
    / "prepare-production-identity-ownership-template.py"
)
SPEC = importlib.util.spec_from_file_location("prepare_production_identity_ownership", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Resources": {
            "Unrelated": {"Type": "Safe::Resource", "Properties": {"Value": "same"}},
            MODULE.CLAIM_FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Environment": {
                        "Variables": {
                            "UNCHANGED": "same",
                            "EXPECTED_NATIVE_CLIENT_NAME": {"Fn::If": ["Old", "x", ""]},
                            "EXPECTED_NATIVE_CALLBACK_URI": {"Fn::If": ["Old", "x", ""]},
                            "EXPECTED_NATIVE_LOGOUT_URI": {"Fn::If": ["Old", "x", ""]},
                        }
                    }
                },
            },
            MODULE.OWNER_ROLE: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [{
                        "PolicyName": "owner",
                        "PolicyDocument": {
                            "Statement": [
                                {
                                    "Sid": "BootstrapAuthoritativeIdentityGraph",
                                    "Effect": "Allow",
                                    "Action": [
                                        "dynamodb:GetItem",
                                        "dynamodb:PutItem",
                                        "dynamodb:TransactWriteItems",
                                    ],
                                    "Resource": [
                                        {"Fn::GetAtt": ["KaevoAccountsTable", "Arn"]}
                                    ],
                                },
                                {
                                    "Sid": "ReadAuditReferenceKey",
                                    "Effect": "Allow",
                                    "Action": ["secretsmanager:GetSecretValue"],
                                    "Resource": {"Ref": "KaevoAuditReferenceSecret"},
                                },
                            ]
                        },
                    }]
                },
            },
        }
    }


def test_preparer_imports_only_source_owned_production_identity_contracts():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(deployed)

    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]
    variables = prepared["Resources"][MODULE.CLAIM_FUNCTION]["Properties"][
        "Environment"
    ]["Variables"]
    assert variables["UNCHANGED"] == "same"
    assert variables["EXPECTED_NATIVE_CLIENT_NAME"]["Fn::If"][2]["Fn::If"] == [
        "IsProduction",
        "kaevo-cloud-production-native-oidc",
        {"Fn::If": ["IsDevelopment", "kaevo-cloud-dev-native-oidc", ""]},
    ]
    assert variables["EXPECTED_NATIVE_CALLBACK_URI"]["Fn::If"][2]["Fn::If"] == [
        "IsProduction",
        "kaevo://oauth/callback",
        {"Fn::If": ["IsDevelopment", "kaevo://oauth/callback", ""]},
    ]
    assert variables["EXPECTED_NATIVE_LOGOUT_URI"]["Fn::If"][2]["Fn::If"] == [
        "IsProduction",
        "kaevo://oauth/logout",
        {"Fn::If": ["IsDevelopment", "kaevo://oauth/logout", ""]},
    ]

    statements = prepared["Resources"][MODULE.OWNER_ROLE]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"]
    bootstrap = next(s for s in statements if s["Sid"] == "BootstrapAuthoritativeIdentityGraph")
    assert "dynamodb:UpdateItem" in bootstrap["Action"]
    assert {"Fn::GetAtt": ["KaevoHouseholdMembershipsTable", "Arn"]} in bootstrap[
        "Resource"
    ]
    exact_user = next(s for s in statements if s["Sid"] == "ReadExactEnrollingCognitoUser")
    assert exact_user["Action"] == ["cognito-idp:AdminGetUser"]


def test_preparer_never_mutates_the_deployed_template():
    deployed = deployed_template()
    original = copy.deepcopy(deployed)
    MODULE.prepare_template(deployed)
    assert deployed == original


def test_preparer_fails_closed_without_expected_owner_policy():
    deployed = deployed_template()
    deployed["Resources"][MODULE.OWNER_ROLE]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]["Sid"] = "Unexpected"

    with pytest.raises(MODULE.ScopeError, match="owner bootstrap policy"):
        MODULE.prepare_template(deployed)
