from __future__ import annotations

import importlib.util
import pathlib

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-social-identity-guard-code-template.py"
SPEC = importlib.util.spec_from_file_location("social_identity_guard_code_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def deployed() -> dict:
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Resources": {
            MODULE.FUNCTION: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "stable", "S3Key": "guard/old"},
                    "Environment": {"Variables": {"EXPECTED_USER_POOL_ID": "pool"}},
                    "Role": "unchanged-role",
                },
            },
            "KaevoUserPool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"LambdaConfig": {"PreSignUp": "unchanged-guard-arn"}},
            },
            "KaevoIdentityClaimIssuerFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {"Code": {"S3Bucket": "stable", "S3Key": "identity/old"}},
            },
        },
    }


def test_only_social_guard_code_object_changes():
    baseline = deployed()
    result = MODULE.prepare_template(baseline, "s3://candidate/guard/new?versionId=v1")
    assert result["Resources"][MODULE.FUNCTION]["Properties"]["Code"] == {
        "S3Bucket": "candidate",
        "S3Key": "guard/new",
        "S3ObjectVersion": "v1",
    }
    assert result["Resources"]["KaevoUserPool"] == baseline["Resources"]["KaevoUserPool"]
    assert (
        result["Resources"]["KaevoIdentityClaimIssuerFunction"]
        == baseline["Resources"]["KaevoIdentityClaimIssuerFunction"]
    )
    assert baseline["Resources"][MODULE.FUNCTION]["Properties"]["Code"]["S3Key"] == "guard/old"


@pytest.mark.parametrize(
    "value",
    [
        "https://bucket.example/guard.zip",
        "s3://",
        "s3://bucket/",
        "s3://bucket/key?unexpected=value",
    ],
)
def test_candidate_code_uri_must_be_a_narrow_s3_object(value):
    with pytest.raises(ValueError):
        MODULE.prepare_template(deployed(), value)


def test_missing_transformed_guard_fails_closed():
    baseline = deployed()
    baseline["Resources"][MODULE.FUNCTION]["Type"] = "AWS::Serverless::Function"
    with pytest.raises(ValueError, match="transformed"):
        MODULE.prepare_template(baseline, "s3://candidate/guard/new")
