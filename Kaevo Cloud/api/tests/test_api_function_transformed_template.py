from __future__ import annotations

import importlib.util
import pathlib

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-api-function-transformed-template.py"
SPEC = importlib.util.spec_from_file_location("api_function_transformed_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def deployed_template():
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Conditions": {"IsDev": {"Fn::Equals": ["dev", "dev"]}},
        "Resources": {
            "LegacyV2Permission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {"FunctionName": "api"},
            },
            "KaevoCloudHttpApi": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"Body": {"legacy": True}},
            },
            "KaevoCloudApiFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Code": {"S3Bucket": "old", "S3Key": "old.zip"},
                    "Environment": {"Variables": {"KAEVO_ENV": "dev"}},
                    "Role": "unchanged",
                },
            },
            "KaevoIdentityClaimIssuerFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {"Code": {"S3Bucket": "old", "S3Key": "issuer.zip"}},
            },
        },
    }


def test_only_api_code_and_public_origin_change():
    deployed = deployed_template()
    prepared = MODULE.prepare_template(
        deployed,
        artifact_uri="s3://artifacts/account-repair.zip",
        public_api_base_url="https://api.kaevo.watch",
    )

    function = prepared["Resources"]["KaevoCloudApiFunction"]["Properties"]
    assert function["Code"] == {
        "S3Bucket": "artifacts",
        "S3Key": "account-repair.zip",
    }
    assert function["Environment"]["Variables"] == {
        "KAEVO_ENV": "dev",
        "PUBLIC_API_BASE_URL": "https://api.kaevo.watch",
    }
    assert function["Role"] == "unchanged"
    for name, resource in deployed["Resources"].items():
        if name != "KaevoCloudApiFunction":
            assert prepared["Resources"][name] == resource


@pytest.mark.parametrize(
    "origin",
    [
        "http://api.kaevo.watch",
        "https://user@api.kaevo.watch",
        "https://api.kaevo.watch/dev",
        "https://api.kaevo.watch?secret=value",
    ],
)
def test_public_origin_fails_closed(origin):
    with pytest.raises(ValueError, match="HTTPS origin"):
        MODULE.prepare_template(
            deployed_template(),
            artifact_uri="s3://artifacts/account-repair.zip",
            public_api_base_url=origin,
        )


def test_artifact_must_be_s3():
    with pytest.raises(ValueError, match="s3://"):
        MODULE.prepare_template(
            deployed_template(),
            artifact_uri="/tmp/account-repair.zip",
            public_api_base_url="https://api.kaevo.watch",
        )
