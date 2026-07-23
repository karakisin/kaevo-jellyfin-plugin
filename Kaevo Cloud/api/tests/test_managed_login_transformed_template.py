from __future__ import annotations

import importlib.util
import pathlib

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare-managed-login-transformed-template.py"
SPEC = importlib.util.spec_from_file_location("managed_login_transformed_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def templates():
    deployed = {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Conditions": {"HasNativeOidc": {"Fn::Equals": ["dev", "dev"]}},
        "Resources": {
            "LegacyV2Permission": {"Type": "AWS::Lambda::Permission", "Properties": {"Route": "/v2"}},
            "KaevoCloudHttpApi": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"Body": {"legacy": True}}},
            "KaevoIdentityClaimIssuerFunction": {"Properties": {"Code": {"S3Bucket": "old", "S3Key": "old"}}},
            "KaevoSecurityStageManagedLoginBranding": {"Properties": {"UseCognitoProvidedValues": True}},
            "KaevoSecurityStageNativeOidcClient": {"Properties": {"SupportedIdentityProviders": ["COGNITO"]}},
        },
    }
    candidate = {
        "Parameters": {
            "GoogleIdentityProviderSecretArn": {"Type": "String", "Default": ""},
            "AppleIdentityProviderSecretArn": {"Type": "String", "Default": ""},
        },
        "Conditions": {
            "HasGoogleIdentityProvider": {"Fn::Not": [{"Fn::Equals": ["", ""]}]},
            "HasAppleIdentityProvider": {"Fn::Not": [{"Fn::Equals": ["", ""]}]},
        },
        "Resources": {
            "KaevoIdentityClaimIssuerFunction": {
                "Properties": {
                    "Code": {"S3Bucket": "new", "S3Key": "identity"},
                    "Environment": {"Variables": {
                        "EXPECTED_NATIVE_GOOGLE_ENABLED": "false",
                        "EXPECTED_NATIVE_APPLE_ENABLED": "false",
                    }},
                }
            },
            "KaevoSecurityStageManagedLoginBranding": {
                "Properties": {"UseCognitoProvidedValues": False, "Settings": {"brand": "kaevo"}}
            },
            "KaevoSecurityStageNativeOidcClient": {"Properties": {"SupportedIdentityProviders": ["COGNITO"]}},
            "KaevoGoogleIdentityProvider": {"Type": "AWS::Cognito::UserPoolIdentityProvider"},
            "KaevoAppleIdentityProvider": {"Type": "AWS::Cognito::UserPoolIdentityProvider"},
            "KaevoCloudHttpApi": {"Properties": {"Body": {"legacy": False}}},
        },
    }
    return deployed, candidate


def test_deployed_routes_and_permissions_are_preserved_exactly():
    deployed, candidate = templates()
    result = MODULE.prepare_template(deployed, candidate)
    assert result["Resources"]["LegacyV2Permission"] == deployed["Resources"]["LegacyV2Permission"]
    assert result["Resources"]["KaevoCloudHttpApi"] == deployed["Resources"]["KaevoCloudHttpApi"]
    assert result["Resources"]["KaevoIdentityClaimIssuerFunction"] == candidate["Resources"]["KaevoIdentityClaimIssuerFunction"]


def test_identity_issuer_cannot_receive_provider_credentials():
    deployed, candidate = templates()
    candidate["Resources"]["KaevoIdentityClaimIssuerFunction"]["Properties"]["Environment"]["Variables"][
        "GoogleIdentityProviderSecretArn"
    ] = "forbidden"
    with pytest.raises(ValueError, match="must not receive"):
        MODULE.prepare_template(deployed, candidate)


def test_missing_allowlisted_resource_fails_closed():
    deployed, candidate = templates()
    del candidate["Resources"]["KaevoAppleIdentityProvider"]
    with pytest.raises(ValueError, match="missing resources"):
        MODULE.prepare_template(deployed, candidate)


def test_branding_only_mode_preserves_every_other_deployed_resource():
    deployed, candidate = templates()
    result = MODULE.prepare_branding_only_template(deployed, candidate)
    assert result["Resources"]["KaevoSecurityStageManagedLoginBranding"] == candidate["Resources"][
        "KaevoSecurityStageManagedLoginBranding"
    ]
    for name, resource in deployed["Resources"].items():
        if name != "KaevoSecurityStageManagedLoginBranding":
            assert result["Resources"][name] == resource
    assert set(result["Parameters"]) == set(deployed["Parameters"])
    assert set(result["Conditions"]) == set(deployed["Conditions"])
