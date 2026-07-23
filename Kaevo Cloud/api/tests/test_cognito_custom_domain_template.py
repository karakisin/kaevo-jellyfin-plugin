from __future__ import annotations

import importlib.util
import pathlib

import pytest
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra" / "template.yaml"
SCRIPT = ROOT / "scripts" / "prepare-cognito-custom-domain-template.py"
SPEC = importlib.util.spec_from_file_location("cognito_custom_domain_template", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Loader(yaml.SafeLoader):
    pass


def _construct_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    tags = {
        "Ref": "Ref",
        "GetAtt": "Fn::GetAtt",
        "Sub": "Fn::Sub",
        "Equals": "Fn::Equals",
        "Not": "Fn::Not",
        "And": "Fn::And",
        "Condition": "Condition",
    }
    return {tags.get(tag_suffix, f"Fn::{tag_suffix}"): value}


Loader.add_multi_constructor("!", _construct_tag)


def template():
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=Loader)


def candidate():
    return {
        "Parameters": {
            "CognitoCustomDomainName": {"Type": "String", "Default": ""},
            "CognitoCustomDomainCertificateArn": {"Type": "String", "Default": ""},
        },
        "Conditions": {"HasCognitoCustomDomain": {"Fn::And": [True, True]}},
        "Resources": {
            "KaevoCustomUserPoolDomain": {
                "Type": "AWS::Cognito::UserPoolDomain",
                "Properties": {
                    "UserPoolId": {"Ref": "KaevoUserPool"},
                    "Domain": {"Ref": "CognitoCustomDomainName"},
                    "ManagedLoginVersion": 2,
                    "CustomDomainConfig": {
                        "CertificateArn": {"Ref": "CognitoCustomDomainCertificateArn"}
                    },
                },
            }
        },
        "Outputs": {name: {"Value": name} for name in MODULE.COPIED_OUTPUTS},
    }


def deployed():
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Conditions": {"HasNativeOidc": {"Fn::Equals": ["dev", "dev"]}},
        "Resources": {
            "KaevoUserPool": {"Type": "AWS::Cognito::UserPool"},
            "LegacyV2Permission": {"Type": "AWS::Lambda::Permission"},
            "KaevoCloudHttpApi": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"legacy": True}},
        },
        "Outputs": {"LegacyOutput": {"Value": "preserved"}},
    }


def test_source_template_defines_additive_custom_domain_without_replacing_prefix_domain():
    data = template()
    resources = data["Resources"]
    assert resources["KaevoSecurityStageUserPoolDomain"]["Properties"]["ManagedLoginVersion"] == 2
    custom = resources["KaevoCustomUserPoolDomain"]
    assert custom["Type"] == "AWS::Cognito::UserPoolDomain"
    assert custom["Properties"]["UserPoolId"] == {"Ref": "KaevoUserPool"}
    assert custom["Properties"]["CustomDomainConfig"] == {
        "CertificateArn": {"Ref": "CognitoCustomDomainCertificateArn"}
    }


def test_narrow_generator_preserves_every_deployed_resource_exactly():
    baseline = deployed()
    result = MODULE.prepare_template(baseline, candidate())
    for name, resource in baseline["Resources"].items():
        assert result["Resources"][name] == resource
    assert set(result["Resources"]) - set(baseline["Resources"]) == {"KaevoCustomUserPoolDomain"}
    assert result["Outputs"]["LegacyOutput"] == baseline["Outputs"]["LegacyOutput"]


def test_generator_fails_closed_for_wrong_pool_or_unexpected_resource():
    wrong_pool = candidate()
    wrong_pool["Resources"]["KaevoCustomUserPoolDomain"]["Properties"]["UserPoolId"] = {
        "Ref": "OtherPool"
    }
    with pytest.raises(ValueError, match="existing Kaevo user pool"):
        MODULE.prepare_template(deployed(), wrong_pool)

    extra = candidate()
    extra["Resources"]["UnexpectedRole"] = {"Type": "AWS::IAM::Role"}
    result = MODULE.prepare_template(deployed(), extra)
    assert "UnexpectedRole" not in result["Resources"]
