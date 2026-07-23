from __future__ import annotations

import importlib.util
import pathlib

import pytest
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra" / "template.yaml"
SCRIPT = ROOT / "scripts" / "prepare-api-custom-domain-template.py"
SPEC = importlib.util.spec_from_file_location("api_custom_domain_template", SCRIPT)
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


def test_generator_loads_cloudformation_yaml_candidate():
    loaded = MODULE._load_template(TEMPLATE)

    assert loaded["Resources"]["KaevoCloudApiCustomDomain"]["Properties"]["DomainName"] == {
        "Ref": "ApiCustomDomainName"
    }
    assert loaded["Conditions"]["HasApiCustomDomain"]["Fn::And"]


def candidate():
    return {
        "Parameters": {
            "ApiCustomDomainName": {"Type": "String", "Default": ""},
            "ApiCustomDomainCertificateArn": {"Type": "String", "Default": ""},
        },
        "Conditions": {"HasApiCustomDomain": {"Fn::And": [True, True]}},
        "Resources": {
            "KaevoCloudApiCustomDomain": {
                "Type": "AWS::ApiGatewayV2::DomainName",
                "Properties": {
                    "DomainName": {"Ref": "ApiCustomDomainName"},
                    "DomainNameConfigurations": [{
                        "CertificateArn": {"Ref": "ApiCustomDomainCertificateArn"},
                        "EndpointType": "REGIONAL",
                        "SecurityPolicy": "TLS_1_2",
                    }],
                },
            },
            "KaevoCloudApiCustomDomainMapping": {
                "Type": "AWS::ApiGatewayV2::ApiMapping",
                "Properties": {
                    "ApiId": {"Ref": "KaevoCloudHttpApi"},
                    "DomainName": {"Ref": "ApiCustomDomainName"},
                    "Stage": "dev",
                },
            },
        },
        "Outputs": {name: {"Value": name} for name in MODULE.COPIED_OUTPUTS},
    }


def deployed():
    return {
        "Parameters": {"EnvironmentName": {"Type": "String"}},
        "Conditions": {"IsDevelopment": {"Fn::Equals": ["dev", "dev"]}},
        "Resources": {
            "KaevoCloudHttpApi": {
                "Type": "AWS::ApiGatewayV2::Api",
                "Properties": {"legacy": True},
            },
            "LegacyV1Permission": {"Type": "AWS::Lambda::Permission"},
            "LegacyV2Permission": {"Type": "AWS::Lambda::Permission"},
        },
        "Outputs": {"LegacyOutput": {"Value": "preserved"}},
    }


def test_source_template_defines_regional_root_api_mapping():
    data = template()
    domain = data["Resources"]["KaevoCloudApiCustomDomain"]
    assert domain["Type"] == "AWS::ApiGatewayV2::DomainName"
    assert domain["Properties"]["DomainNameConfigurations"] == [{
        "CertificateArn": {"Ref": "ApiCustomDomainCertificateArn"},
        "EndpointType": "REGIONAL",
        "SecurityPolicy": "TLS_1_2",
    }]
    mapping = data["Resources"]["KaevoCloudApiCustomDomainMapping"]
    assert mapping["Properties"] == {
        "ApiId": {"Ref": "KaevoCloudHttpApi"},
        "DomainName": {"Ref": "ApiCustomDomainName"},
        "Stage": "dev",
    }
    assert "ApiMappingKey" not in mapping["Properties"]


def test_narrow_generator_preserves_every_deployed_resource_exactly():
    baseline = deployed()
    result = MODULE.prepare_template(baseline, candidate())
    for name, resource in baseline["Resources"].items():
        assert result["Resources"][name] == resource
    assert set(result["Resources"]) - set(baseline["Resources"]) == MODULE.ADDED_RESOURCES
    assert result["Outputs"]["LegacyOutput"] == baseline["Outputs"]["LegacyOutput"]


def test_generator_fails_closed_for_wrong_api_mapping_or_unexpected_resource():
    wrong_mapping = candidate()
    wrong_mapping["Resources"]["KaevoCloudApiCustomDomainMapping"]["Properties"]["Stage"] = "other"
    with pytest.raises(ValueError, match="existing dev API"):
        MODULE.prepare_template(deployed(), wrong_mapping)

    extra = candidate()
    extra["Resources"]["UnexpectedRole"] = {"Type": "AWS::IAM::Role"}
    result = MODULE.prepare_template(deployed(), extra)
    assert "UnexpectedRole" not in result["Resources"]
