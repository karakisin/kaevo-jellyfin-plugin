from __future__ import annotations

import pathlib

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infra" / "template.yaml"


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
        "Or": "Fn::Or",
        "If": "Fn::If",
        "Condition": "Condition",
    }
    return {tags.get(tag_suffix, f"Fn::{tag_suffix}"): value}


Loader.add_multi_constructor("!", _construct_tag)


def template():
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=Loader)


def test_production_receives_an_isolated_api_stage_and_native_oidc_contract():
    data = template()

    assert {"Condition": "IsProduction"} in data["Conditions"]["HasNativeOidc"]["Fn::Or"]
    assert data["Resources"]["KaevoCloudHttpApi"]["Properties"]["StageName"] == {
        "Ref": "EnvironmentName"
    }
    assert data["Resources"]["KaevoCloudApiCustomDomainMapping"]["Properties"]["Stage"] == {
        "Ref": "EnvironmentName"
    }
    assert data["Outputs"]["ApiUrl"]["Value"] == {
        "Fn::Sub": "https://${KaevoCloudHttpApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}/${EnvironmentName}"
    }

    native_client = data["Resources"]["KaevoSecurityStageNativeOidcClient"]
    assert native_client["Condition"] == "HasNativeOidc"
    assert native_client["Properties"]["ClientName"]["Fn::If"][2]["Fn::If"][0] == "IsProduction"

    prefix_domain = data["Resources"]["KaevoSecurityStageUserPoolDomain"]
    production_domain = prefix_domain["Properties"]["Domain"]["Fn::If"][2]["Fn::If"]
    assert production_domain[0] == "IsProduction"
    assert production_domain[1] == {
        "Fn::Sub": "kaevo-cloud-production-${AWS::AccountId}-${AWS::Region}"
    }


def test_production_outputs_are_complete_and_do_not_reuse_development_identity():
    outputs = template()["Outputs"]
    expected = {
        "ProductionNativeOidcClientId",
        "ProductionCognitoDomain",
        "ProductionAuthorizationEndpoint",
        "ProductionTokenEndpoint",
        "ProductionLogoutEndpoint",
        "ProductionCallbackUri",
        "ProductionLogoutUri",
    }

    assert expected.issubset(outputs)
    for name in expected:
        assert outputs[name]["Condition"] == "IsProduction"

    production_text = "\n".join(str(outputs[name]) for name in sorted(expected))
    assert "kaevo-cloud-dev" not in production_text
    assert "us-west-2_waHpB9aex" not in production_text


def test_custom_api_domain_may_target_dev_or_production_only_when_explicitly_supplied():
    condition = template()["Conditions"]["HasApiCustomDomain"]["Fn::And"]
    environment_gate = condition[0]["Fn::Or"]

    assert {"Condition": "IsDevelopment"} in environment_gate
    assert {"Condition": "IsProduction"} in environment_gate
    assert {"Condition": "IsSecurityStage"} not in environment_gate
