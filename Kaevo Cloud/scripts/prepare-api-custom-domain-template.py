#!/usr/bin/env python3
"""Create a narrow API custom-domain template from the deployed stack.

The deployed transformed template remains authoritative for every live
resource. This script adds only the reviewed API-domain parameters, condition,
domain, root mapping, and outputs. It never creates or executes a change set.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # JSON-only use does not require PyYAML.
    yaml = None


COPIED_PARAMETERS = {
    "ApiCustomDomainName",
    "ApiCustomDomainCertificateArn",
}
COPIED_CONDITIONS = {"HasApiCustomDomain"}
ADDED_RESOURCES = {
    "KaevoCloudApiCustomDomain",
    "KaevoCloudApiCustomDomainMapping",
}
COPIED_OUTPUTS = {
    "CustomApiDomain",
    "CustomApiUrl",
    "CustomSocialIdentityLinkCallbackUrl",
    "CustomApiRegionalDomainName",
    "CustomApiRegionalHostedZoneId",
}


def _load_template(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if yaml is None:
        raise ValueError("PyYAML is required to read a non-JSON candidate template")

    class Loader(yaml.SafeLoader):
        pass

    def construct_tag(loader, tag_suffix, node):
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

    Loader.add_multi_constructor("!", construct_tag)
    loaded = yaml.load(text, Loader=Loader)
    if not isinstance(loaded, dict):
        raise ValueError(f"template must decode to an object: {path}")
    return loaded


def _require(mapping: dict[str, Any], names: set[str], kind: str) -> None:
    missing = sorted(names - set(mapping))
    if missing:
        raise ValueError(f"candidate is missing {kind}: {missing}")


def prepare_template(deployed: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    parameters = candidate.get("Parameters") or {}
    conditions = candidate.get("Conditions") or {}
    resources = candidate.get("Resources") or {}
    outputs = candidate.get("Outputs") or {}
    _require(parameters, COPIED_PARAMETERS, "parameters")
    _require(conditions, COPIED_CONDITIONS, "conditions")
    _require(resources, ADDED_RESOURCES, "resources")
    _require(outputs, COPIED_OUTPUTS, "outputs")

    prepared = copy.deepcopy(deployed)
    prepared.setdefault("Parameters", {})
    prepared.setdefault("Conditions", {})
    prepared.setdefault("Resources", {})
    prepared.setdefault("Outputs", {})
    for name in COPIED_PARAMETERS:
        prepared["Parameters"][name] = copy.deepcopy(parameters[name])
    for name in COPIED_CONDITIONS:
        prepared["Conditions"][name] = copy.deepcopy(conditions[name])
    for name in ADDED_RESOURCES:
        if name in prepared["Resources"]:
            raise ValueError(f"deployed stack already contains additive resource: {name}")
        prepared["Resources"][name] = copy.deepcopy(resources[name])
    for name in COPIED_OUTPUTS:
        prepared["Outputs"][name] = copy.deepcopy(outputs[name])

    domain = prepared["Resources"]["KaevoCloudApiCustomDomain"]
    if domain.get("Type") != "AWS::ApiGatewayV2::DomainName":
        raise ValueError("API custom domain must be AWS::ApiGatewayV2::DomainName")
    domain_properties = domain.get("Properties") or {}
    if domain_properties.get("DomainName") != {"Ref": "ApiCustomDomainName"}:
        raise ValueError("API custom domain must use the dedicated name parameter")
    expected_configuration = [{
        "CertificateArn": {"Ref": "ApiCustomDomainCertificateArn"},
        "EndpointType": "REGIONAL",
        "SecurityPolicy": "TLS_1_2",
    }]
    if domain_properties.get("DomainNameConfigurations") != expected_configuration:
        raise ValueError("API custom domain must remain regional TLS 1.2")

    mapping = prepared["Resources"]["KaevoCloudApiCustomDomainMapping"]
    if mapping.get("Type") != "AWS::ApiGatewayV2::ApiMapping":
        raise ValueError("API domain mapping must be AWS::ApiGatewayV2::ApiMapping")
    expected_mapping = {
        "ApiId": {"Ref": "KaevoCloudHttpApi"},
        "DomainName": {"Ref": "ApiCustomDomainName"},
        "Stage": "dev",
    }
    if mapping.get("Properties") != expected_mapping:
        raise ValueError("API custom domain must map the existing dev API at the root")

    for name, resource in (deployed.get("Resources") or {}).items():
        if prepared["Resources"].get(name) != resource:
            raise ValueError(f"unrelated deployed resource changed: {name}")
    if set(prepared["Resources"]) != set(deployed.get("Resources") or {}) | ADDED_RESOURCES:
        raise ValueError("prepared template contains an unexpected resource")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--candidate-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.deployed_template.is_file() or not args.candidate_template.is_file():
        raise ValueError("both input templates must exist")
    if args.output.resolve() in {args.deployed_template.resolve(), args.candidate_template.resolve()}:
        raise ValueError("output must be distinct from both inputs")
    deployed = _load_template(args.deployed_template)
    candidate = _load_template(args.candidate_template)
    prepared = prepare_template(deployed, candidate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
