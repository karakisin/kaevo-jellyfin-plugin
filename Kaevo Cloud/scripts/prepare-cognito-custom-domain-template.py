#!/usr/bin/env python3
"""Create a narrow custom-domain template from the deployed stack.

The deployed transformed template remains authoritative for every existing
resource. Only the two custom-domain parameters, one condition, one additive
Cognito domain resource, and its outputs are copied from the reviewed
candidate. This script never creates or executes a change set.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


COPIED_PARAMETERS = {
    "CognitoCustomDomainName",
    "CognitoCustomDomainCertificateArn",
}
COPIED_CONDITIONS = {"HasCognitoCustomDomain"}
ADDED_RESOURCES = {"KaevoCustomUserPoolDomain"}
COPIED_OUTPUTS = {
    "CustomCognitoDomain",
    "CustomAuthorizationEndpoint",
    "CustomTokenEndpoint",
    "CustomLogoutEndpoint",
    "CustomDomainCloudFrontDistribution",
}


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

    domain = prepared["Resources"]["KaevoCustomUserPoolDomain"]
    if domain.get("Type") != "AWS::Cognito::UserPoolDomain":
        raise ValueError("custom domain must be an AWS::Cognito::UserPoolDomain")
    properties = domain.get("Properties") or {}
    if properties.get("UserPoolId") != {"Ref": "KaevoUserPool"}:
        raise ValueError("custom domain must use the existing Kaevo user pool")
    expected_config = {"CertificateArn": {"Ref": "CognitoCustomDomainCertificateArn"}}
    if properties.get("CustomDomainConfig") != expected_config:
        raise ValueError("custom domain certificate must come from the dedicated parameter")
    if properties.get("ManagedLoginVersion") != 2:
        raise ValueError("custom domain must retain managed login version 2")

    # Prove every deployed resource is byte-for-byte structurally preserved.
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
    deployed = json.loads(args.deployed_template.read_text(encoding="utf-8"))
    candidate = json.loads(args.candidate_template.read_text(encoding="utf-8"))
    prepared = prepare_template(deployed, candidate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
