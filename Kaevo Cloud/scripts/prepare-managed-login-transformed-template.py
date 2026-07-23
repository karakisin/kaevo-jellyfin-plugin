#!/usr/bin/env python3
"""Create a narrow managed-login template from the deployed transformed stack.

The deployed transformed template is authoritative for every API route,
permission, table, role, and unrelated Lambda. Only the explicitly allowlisted
managed-login parameters, conditions, and resources are copied from a reviewed
candidate. The output contains no SAM transform and is never executed by this
script.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


ADDED_PARAMETERS = {
    "GoogleIdentityProviderSecretArn",
    "AppleIdentityProviderSecretArn",
}
ADDED_CONDITIONS = {
    "HasGoogleIdentityProvider",
    "HasAppleIdentityProvider",
}
COPIED_RESOURCES = {
    "KaevoIdentityClaimIssuerFunction",
    "KaevoSecurityStageManagedLoginBranding",
    "KaevoSecurityStageNativeOidcClient",
    "KaevoGoogleIdentityProvider",
    "KaevoAppleIdentityProvider",
}


def _require(mapping: dict[str, Any], names: set[str], kind: str) -> None:
    missing = sorted(names - set(mapping))
    if missing:
        raise ValueError(f"candidate is missing {kind}: {missing}")


def prepare_template(deployed: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    candidate_parameters = candidate.get("Parameters") or {}
    candidate_conditions = candidate.get("Conditions") or {}
    candidate_resources = candidate.get("Resources") or {}
    _require(candidate_parameters, ADDED_PARAMETERS, "parameters")
    _require(candidate_conditions, ADDED_CONDITIONS, "conditions")
    _require(candidate_resources, COPIED_RESOURCES, "resources")

    prepared = copy.deepcopy(deployed)
    prepared.setdefault("Parameters", {})
    prepared.setdefault("Conditions", {})
    prepared.setdefault("Resources", {})
    for name in ADDED_PARAMETERS:
        prepared["Parameters"][name] = copy.deepcopy(candidate_parameters[name])
    for name in ADDED_CONDITIONS:
        prepared["Conditions"][name] = copy.deepcopy(candidate_conditions[name])
    for name in COPIED_RESOURCES:
        prepared["Resources"][name] = copy.deepcopy(candidate_resources[name])

    issuer = prepared["Resources"]["KaevoIdentityClaimIssuerFunction"]
    code = (issuer.get("Properties") or {}).get("Code") or {}
    if not code.get("S3Bucket") or not code.get("S3Key"):
        raise ValueError("identity issuer candidate must use an immutable S3 artifact")
    variables = ((issuer.get("Properties") or {}).get("Environment") or {}).get("Variables") or {}
    if not all(name in variables for name in (
        "EXPECTED_NATIVE_GOOGLE_ENABLED",
        "EXPECTED_NATIVE_APPLE_ENABLED",
    )):
        raise ValueError("identity issuer is missing the social-provider allowlist flags")
    serialized_issuer = json.dumps(issuer, sort_keys=True)
    if "SecretString" in serialized_issuer or "IdentityProviderSecretArn" in serialized_issuer:
        raise ValueError("identity issuer must not receive social-provider credentials")

    branding = prepared["Resources"]["KaevoSecurityStageManagedLoginBranding"]
    branding_properties = branding.get("Properties") or {}
    if branding_properties.get("UseCognitoProvidedValues") is not False or not branding_properties.get("Settings"):
        raise ValueError("candidate does not contain Kaevo managed-login branding")

    # Every non-allowlisted deployed resource remains structurally identical.
    deployed_resources = deployed.get("Resources") or {}
    for name, resource in deployed_resources.items():
        if name not in COPIED_RESOURCES and prepared["Resources"].get(name) != resource:
            raise ValueError(f"unrelated deployed resource changed: {name}")
    return prepared


def prepare_branding_only_template(
    deployed: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    candidate_resources = candidate.get("Resources") or {}
    name = "KaevoSecurityStageManagedLoginBranding"
    _require(candidate_resources, {name}, "resources")
    prepared = copy.deepcopy(deployed)
    prepared["Resources"][name] = copy.deepcopy(candidate_resources[name])
    branding_properties = prepared["Resources"][name].get("Properties") or {}
    if branding_properties.get("UseCognitoProvidedValues") is not False or not branding_properties.get("Settings"):
        raise ValueError("candidate does not contain Kaevo managed-login branding")
    for resource_name, resource in (deployed.get("Resources") or {}).items():
        if resource_name != name and prepared["Resources"].get(resource_name) != resource:
            raise ValueError(f"unrelated deployed resource changed: {resource_name}")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--candidate-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--branding-only", action="store_true")
    args = parser.parse_args()
    if not args.deployed_template.is_file() or not args.candidate_template.is_file():
        raise ValueError("both input templates must exist")
    if args.output.resolve() in {
        args.deployed_template.resolve(),
        args.candidate_template.resolve(),
    }:
        raise ValueError("output must be distinct from both inputs")
    deployed = json.loads(args.deployed_template.read_text(encoding="utf-8"))
    candidate = json.loads(args.candidate_template.read_text(encoding="utf-8"))
    prepared = (
        prepare_branding_only_template(deployed, candidate)
        if args.branding_only
        else prepare_template(deployed, candidate)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Preserve the deployed mapping order. API Gateway's inline OpenAPI Body
    # receives an order-sensitive CloudFormation signature even when two JSON
    # objects are structurally equal.
    args.output.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
