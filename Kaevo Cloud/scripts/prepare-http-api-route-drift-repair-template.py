#!/usr/bin/env python3
"""Prepare bounded CloudFormation templates to repair deleted HTTP API routes.

Updating a transformed SAM HTTP API body in overwrite mode removes routes that
are managed as separate ``AWS::ApiGatewayV2::Route`` resources. CloudFormation
then retains stale physical IDs for those deleted routes and their integrations.

This helper produces two templates from the deployed and candidate processed
templates:

1. detach the exact affected route and integration resources from stack state;
2. restore the same resources under their original logical IDs.

The candidate supplies only identity routes that are intentionally new to the
deployed template. Every unrelated resource is preserved byte-for-byte in the
JSON object model.
HTTP API v2 does not support the REST API ``Mode`` property, so the repair must
not update the inline API body in either phase.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path


API = "KaevoCloudHttpApi"
EXPECTED_INTEGRATIONS = {
    "KaevoHouseholdJoinIntegration",
    "KaevoIdentityV3ApiIntegration",
}
EXPECTED_AUTHORIZER = "KaevoHouseholdJoinAuthorizer"
EXPECTED_NEW_ROUTE_KEYS = {
    "GET /v3/identity/home-connector-binding",
    "GET /v3/identity/jellyfin-binding-operations/{operationId}",
    "POST /v3/identity/bind-home-connector",
    "POST /v3/identity/profiles/{profileId}/jellyfin-binding-operations",
}
EXPECTED_ROUTE_KEYS = {
    "GET /v3/identity/account-deletions/{deletionAttemptId}",
    "GET /v3/identity/home-connector-binding",
    "GET /v3/identity/household-joins/authorize",
    "GET /v3/identity/household-joins/onboarding-status",
    "GET /v3/identity/households/profiles",
    "GET /v3/identity/households/ownership-transfer/candidates",
    "GET /v3/identity/jellyfin-binding-operations/{operationId}",
    "GET /v3/identity/me",
    "GET /v3/identity/profile-mappings",
    "POST /v3/identity/bind-home-connector",
    "POST /v3/identity/account-deletion",
    "POST /v3/identity/household-joins/auth-result",
    "POST /v3/identity/household-joins/begin",
    "POST /v3/identity/household-joins/complete",
    "POST /v3/identity/household-joins/complete-native",
    "POST /v3/identity/household-joins/profile-setup",
    "POST /v3/identity/household-joins/resolve-email",
    "POST /v3/identity/household-joins/route-auth",
    "POST /v3/identity/migrate-existing-account",
    "POST /v3/identity/migrate-household-membership",
    "POST /v3/identity/profile-mappings/confirm",
    "POST /v3/identity/profile-mappings/create-and-confirm",
    "POST /v3/identity/profile-mappings/preview",
    "POST /v3/identity/profiles",
    "POST /v3/identity/profiles/{profileId}/bindings",
    "POST /v3/identity/profiles/{profileId}/deletion",
    "POST /v3/identity/profiles/{profileId}/jellyfin-binding-operations",
    "POST /v3/identity/profiles/{profileId}/switch-pin/verify",
    "POST /v3/identity/households/ownership-transfer",
    "PUT /v3/identity/profiles/{profileId}/jellyfin-binding",
    "PUT /v3/identity/profiles/{profileId}/seerr-binding",
    "PUT /v3/identity/profiles/{profileId}/switch-pin",
    "PUT /v3/identity/profiles/{profileId}/switch-targets",
    "PUT /v3/identity/profiles/{profileId}/watching-targets",
}


def transformed_template(wrapper: dict) -> dict:
    body = wrapper.get("TemplateBody")
    if not isinstance(body, dict):
        raise ValueError("deployed template body must be transformed JSON")
    return deepcopy(body)


def selected_routes(template: dict) -> tuple[dict[str, dict], set[str], set[str]]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ValueError("deployed template has no resources")

    routes: dict[str, dict] = {}
    found_keys: set[str] = set()
    integration_refs: set[str] = set()
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::ApiGatewayV2::Route":
            continue
        properties = resource.get("Properties", {})
        if properties.get("ApiId") != {"Ref": API}:
            continue
        route_key = properties.get("RouteKey")
        if route_key not in EXPECTED_ROUTE_KEYS:
            continue
        target = properties.get("Target", {})
        join = target.get("Fn::Join") if isinstance(target, dict) else None
        parts = join[1] if isinstance(join, list) and len(join) == 2 else []
        refs = [
            part["Ref"]
            for part in parts
            if isinstance(part, dict) and set(part) == {"Ref"}
        ]
        if len(refs) != 1:
            raise ValueError(f"route {name} has an unexpected target")
        routes[name] = deepcopy(resource)
        found_keys.add(route_key)
        integration_refs.add(refs[0])

    return routes, found_keys, integration_refs


def affected_resources(deployed: dict, candidate: dict) -> tuple[dict, dict]:
    resources = deployed.get("Resources", {})
    candidate_resources = candidate.get("Resources", {})
    routes, found_keys, integration_refs = selected_routes(deployed)
    candidate_routes, candidate_keys, candidate_integration_refs = selected_routes(candidate)

    required_deployed = EXPECTED_ROUTE_KEYS - EXPECTED_NEW_ROUTE_KEYS
    if not required_deployed.issubset(found_keys) or not found_keys.issubset(EXPECTED_ROUTE_KEYS):
        missing = sorted(required_deployed - found_keys)
        extra = sorted(found_keys - EXPECTED_ROUTE_KEYS)
        raise ValueError(
            f"deployed affected route set differs; missing={missing}, extra={extra}"
        )
    if candidate_keys != EXPECTED_ROUTE_KEYS:
        missing = sorted(EXPECTED_ROUTE_KEYS - candidate_keys)
        extra = sorted(candidate_keys - EXPECTED_ROUTE_KEYS)
        raise ValueError(
            f"candidate affected route set differs; missing={missing}, extra={extra}"
        )
    if integration_refs != EXPECTED_INTEGRATIONS or candidate_integration_refs != EXPECTED_INTEGRATIONS:
        raise ValueError(
            "affected integration set differs: "
            f"deployed={sorted(integration_refs)} candidate={sorted(candidate_integration_refs)}"
        )

    selected = dict(routes)
    for name in EXPECTED_INTEGRATIONS:
        resource = resources.get(name)
        if not isinstance(resource, dict):
            raise ValueError(f"deployed template is missing {name}")
        if resource.get("Type") != "AWS::ApiGatewayV2::Integration":
            raise ValueError(f"{name} is not an API integration")
        selected[name] = deepcopy(resource)
    authorizer = resources.get(EXPECTED_AUTHORIZER)
    if not isinstance(authorizer, dict):
        raise ValueError(f"deployed template is missing {EXPECTED_AUTHORIZER}")
    if authorizer.get("Type") != "AWS::ApiGatewayV2::Authorizer":
        raise ValueError(f"{EXPECTED_AUTHORIZER} is not an API authorizer")
    if authorizer.get("Properties", {}).get("ApiId") != {"Ref": API}:
        raise ValueError(f"{EXPECTED_AUTHORIZER} targets an unexpected API")
    selected[EXPECTED_AUTHORIZER] = deepcopy(authorizer)
    restored = deepcopy(selected)
    for name, resource in candidate_routes.items():
        route_key = resource.get("Properties", {}).get("RouteKey")
        if route_key not in EXPECTED_NEW_ROUTE_KEYS:
            continue
        if name in resources:
            if resources[name] != resource:
                raise ValueError(
                    f"new candidate route differs from deployed template: {name}"
                )
            continue
        restored[name] = deepcopy(resource)
    if {
        resource.get("Properties", {}).get("RouteKey")
        for resource in restored.values()
        if resource.get("Type") == "AWS::ApiGatewayV2::Route"
    } != EXPECTED_ROUTE_KEYS:
        raise ValueError("restored route contract is incomplete")
    return selected, restored


def prepare(deployed_wrapper: dict, candidate_wrapper: dict) -> tuple[dict, dict, set[str]]:
    baseline = transformed_template(deployed_wrapper)
    candidate = transformed_template(candidate_wrapper)
    resources = baseline.get("Resources", {})
    api = resources.get(API)
    if not isinstance(api, dict) or api.get("Type") != "AWS::ApiGatewayV2::Api":
        raise ValueError("deployed Cloud HTTP API is not transformed")
    if not isinstance(api.get("Properties", {}).get("Body"), dict):
        raise ValueError("deployed Cloud HTTP API has no inline body")

    removed, restore_resources = affected_resources(baseline, candidate)
    detached = deepcopy(baseline)
    detached_resources = detached["Resources"]
    for name in removed:
        detached_resources.pop(name)

    restored = deepcopy(detached)
    restored["Resources"].update(deepcopy(restore_resources))

    baseline_without_removed = {
        name: resource
        for name, resource in baseline["Resources"].items()
        if name not in removed
    }
    if detached["Resources"] != baseline_without_removed:
        raise ValueError("detach candidate changed unrelated resources")

    expected_restored = deepcopy(baseline)
    for name, resource in restore_resources.items():
        expected_restored["Resources"][name] = deepcopy(resource)
    if restored != expected_restored:
        raise ValueError("restore candidate escaped the reviewed route contract")
    return detached, restored, set(removed)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template-json", required=True, type=Path)
    parser.add_argument("--candidate-template-json", required=True, type=Path)
    parser.add_argument("--detach-output", required=True, type=Path)
    parser.add_argument("--restore-output", required=True, type=Path)
    args = parser.parse_args()
    if args.detach_output.resolve() == args.restore_output.resolve():
        raise ValueError("detach and restore outputs must differ")
    wrapper = json.loads(args.deployed_template_json.read_text())
    candidate_wrapper = json.loads(args.candidate_template_json.read_text())
    detached, restored, removed = prepare(wrapper, candidate_wrapper)
    write_json(args.detach_output, detached)
    write_json(args.restore_output, restored)
    print(f"DRIFT_REPAIR_DETACH_RESOURCES={len(removed)}")
    print("DRIFT_REPAIR_API_BODY_CHANGES=0")


if __name__ == "__main__":
    main()
