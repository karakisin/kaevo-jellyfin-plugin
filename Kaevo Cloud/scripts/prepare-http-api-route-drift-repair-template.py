#!/usr/bin/env python3
"""Prepare bounded CloudFormation templates to repair deleted HTTP API routes.

Updating a transformed SAM HTTP API body in overwrite mode removes routes that
are managed as separate ``AWS::ApiGatewayV2::Route`` resources. CloudFormation
then retains stale physical IDs for those deleted routes and their integrations.

This helper produces two templates from the deployed processed template:

1. detach the exact affected route and integration resources from stack state;
2. restore the same resources under their original logical IDs.

Every unrelated resource is preserved byte-for-byte in the JSON object model.
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
EXPECTED_ROUTE_KEYS = {
    "GET /v3/identity/home-connector-binding",
    "GET /v3/identity/household-joins/authorize",
    "GET /v3/identity/household-joins/onboarding-status",
    "GET /v3/identity/households/profiles",
    "GET /v3/identity/me",
    "GET /v3/identity/profile-mappings",
    "POST /v3/identity/bind-home-connector",
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
}


def transformed_template(wrapper: dict) -> dict:
    body = wrapper.get("TemplateBody")
    if not isinstance(body, dict):
        raise ValueError("deployed template body must be transformed JSON")
    return deepcopy(body)


def affected_resources(template: dict) -> dict:
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

    if found_keys != EXPECTED_ROUTE_KEYS:
        missing = sorted(EXPECTED_ROUTE_KEYS - found_keys)
        extra = sorted(found_keys - EXPECTED_ROUTE_KEYS)
        raise ValueError(
            f"deployed affected route set differs; missing={missing}, extra={extra}"
        )
    if integration_refs != EXPECTED_INTEGRATIONS:
        raise ValueError(
            "deployed affected integration set differs: "
            f"{sorted(integration_refs)}"
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
    return selected


def prepare(wrapper: dict) -> tuple[dict, dict, set[str]]:
    baseline = transformed_template(wrapper)
    resources = baseline.get("Resources", {})
    api = resources.get(API)
    if not isinstance(api, dict) or api.get("Type") != "AWS::ApiGatewayV2::Api":
        raise ValueError("deployed Cloud HTTP API is not transformed")
    if not isinstance(api.get("Properties", {}).get("Body"), dict):
        raise ValueError("deployed Cloud HTTP API has no inline body")

    removed = affected_resources(baseline)
    detached = deepcopy(baseline)
    detached_resources = detached["Resources"]
    for name in removed:
        detached_resources.pop(name)

    restored = deepcopy(detached)
    restored["Resources"].update(deepcopy(removed))

    baseline_without_removed = {
        name: resource
        for name, resource in baseline["Resources"].items()
        if name not in removed
    }
    if detached["Resources"] != baseline_without_removed:
        raise ValueError("detach candidate changed unrelated resources")

    if restored != baseline:
        raise ValueError("restore candidate differs from deployed baseline")
    return detached, restored, set(removed)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template-json", required=True, type=Path)
    parser.add_argument("--detach-output", required=True, type=Path)
    parser.add_argument("--restore-output", required=True, type=Path)
    args = parser.parse_args()
    if args.detach_output.resolve() == args.restore_output.resolve():
        raise ValueError("detach and restore outputs must differ")
    wrapper = json.loads(args.deployed_template_json.read_text())
    detached, restored, removed = prepare(wrapper)
    write_json(args.detach_output, detached)
    write_json(args.restore_output, restored)
    print(f"DRIFT_REPAIR_DETACH_RESOURCES={len(removed)}")
    print("DRIFT_REPAIR_API_BODY_CHANGES=0")


if __name__ == "__main__":
    main()
