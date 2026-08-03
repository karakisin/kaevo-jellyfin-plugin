#!/usr/bin/env python3
"""Fail closed unless the pending-profile Household Join candidate is exact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


MODIFIED = {"KaevoHouseholdJoinFunctionRole", "KaevoHouseholdJoinFunction", "KaevoHouseholdJoinIntegration"}
ADDED = {"KaevoHouseholdJoinOnboardingStatusRoute", "KaevoHouseholdJoinProfileSetupRoute"}
EXISTING_ROUTES = {
    "KaevoHouseholdJoinBeginRoute", "KaevoHouseholdJoinRouteAuthRoute",
    "KaevoHouseholdJoinAuthorizeRoute", "KaevoHouseholdJoinCompleteRoute",
}
EXPECTED_ROUTES = {
    "KaevoHouseholdJoinOnboardingStatusRoute": "GET /v3/identity/household-joins/onboarding-status",
    "KaevoHouseholdJoinProfileSetupRoute": "POST /v3/identity/household-joins/profile-setup",
}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if "TemplateBody" not in value:
        return value
    body = value["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    baseline = load(args.baseline)["Resources"]
    candidate = load(args.candidate)["Resources"]
    changes = load(args.change_set).get("Changes", [])
    errors: list[str] = []

    actual = {item["ResourceChange"].get("LogicalResourceId"): item["ResourceChange"].get("Action") for item in changes}
    if actual != {**{name: "Modify" for name in MODIFIED}, **{name: "Add" for name in ADDED}}:
        errors.append(f"unexpected_change_set_resources={actual}")
    for item in changes:
        resource = item["ResourceChange"]
        if resource.get("Replacement") in {True, "True", "Conditional"}:
            errors.append(f"replacement_forbidden={resource.get('LogicalResourceId')}")
        if resource.get("LogicalResourceId") == "KaevoHouseholdJoinIntegration":
            details = resource.get("Details") or []
            expected = [{
                "Target": {"Attribute": "Properties", "Name": "IntegrationUri", "RequiresRecreation": "Never"},
                "Evaluation": "Dynamic", "ChangeSource": "ResourceAttribute",
                "CausingEntity": "KaevoHouseholdJoinFunction.Arn",
            }]
            if details != expected:
                errors.append("integration_dynamic_dependency_mismatch")

    role_before = baseline["KaevoHouseholdJoinFunctionRole"]
    role_after = candidate["KaevoHouseholdJoinFunctionRole"]
    if role_before.get("Properties", {}).get("Tags") != role_after.get("Properties", {}).get("Tags"):
        errors.append("role_tags_changed")
    before_role = json.loads(json.dumps(role_before))
    after_role = json.loads(json.dumps(role_after))
    before_role["Properties"].pop("Policies", None)
    after_role["Properties"].pop("Policies", None)
    if before_role != after_role:
        errors.append("role_property_changed_outside_inline_policy")

    function_before = baseline["KaevoHouseholdJoinFunction"]
    function_after = candidate["KaevoHouseholdJoinFunction"]
    if function_before["Properties"].get("Tags") != function_after["Properties"].get("Tags"):
        errors.append("function_tags_changed")
    for property_name in ("Role", "Handler", "Runtime", "Architectures", "Timeout", "MemorySize"):
        if function_before["Properties"].get(property_name) != function_after["Properties"].get(property_name):
            errors.append(f"function_property_changed={property_name}")

    if baseline["KaevoHouseholdJoinIntegration"] != candidate["KaevoHouseholdJoinIntegration"]:
        errors.append("integration_effective_properties_changed")
    for route in EXISTING_ROUTES:
        if baseline[route] != candidate[route]:
            errors.append(f"existing_route_changed={route}")
    for logical_id, route_key in EXPECTED_ROUTES.items():
        properties = candidate.get(logical_id, {}).get("Properties", {})
        if (properties.get("RouteKey") != route_key
            or properties.get("AuthorizationType") != "JWT"
            or properties.get("AuthorizerId") != {"Ref": "KaevoHouseholdJoinAuthorizer"}
            or properties.get("Target") != {"Fn::Join": ["/", ["integrations", {"Ref": "KaevoHouseholdJoinIntegration"}]]}):
            errors.append(f"new_route_properties_mismatch={logical_id}")

    if errors:
        raise SystemExit("PENDING_PROFILE_CHANGE_SET_SCOPE=REJECTED\n- " + "\n- ".join(errors))
    print("PENDING_PROFILE_CHANGE_SET_SCOPE=APPROVED")
    print("ROLE_TAGS=UNCHANGED")
    print("INTEGRATION_EFFECTIVE_PROPERTIES=IDENTICAL")
    print("ADDITIONS=KaevoHouseholdJoinOnboardingStatusRoute,KaevoHouseholdJoinProfileSetupRoute")


if __name__ == "__main__":
    main()
