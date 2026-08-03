#!/usr/bin/env python3
"""Add only the protected Identity V3 profile-deletion API route."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path


ROUTE = "KaevoIdentityV3DeleteProfileRoute"
ROUTE_KEY = "POST /v3/identity/profiles/{profileId}/deletion"
API = "KaevoCloudHttpApi"
INTEGRATION = "KaevoIdentityV3ApiIntegration"


def prepare(baseline: dict) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    if API not in resources or INTEGRATION not in resources:
        raise ValueError("deployed template is missing the Identity V3 API integration")
    if ROUTE in resources:
        raise ValueError("profile-deletion route already exists")
    resources[ROUTE] = {
        "Type": "AWS::ApiGatewayV2::Route",
        "Properties": {
            "ApiId": {"Ref": API},
            "AuthorizationType": "NONE",
            "RouteKey": ROUTE_KEY,
            "Target": {
                "Fn::Join": [
                    "/",
                    ["integrations", {"Ref": INTEGRATION}],
                ],
            },
        },
    }
    baseline_resources = baseline["Resources"]
    if any(resources[name] != baseline_resources[name] for name in baseline_resources):
        raise ValueError("route candidate modified an existing resource")
    if set(resources) - set(baseline_resources) != {ROUTE}:
        raise ValueError("route candidate added an unexpected resource")
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-original-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    baseline = json.loads(args.deployed_original_template.read_text(encoding="utf-8"))
    candidate = prepare(baseline)
    if args.output.resolve() == args.deployed_original_template.resolve():
        raise ValueError("output must differ from deployed original template")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    print("IDENTITY_V3_PROFILE_DELETION_ROUTE_TEMPLATE=APPROVED")
    print("ADDED_RESOURCE=KaevoIdentityV3DeleteProfileRoute")


if __name__ == "__main__":
    main()
