#!/usr/bin/env python3
"""Prepare a live-baseline-only CloudFormation update for Profile Switching."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from urllib.parse import urlparse


FUNCTION = "KaevoIdentityV3ApiFunction"
INTEGRATION = "KaevoIdentityV3ApiIntegration"
ROUTES = {
    "KaevoIdentityV3SetProfileSwitchPINRoute": "PUT /v3/identity/profiles/{profileId}/switch-pin",
    "KaevoIdentityV3VerifyProfileSwitchPINRoute": "POST /v3/identity/profiles/{profileId}/switch-pin/verify",
    "KaevoIdentityV3UpdateProfileSwitchTargetsRoute": "PUT /v3/identity/profiles/{profileId}/switch-targets",
}


def ref(name: str) -> dict:
    return {"Ref": name}


def s3_code(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("identity code URI must be a complete s3://bucket/key URI")
    return {"S3Bucket": parsed.netloc, "S3Key": parsed.path.lstrip("/")}


def prepare(baseline: dict, identity_code_uri: str) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    for name in (FUNCTION, INTEGRATION):
        if name not in resources:
            raise ValueError(f"missing expected deployed resource: {name}")
    existing = set(ROUTES) & set(resources)
    if existing:
        raise ValueError(f"profile-switching route already exists: {sorted(existing)}")
    resources[FUNCTION]["Properties"]["Code"] = s3_code(identity_code_uri)
    for logical_id, route_key in ROUTES.items():
        resources[logical_id] = {
            "Type": "AWS::ApiGatewayV2::Route",
            "Properties": {
                "ApiId": ref("KaevoCloudHttpApi"),
                "AuthorizationType": "NONE",
                "RouteKey": route_key,
                "Target": {"Fn::Join": ["/", ["integrations", ref(INTEGRATION)]]},
            },
        }

    baseline_resources = baseline["Resources"]
    modified = [name for name in baseline_resources if resources[name] != baseline_resources[name]]
    added = set(resources) - set(baseline_resources)
    if modified != [FUNCTION]:
        raise ValueError(f"unexpected baseline resource modifications: {modified}")
    if added != set(ROUTES):
        raise ValueError(f"unexpected resource additions: {sorted(added ^ set(ROUTES))}")
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-processed-template", required=True, type=Path)
    parser.add_argument("--identity-code-s3-uri", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    baseline = json.loads(args.deployed_processed_template.read_text(encoding="utf-8"))
    candidate = prepare(baseline, args.identity_code_s3_uri)
    if args.output.resolve() == args.deployed_processed_template.resolve():
        raise ValueError("output must differ from deployed processed template")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    print("IDENTITY_V3_PROFILE_SWITCHING_TEMPLATE=APPROVED")


if __name__ == "__main__":
    main()
