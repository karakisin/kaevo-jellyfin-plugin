#!/usr/bin/env python3
"""Add the canonical household roster path to the live Identity V3 baseline."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from urllib.parse import urlparse


FUNCTION = "KaevoIdentityV3ApiFunction"
POLICY = "KaevoIdentityV3ApiDataPolicy"
INTEGRATION = "KaevoIdentityV3ApiIntegration"
ROUTE = "KaevoIdentityV3ListHouseholdProfilesRoute"
ROUTE_KEY = "GET /v3/identity/households/profiles"
MEMBERSHIPS = "KaevoHouseholdMembershipsTable"
PROFILES = "KaevoProfilesTable"
ROSTER_READ_SID = "ReadCanonicalHouseholdProfileRoster"


def ref(name: str) -> dict:
    return {"Ref": name}


def get_att(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def s3_code(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("identity code URI must be a complete s3://bucket/key URI")
    return {"S3Bucket": parsed.netloc, "S3Key": parsed.path.lstrip("/")}


def roster_read_statement() -> dict:
    return {
        "Sid": ROSTER_READ_SID,
        "Effect": "Allow",
        "Action": ["dynamodb:Query"],
        "Resource": [
            get_att(MEMBERSHIPS),
            {"Fn::Sub": "${KaevoHouseholdMembershipsTable.Arn}/index/*"},
            get_att(PROFILES),
            {"Fn::Sub": "${KaevoProfilesTable.Arn}/index/*"},
        ],
    }


def prepare(baseline: dict, identity_code_uri: str) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    for name in (FUNCTION, POLICY, INTEGRATION, MEMBERSHIPS, PROFILES):
        if name not in resources:
            raise ValueError(f"missing expected deployed resource: {name}")
    if ROUTE in resources:
        raise ValueError("canonical household roster route already exists")

    function = resources[FUNCTION].get("Properties") or {}
    function["Code"] = s3_code(identity_code_uri)
    policy = resources[POLICY].get("Properties", {}).get("PolicyDocument", {})
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise ValueError("Identity V3 data policy has no statement list")
    if any(statement.get("Sid") == ROSTER_READ_SID for statement in statements if isinstance(statement, dict)):
        raise ValueError("canonical household roster query policy already exists")
    statements.append(roster_read_statement())
    resources[ROUTE] = {
        "Type": "AWS::ApiGatewayV2::Route",
        "Properties": {
            "ApiId": ref("KaevoCloudHttpApi"),
            "AuthorizationType": "NONE",
            "RouteKey": ROUTE_KEY,
            "Target": {"Fn::Join": ["/", ["integrations", ref(INTEGRATION)]]},
        },
    }

    baseline_resources = baseline["Resources"]
    modified = [name for name in baseline_resources if resources[name] != baseline_resources[name]]
    added = set(resources) - set(baseline_resources)
    if set(modified) != {FUNCTION, POLICY}:
        raise ValueError(f"unexpected baseline resource modifications: {modified}")
    if added != {ROUTE}:
        raise ValueError(f"unexpected resource additions: {sorted(added ^ {ROUTE})}")
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
    print("IDENTITY_V3_HOUSEHOLD_ROSTER_TEMPLATE=APPROVED")


if __name__ == "__main__":
    main()
