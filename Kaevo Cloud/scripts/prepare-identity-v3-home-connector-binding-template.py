#!/usr/bin/env python3
"""Build the Connector <-> Identity binding candidate from the live template.

The candidate intentionally starts with CloudFormation's processed template.
It retains every current deployed resource verbatim, then changes only the
dedicated Identity V3 package/environment, its existing least-privilege data
policy, and two Identity V3 HTTP routes.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from urllib.parse import urlparse


FUNCTION = "KaevoIdentityV3ApiFunction"
POLICY = "KaevoIdentityV3ApiDataPolicy"
HOME_CONNECTORS = "KaevoHomeConnectorsTable"
AUDIT = "KaevoSecurityAuditTable"
ROUTES = {
    "KaevoIdentityV3GetHomeConnectorBindingRoute": "GET /v3/identity/home-connector-binding",
    "KaevoIdentityV3BindHomeConnectorRoute": "POST /v3/identity/bind-home-connector",
}


def s3_code(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("identity code URI must be a complete s3://bucket/key URI")
    return {"S3Bucket": parsed.netloc, "S3Key": parsed.path.lstrip("/")}


def get_att(name: str) -> dict:
    return {"Fn::GetAtt": [name, "Arn"]}


def ref(name: str) -> dict:
    return {"Ref": name}


def binding_policy(existing: dict) -> dict:
    """Append exactly the two actions the binding path calls.

    The deployed HomeConnectors table has an exact profile index.  The binding
    write is one DynamoDB transaction with its immutable audit record.
    """
    policy = copy.deepcopy(existing)
    statements = policy["Properties"]["PolicyDocument"]["Statement"]
    prohibited = {"ReadHomeConnectorBindingAuthority", "WriteHomeConnectorBindingAtomically"}
    if any(statement.get("Sid") in prohibited for statement in statements):
        raise ValueError("binding IAM statements already exist in the deployed baseline")
    statements.extend([
        {
            "Sid": "ReadHomeConnectorBindingAuthority",
            "Effect": "Allow",
            "Action": ["dynamodb:Query"],
            "Resource": {"Fn::Sub": [
                "${TableArn}/index/profile_id-updated_at-index",
                {"TableArn": get_att(HOME_CONNECTORS)},
            ]},
        },
        {
            "Sid": "WriteHomeConnectorBindingAtomically",
            "Effect": "Allow",
            "Action": ["dynamodb:TransactWriteItems"],
            "Resource": [get_att(HOME_CONNECTORS), get_att(AUDIT)],
        },
    ])
    return policy


def prepare(baseline: dict, identity_code_uri: str) -> dict:
    candidate = copy.deepcopy(baseline)
    resources = candidate.get("Resources") or {}
    for name in (FUNCTION, POLICY, HOME_CONNECTORS, AUDIT, "KaevoIdentityV3ApiIntegration"):
        if name not in resources:
            raise ValueError(f"missing expected deployed resource: {name}")
    if any(name in resources for name in ROUTES):
        raise ValueError("a Connector <-> Identity binding route already exists")

    function = resources[FUNCTION]["Properties"]
    environment = function.setdefault("Environment", {}).setdefault("Variables", {})
    if "HOME_CONNECTORS_TABLE" in environment:
        raise ValueError("HOME_CONNECTORS_TABLE already exists in the deployed Identity V3 environment")
    function["Code"] = s3_code(identity_code_uri)
    environment["HOME_CONNECTORS_TABLE"] = ref(HOME_CONNECTORS)
    resources[POLICY] = binding_policy(resources[POLICY])

    for logical_id, route_key in ROUTES.items():
        resources[logical_id] = {
            "Type": "AWS::ApiGatewayV2::Route",
            "Properties": {
                "ApiId": ref("KaevoCloudHttpApi"),
                "AuthorizationType": "NONE",
                "RouteKey": route_key,
                "Target": {"Fn::Join": ["/", ["integrations", ref("KaevoIdentityV3ApiIntegration")]]},
            },
        }

    baseline_resources = baseline["Resources"]
    modified = [name for name in baseline_resources if resources[name] != baseline_resources[name]]
    added = set(resources) - set(baseline_resources)
    if modified != [FUNCTION, POLICY]:
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
    baseline = json.loads(args.deployed_processed_template.read_text())
    candidate = prepare(baseline, args.identity_code_s3_uri)
    if args.output.resolve() == args.deployed_processed_template.resolve():
        raise ValueError("output must differ from deployed processed template")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")
    print("IDENTITY_V3_HOME_CONNECTOR_BINDING_TEMPLATE=APPROVED")


if __name__ == "__main__":
    main()
