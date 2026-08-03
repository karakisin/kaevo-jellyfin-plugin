#!/usr/bin/env python3
"""Repair the API runtime dependencies for household connector inheritance.

The household connector code is already deployed.  This helper starts from
the exact processed stack template and changes only the API Lambda environment
and its execution role so that the deployed code can strongly read the
canonical household membership record.  It never changes Lambda code, routes,
tables, or any other resource.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


API_FUNCTION = "KaevoCloudApiFunction"
API_ROLE = "KaevoCloudApiFunctionRole"
MEMBERSHIPS_TABLE = "KaevoHouseholdMembershipsTable"
ENVIRONMENT_KEY = "HOUSEHOLD_MEMBERSHIPS_TABLE"
POLICY_NAME = "KaevoCloudApiFunctionHouseholdMembershipReadPolicy"


def _membership_read_policy() -> dict[str, Any]:
    return {
        "PolicyName": POLICY_NAME,
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "ReadCanonicalHouseholdMembershipForConnectorAccess",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": {"Fn::GetAtt": [MEMBERSHIPS_TABLE, "Arn"]},
            }],
        },
    }


def prepare_template(deployed: dict[str, Any]) -> dict[str, Any]:
    prepared = copy.deepcopy(deployed)
    resources = prepared.get("Resources") or {}
    deployed_resources = deployed.get("Resources") or {}

    function = resources.get(API_FUNCTION)
    role = resources.get(API_ROLE)
    membership_table = resources.get(MEMBERSHIPS_TABLE)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ValueError("deployed template is missing the transformed API Lambda")
    if not isinstance(role, dict) or role.get("Type") != "AWS::IAM::Role":
        raise ValueError("deployed template is missing the API Lambda execution role")
    if not isinstance(membership_table, dict) or membership_table.get("Type") != "AWS::DynamoDB::Table":
        raise ValueError("deployed template is missing canonical household memberships")

    variables = (
        function.setdefault("Properties", {})
        .setdefault("Environment", {})
        .setdefault("Variables", {})
    )
    if ENVIRONMENT_KEY in variables:
        raise ValueError("household membership environment binding already exists")
    variables[ENVIRONMENT_KEY] = {"Ref": MEMBERSHIPS_TABLE}

    policies = role.setdefault("Properties", {}).setdefault("Policies", [])
    if any(policy.get("PolicyName") == POLICY_NAME for policy in policies):
        raise ValueError("household membership read policy already exists")
    policies.append(_membership_read_policy())

    if set(resources) != set(deployed_resources):
        raise ValueError("prepared template changed the deployed resource set")
    changed = {
        logical_id
        for logical_id, deployed_resource in deployed_resources.items()
        if resources.get(logical_id) != deployed_resource
    }
    if changed != {API_FUNCTION, API_ROLE}:
        raise ValueError(f"prepared template scope is unexpected: {sorted(changed)}")
    if prepared.get("Parameters") != deployed.get("Parameters"):
        raise ValueError("prepared template changed deployed parameters")
    if prepared.get("Conditions") != deployed.get("Conditions"):
        raise ValueError("prepared template changed deployed conditions")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-processed-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.resolve() == args.deployed_processed_template.resolve():
        raise ValueError("output must differ from deployed processed template")
    deployed = json.loads(args.deployed_processed_template.read_text())
    candidate = prepare_template(deployed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n")
    print("HOUSEHOLD_CONNECTOR_AUTHORITY_RUNTIME_TEMPLATE=APPROVED")
    print("MODIFIED_RESOURCE_COUNT=2")


if __name__ == "__main__":
    main()
