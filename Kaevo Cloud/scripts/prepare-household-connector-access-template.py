#!/usr/bin/env python3
"""Prepare the two-resource household connector access deployment.

The deployed transformed CloudFormation template is authoritative. This helper
changes only:

* the API Lambda immutable S3 code artifact and canonical-membership binding;
* the API Lambda role's exact canonical-membership read permission; and
* the Home Connectors table by adding its household/update-time GSI.

It never creates or executes a change set.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


API_FUNCTION = "KaevoCloudApiFunction"
API_ROLE = "KaevoCloudApiFunctionRole"
CONNECTORS_TABLE = "KaevoHomeConnectorsTable"
MEMBERSHIPS_TABLE = "KaevoHouseholdMembershipsTable"
PROFILE_INDEX = "profile_id-updated_at-index"
HOUSEHOLD_INDEX = "household_id-updated_at-index"
MEMBERSHIP_ENVIRONMENT_KEY = "HOUSEHOLD_MEMBERSHIPS_TABLE"
MEMBERSHIP_POLICY_NAME = "KaevoCloudApiFunctionHouseholdMembershipReadPolicy"


def _artifact_code(artifact_uri: str, current_code: dict[str, Any]) -> dict[str, Any]:
    parsed = urlsplit(artifact_uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.lstrip("/"):
        raise ValueError("artifact-uri must be an s3:// bucket/key URI")
    code = copy.deepcopy(current_code)
    code["S3Bucket"] = parsed.netloc
    code["S3Key"] = parsed.path.lstrip("/")
    code.pop("S3ObjectVersion", None)
    return code


def _household_index() -> dict[str, Any]:
    return {
        "IndexName": HOUSEHOLD_INDEX,
        "KeySchema": [
            {"AttributeName": "household_id", "KeyType": "HASH"},
            {"AttributeName": "updated_at", "KeyType": "RANGE"},
        ],
        "Projection": {"ProjectionType": "ALL"},
    }


def prepare_template(
    deployed: dict[str, Any],
    *,
    artifact_uri: str,
) -> dict[str, Any]:
    prepared = copy.deepcopy(deployed)
    resources = prepared.get("Resources") or {}
    deployed_resources = deployed.get("Resources") or {}

    function = resources.get(API_FUNCTION)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ValueError(f"deployed template is missing transformed {API_FUNCTION}")
    function_properties = function.get("Properties") or {}
    current_code = function_properties.get("Code") or {}
    if not current_code.get("S3Bucket") or not current_code.get("S3Key"):
        raise ValueError(f"{API_FUNCTION} must use an immutable S3 artifact")
    function_properties["Code"] = _artifact_code(artifact_uri, current_code)
    variables = (
        function_properties.setdefault("Environment", {})
        .setdefault("Variables", {})
    )
    if MEMBERSHIP_ENVIRONMENT_KEY in variables:
        raise ValueError("canonical household membership binding already exists")
    variables[MEMBERSHIP_ENVIRONMENT_KEY] = {"Ref": MEMBERSHIPS_TABLE}
    function["Properties"] = function_properties

    role = resources.get(API_ROLE)
    if not isinstance(role, dict) or role.get("Type") != "AWS::IAM::Role":
        raise ValueError(f"deployed template is missing {API_ROLE}")
    policies = role.setdefault("Properties", {}).setdefault("Policies", [])
    if any(policy.get("PolicyName") == MEMBERSHIP_POLICY_NAME for policy in policies):
        raise ValueError("canonical household membership read policy already exists")
    policies.append({
        "PolicyName": MEMBERSHIP_POLICY_NAME,
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "ReadCanonicalHouseholdMembershipForConnectorAccess",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": {"Fn::GetAtt": [MEMBERSHIPS_TABLE, "Arn"]},
            }],
        },
    })

    table = resources.get(CONNECTORS_TABLE)
    if not isinstance(table, dict) or table.get("Type") != "AWS::DynamoDB::Table":
        raise ValueError(f"deployed template is missing {CONNECTORS_TABLE}")
    properties = table.get("Properties") or {}
    if properties.get("BillingMode") != "PAY_PER_REQUEST":
        raise ValueError("Home Connectors table billing mode changed unexpectedly")
    if properties.get("KeySchema") != [
        {"AttributeName": "connector_id", "KeyType": "HASH"}
    ]:
        raise ValueError("Home Connectors base key changed unexpectedly")

    definitions = properties.get("AttributeDefinitions")
    if not isinstance(definitions, list):
        raise ValueError("Home Connectors attribute definitions are missing")
    definition_names = {
        entry.get("AttributeName")
        for entry in definitions
        if isinstance(entry, dict)
    }
    if definition_names != {"connector_id", "profile_id", "updated_at"}:
        raise ValueError("Home Connectors attribute definitions changed unexpectedly")

    indexes = properties.get("GlobalSecondaryIndexes")
    if not isinstance(indexes, list) or len(indexes) != 1:
        raise ValueError("Home Connectors existing indexes changed unexpectedly")
    if indexes[0].get("IndexName") != PROFILE_INDEX:
        raise ValueError("Home Connectors profile index changed unexpectedly")

    definitions.append({"AttributeName": "household_id", "AttributeType": "S"})
    indexes.append(_household_index())
    table["Properties"] = properties

    if set(resources) != set(deployed_resources):
        raise ValueError("prepared template changed the deployed resource set")
    changed = {
        logical_id
        for logical_id, deployed_resource in deployed_resources.items()
        if resources.get(logical_id) != deployed_resource
    }
    if changed != {API_FUNCTION, API_ROLE, CONNECTORS_TABLE}:
        raise ValueError(f"prepared template scope is unexpected: {sorted(changed)}")
    if prepared.get("Parameters") != deployed.get("Parameters"):
        raise ValueError("prepared template changed deployed parameters")
    if prepared.get("Conditions") != deployed.get("Conditions"):
        raise ValueError("prepared template changed deployed conditions")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--artifact-uri", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.deployed_template.is_file():
        raise ValueError("deployed-template must exist")
    if args.output.resolve() == args.deployed_template.resolve():
        raise ValueError("output must be distinct from deployed-template")
    deployed = json.loads(args.deployed_template.read_text(encoding="utf-8"))
    prepared = prepare_template(deployed, artifact_uri=args.artifact_uri)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")
    print("HOUSEHOLD_CONNECTOR_TEMPLATE_SCOPE=APPROVED")
    print("MODIFIED_RESOURCE_COUNT=3")


if __name__ == "__main__":
    main()
