#!/usr/bin/env python3
"""Prepare a fail-closed Production V2 API code and runtime-enumeration update."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
from pathlib import Path
from typing import Any


API_FUNCTION = "KaevoAccountLifecycleV2ApiFunction"
API_ROLE = "KaevoAccountLifecycleV2ApiFunctionRole"
POLICY_NAME = "KaevoAccountLifecycleV2ApiFunctionRolePolicy1"
STATEMENT_SID = "EnumerateExactAccountLifecycleV2RuntimeResources"


class ScopeError(RuntimeError):
    """Raised when the deployed template cannot be updated without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    return resources


def _policy(role: dict[str, Any]) -> dict[str, Any]:
    policies = role.get("Properties", {}).get("Policies", [])
    matches = [policy for policy in policies if policy.get("PolicyName") == POLICY_NAME]
    if len(matches) != 1:
        raise ScopeError("V2 API exact policy layout changed")
    return matches[0]


def prepare_template(
    deployed_template: dict[str, Any], *, code_bucket: str, code_key: str,
) -> dict[str, Any]:
    if not code_bucket or not code_key:
        raise ScopeError("code location is required")
    deployed_resources = _resources(deployed_template)
    if API_FUNCTION not in deployed_resources or API_ROLE not in deployed_resources:
        raise ScopeError("deployed V2 API resources are missing")

    prepared = copy.deepcopy(deployed_template)
    prepared_resources = _resources(prepared)
    function = prepared_resources[API_FUNCTION]
    if function.get("Type") != "AWS::Lambda::Function":
        raise ScopeError("deployed V2 API function type changed")
    function.get("Properties", {})["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": code_key,
    }

    policy = _policy(prepared_resources[API_ROLE])
    statements = policy.get("PolicyDocument", {}).get("Statement")
    if not isinstance(statements, list):
        raise ScopeError("V2 API policy statements are missing")
    if any(str(statement.get("Sid") or "") == STATEMENT_SID for statement in statements):
        raise ScopeError("runtime enumeration statement already exists")
    statements.append({
        "Sid": STATEMENT_SID,
        "Effect": "Allow",
        "Action": ["dynamodb:Scan"],
        "Resource": [
            {"Fn::GetAtt": ["KaevoInstallationsTable", "Arn"]},
            {"Fn::GetAtt": ["KaevoAppSessionsTable", "Arn"]},
        ],
    })

    changed = {
        logical_id for logical_id in deployed_resources
        if prepared_resources[logical_id] != deployed_resources[logical_id]
    }
    if changed != {API_FUNCTION, API_ROLE}:
        raise ScopeError(f"prepared template escaped V2 API boundary: {sorted(changed)}")
    if set(prepared_resources) != set(deployed_resources):
        raise ScopeError("prepared resource set changed")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--code-bucket", required=True)
    parser.add_argument("--code-key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")

    response = subprocess.run(
        [
            "aws", "cloudformation", "get-template",
            "--stack-name", args.stack_name,
            "--template-stage", "Processed",
            "--region", args.region,
            "--output", "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    deployed = json.loads(response.stdout)["TemplateBody"]
    prepared = prepare_template(
        deployed, code_bucket=args.code_bucket, code_key=args.code_key,
    )
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
