#!/usr/bin/env python3
"""Prepare a fail-closed Production Lifecycle V2 execution update."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


WORKER_FUNCTION = "KaevoAccountLifecycleV2WorkerFunction"
WORKER_HANDLER = "account_lifecycle_v2_worker.lambda_handler"
ENROLLMENT_ROLE = "KaevoAccountLifecycleV2EnrollmentFunctionRole"
ENROLLMENT_POLICY_NAME = "KaevoAccountLifecycleV2EnrollmentFunctionRolePolicy0"
API_ROLE = "KaevoAccountLifecycleV2ApiFunctionRole"
API_POLICY_NAME = "KaevoAccountLifecycleV2ApiFunctionRolePolicy1"
ENUMERATION_SID = "EnumerateExactAccountLifecycleV2RuntimeResources"
ENUMERATION_STATEMENT = {
    "Sid": ENUMERATION_SID,
    "Effect": "Allow",
    "Action": ["dynamodb:Scan"],
    "Resource": [
        {"Fn::GetAtt": ["KaevoInstallationsTable", "Arn"]},
        {"Fn::GetAtt": ["KaevoAppSessionsTable", "Arn"]},
    ],
}
ENROLLMENT_PUT_SID = "PutExactAccountLifecycleV2EnrollmentRecords"
ENROLLMENT_TABLES = [
    "KaevoAccountLifecycleV2Table",
    "KaevoAccountsTable",
    "KaevoAuthIdentitiesTable",
    "KaevoPrincipalsTable",
    "KaevoIdentityMembershipsTable",
    "KaevoHouseholdMembershipsTable",
    "KaevoIdentityHouseholdsTable",
    "KaevoIdentityProfilesTable",
    "KaevoProfilesTable",
    "KaevoProfileBindingsTable",
    "KaevoSecurityAuditTable",
]
ENROLLMENT_PUT_STATEMENT = {
    "Sid": ENROLLMENT_PUT_SID,
    "Effect": "Allow",
    "Action": ["dynamodb:PutItem"],
    "Resource": [
        {"Fn::GetAtt": [logical_id, "Arn"]}
        for logical_id in ENROLLMENT_TABLES
    ],
    "Condition": {
        "ForAnyValue:StringEquals": {
            "dynamodb:EnclosingOperation": ["TransactWriteItems"],
        },
    },
}


class ScopeError(RuntimeError):
    """Raised when the deployed template cannot be updated without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    return resources


def _require_runtime_enumeration(resources: dict[str, Any]) -> None:
    role = resources.get(API_ROLE)
    if not isinstance(role, dict) or role.get("Type") != "AWS::IAM::Role":
        raise ScopeError("deployed V2 API role is missing")
    policies = role.get("Properties", {}).get("Policies", [])
    matches = [
        policy for policy in policies
        if policy.get("PolicyName") == API_POLICY_NAME
    ]
    if len(matches) != 1:
        raise ScopeError("V2 API exact policy layout changed")
    statements = matches[0].get("PolicyDocument", {}).get("Statement", [])
    enumeration = [
        statement for statement in statements
        if statement.get("Sid") == ENUMERATION_SID
    ]
    if enumeration != [ENUMERATION_STATEMENT]:
        raise ScopeError("deployed V2 runtime enumeration contract is missing")


def _enrollment_policy(resources: dict[str, Any]) -> dict[str, Any]:
    role = resources.get(ENROLLMENT_ROLE)
    if not isinstance(role, dict) or role.get("Type") != "AWS::IAM::Role":
        raise ScopeError("deployed V2 enrollment role is missing")
    policies = role.get("Properties", {}).get("Policies", [])
    matches = [
        policy for policy in policies
        if policy.get("PolicyName") == ENROLLMENT_POLICY_NAME
    ]
    if len(matches) != 1:
        raise ScopeError("V2 enrollment exact policy layout changed")
    return matches[0]


def validate_worker_artifact(path: Path) -> None:
    required = {
        "account_lifecycle_v2_worker.py": [b"def lambda_handler("],
        "account_lifecycle_v2.py": [b'"app_session_refresh"'],
        "account_lifecycle_v2_aws.py": [
            b'"app_session_refresh": 5',
            b'{"app_session_access", "app_session_refresh"}',
        ],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            for name, needles in required.items():
                source = archive.read(name)
                if any(needle not in source for needle in needles):
                    raise ScopeError(f"worker artifact contract missing from {name}")
    except (FileNotFoundError, KeyError, zipfile.BadZipFile) as error:
        raise ScopeError("worker artifact is incomplete") from error


def prepare_template(
    deployed_template: dict[str, Any], *, code_bucket: str, code_key: str,
) -> dict[str, Any]:
    if not code_bucket or not code_key:
        raise ScopeError("code location is required")
    deployed_resources = _resources(deployed_template)
    _require_runtime_enumeration(deployed_resources)

    deployed_worker = deployed_resources.get(WORKER_FUNCTION)
    if not isinstance(deployed_worker, dict):
        raise ScopeError("deployed V2 worker is missing")
    if deployed_worker.get("Type") != "AWS::Lambda::Function":
        raise ScopeError("deployed V2 worker function type changed")
    if deployed_worker.get("Properties", {}).get("Handler") != WORKER_HANDLER:
        raise ScopeError("deployed V2 worker handler changed")

    prepared = copy.deepcopy(deployed_template)
    prepared_resources = _resources(prepared)
    prepared_resources[WORKER_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": code_key,
    }

    enrollment_policy = _enrollment_policy(prepared_resources)
    enrollment_statements = enrollment_policy.get("PolicyDocument", {}).get("Statement")
    if not isinstance(enrollment_statements, list):
        raise ScopeError("V2 enrollment policy statements are missing")
    if any(statement.get("Sid") == ENROLLMENT_PUT_SID for statement in enrollment_statements):
        raise ScopeError("transactional enrollment PutItem statement already exists")
    enrollment_statements.append(copy.deepcopy(ENROLLMENT_PUT_STATEMENT))

    changed = {
        logical_id for logical_id in deployed_resources
        if prepared_resources[logical_id] != deployed_resources[logical_id]
    }
    if changed != {WORKER_FUNCTION, ENROLLMENT_ROLE}:
        raise ScopeError(f"prepared template escaped V2 execution boundary: {sorted(changed)}")
    if set(prepared_resources) != set(deployed_resources):
        raise ScopeError("prepared resource set changed")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--code-bucket", required=True)
    parser.add_argument("--code-key", required=True)
    parser.add_argument("--code-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")

    validate_worker_artifact(args.code_artifact)
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
