#!/usr/bin/env python3
"""Prepare a fail-closed Production V2 profile-mapping runtime update."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


API_FUNCTION = "KaevoAccountLifecycleV2ApiFunction"
API_ROLE = "KaevoAccountLifecycleV2ApiFunctionRole"
API_POLICY = "KaevoAccountLifecycleV2ApiFunctionRolePolicy1"
WORKER_FUNCTION = "KaevoAccountLifecycleV2WorkerFunction"
WORKER_ROLE = "KaevoAccountLifecycleV2WorkerFunctionRole"
WORKER_POLICY = "KaevoAccountLifecycleV2WorkerFunctionRolePolicy1"
ENROLLMENT_ROLE = "KaevoAccountLifecycleV2EnrollmentFunctionRole"
ENROLLMENT_POLICY = "KaevoAccountLifecycleV2EnrollmentFunctionRolePolicy0"
ENUMERATION_SID = "EnumerateExactAccountLifecycleV2RuntimeResources"
WORKER_GRAPH_SID = "ExecuteExactAccountLifecycleV2Graph"
ENROLLMENT_PUT_SID = "PutExactAccountLifecycleV2EnrollmentRecords"
PROFILE_MAPPINGS_TABLE = "KaevoProfileMappingsTable"


class ScopeError(RuntimeError):
    """Raised when the deployed template cannot be updated without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    return resources


def _policy(resources: dict[str, Any], role_id: str, policy_name: str) -> dict[str, Any]:
    role = resources.get(role_id)
    if not isinstance(role, dict) or role.get("Type") != "AWS::IAM::Role":
        raise ScopeError(f"deployed role is missing: {role_id}")
    policies = role.get("Properties", {}).get("Policies", [])
    matches = [policy for policy in policies if policy.get("PolicyName") == policy_name]
    if len(matches) != 1:
        raise ScopeError(f"deployed policy layout changed: {policy_name}")
    return matches[0]


def _statement(policy: dict[str, Any], sid: str) -> dict[str, Any]:
    statements = policy.get("PolicyDocument", {}).get("Statement", [])
    matches = [statement for statement in statements if statement.get("Sid") == sid]
    if len(matches) != 1:
        raise ScopeError(f"deployed statement layout changed: {sid}")
    return matches[0]


def _table_arn(logical_id: str) -> dict[str, Any]:
    return {"Fn::GetAtt": [logical_id, "Arn"]}


def validate_runtime_artifact(path: Path) -> None:
    required = {
        "account_lifecycle_v2.py": [b'"profile_mapping"'],
        "account_lifecycle_v2_service.py": [b'"profile_mapping"', b"profile_mappings_table"],
        "account_lifecycle_v2_api.py": [b'"PROFILE_MAPPINGS_TABLE"'],
        "account_lifecycle_v2_aws.py": [b'"profile_mapping": 8', b'"profile_mappings"'],
        "account_lifecycle_v2_worker.py": [b'"PROFILE_MAPPINGS_TABLE"'],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            for name, needles in required.items():
                source = archive.read(name)
                if any(needle not in source for needle in needles):
                    raise ScopeError(f"runtime artifact contract missing from {name}")
    except (FileNotFoundError, KeyError, zipfile.BadZipFile) as error:
        raise ScopeError("runtime artifact is incomplete") from error


def prepare_template(
    deployed_template: dict[str, Any], *, code_bucket: str, code_key: str,
) -> dict[str, Any]:
    if not code_bucket or not code_key:
        raise ScopeError("code location is required")
    deployed = _resources(deployed_template)
    prepared_template = copy.deepcopy(deployed_template)
    prepared = _resources(prepared_template)

    for logical_id, handler in (
        (API_FUNCTION, "account_lifecycle_v2_api.lambda_handler"),
        (WORKER_FUNCTION, "account_lifecycle_v2_worker.lambda_handler"),
    ):
        resource = deployed.get(logical_id)
        if not isinstance(resource, dict) or resource.get("Type") != "AWS::Lambda::Function":
            raise ScopeError(f"deployed V2 function is missing: {logical_id}")
        if resource.get("Properties", {}).get("Handler") != handler:
            raise ScopeError(f"deployed V2 handler changed: {logical_id}")
        environment = prepared[logical_id].get("Properties", {}).get("Environment", {}).get("Variables")
        if not isinstance(environment, dict) or "PROFILE_MAPPINGS_TABLE" in environment:
            raise ScopeError(f"profile mapping environment boundary changed: {logical_id}")
        environment["PROFILE_MAPPINGS_TABLE"] = {"Ref": PROFILE_MAPPINGS_TABLE}
        prepared[logical_id]["Properties"]["Code"] = {
            "S3Bucket": code_bucket,
            "S3Key": code_key,
        }

    api_policy = _policy(prepared, API_ROLE, API_POLICY)
    enumeration = _statement(api_policy, ENUMERATION_SID)
    expected_scan_resources = [
        _table_arn("KaevoInstallationsTable"),
        _table_arn("KaevoAppSessionsTable"),
    ]
    if enumeration.get("Action") != ["dynamodb:Scan"]:
        raise ScopeError("runtime enumeration action changed")
    if enumeration.get("Resource") != expected_scan_resources:
        raise ScopeError("runtime enumeration resource boundary changed")
    enumeration["Resource"].append(_table_arn(PROFILE_MAPPINGS_TABLE))

    worker_policy = _policy(prepared, WORKER_ROLE, WORKER_POLICY)
    graph = _statement(worker_policy, WORKER_GRAPH_SID)
    worker_resources = graph.get("Resource")
    if not isinstance(worker_resources, list):
        raise ScopeError("worker graph resource boundary changed")
    mapping_arn = _table_arn(PROFILE_MAPPINGS_TABLE)
    if mapping_arn in worker_resources:
        raise ScopeError("worker already owns profile mappings")
    worker_resources.append(mapping_arn)

    enrollment_policy = _policy(prepared, ENROLLMENT_ROLE, ENROLLMENT_POLICY)
    _statement(enrollment_policy, ENROLLMENT_PUT_SID)

    changed = {
        logical_id for logical_id in deployed
        if prepared[logical_id] != deployed[logical_id]
    }
    expected = {API_FUNCTION, API_ROLE, WORKER_FUNCTION, WORKER_ROLE}
    if changed != expected:
        raise ScopeError(f"prepared template escaped V2 runtime boundary: {sorted(changed)}")
    if set(prepared) != set(deployed):
        raise ScopeError("prepared resource set changed")
    return prepared_template


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
    validate_runtime_artifact(args.code_artifact)

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
    prepared = prepare_template(deployed, code_bucket=args.code_bucket, code_key=args.code_key)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
