#!/usr/bin/env python3
"""Prepare a fail-closed Production V2 resume and enrollment update."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


WORKER_FUNCTION = "KaevoAccountLifecycleV2WorkerFunction"
ENROLLMENT_FUNCTION = "KaevoAccountLifecycleV2EnrollmentFunction"


class ScopeError(RuntimeError):
    """Raised when the deployed template cannot be updated without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    return resources


def _archive_source(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        return archive.read(name)
    except KeyError as error:
        raise ScopeError(f"runtime artifact is missing {name}") from error


def validate_worker_artifact(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            worker = _archive_source(archive, "account_lifecycle_v2_worker.py")
            executor = _archive_source(archive, "account_lifecycle_v2_executor.py")
            aws_adapter = _archive_source(archive, "account_lifecycle_v2_aws.py")
            lifecycle = _archive_source(archive, "account_lifecycle_v2.py")
            required = {
                "worker durable phase redelivery": b"EXECUTABLE_PHASES" in worker,
                "executor durable phase resume": (
                    b"resume_phase" in executor
                    and b"OperationPhase.DELETING_KAEVO_GRAPH" in executor
                ),
                "journal exact resume checkpoint": (
                    b"resume_phase = :resume" in aws_adapter
                    and b"REMOVE failure_reason, resume_phase" in aws_adapter
                ),
                "stale operation cleanup": (
                    b"def _lifecycle_partition(" in aws_adapter
                    and b"record_key != current_operation_key" in aws_adapter
                ),
                "retry transition contract": (
                    b"OperationPhase.RETRY_REQUIRED" in lifecycle
                    and b"OperationPhase.VERIFYING_KAEVO_ABSENCE" in lifecycle
                ),
            }
            missing = [name for name, present in required.items() if not present]
            if missing:
                raise ScopeError(
                    f"worker runtime contract is missing: {', '.join(missing)}"
                )
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        raise ScopeError("worker runtime artifact is incomplete") from error


def validate_enrollment_artifact(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            enrollment = _archive_source(
                archive, "account_lifecycle_v2_enrollment.py",
            )
            required = (
                b'Key={"principal_id": subject}' in enrollment,
                b'active_by_type.get("identity_profile", set())' in enrollment,
                b'by_type.get("cloud_profile", "")' not in enrollment,
            )
            if not all(required):
                raise ScopeError(
                    "enrollment runtime exact-subject profile contract is missing"
                )
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        raise ScopeError("enrollment runtime artifact is incomplete") from error


def _validate_function(
    resources: dict[str, Any], logical_id: str, *, handler: str,
) -> None:
    function = resources.get(logical_id)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ScopeError(f"deployed function is missing: {logical_id}")
    if function.get("Properties", {}).get("Handler") != handler:
        raise ScopeError(f"deployed function boundary changed: {logical_id}")


def prepare_template(
    deployed_template: dict[str, Any], *, code_bucket: str,
    worker_code_key: str, enrollment_code_key: str,
) -> dict[str, Any]:
    if not code_bucket or not worker_code_key or not enrollment_code_key:
        raise ScopeError("code locations are required")
    deployed = _resources(deployed_template)
    _validate_function(
        deployed,
        WORKER_FUNCTION,
        handler="account_lifecycle_v2_worker.lambda_handler",
    )
    _validate_function(
        deployed,
        ENROLLMENT_FUNCTION,
        handler="account_lifecycle_v2_enrollment.lambda_handler",
    )

    prepared_template = copy.deepcopy(deployed_template)
    prepared = _resources(prepared_template)
    prepared[WORKER_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": worker_code_key,
    }
    prepared[ENROLLMENT_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": enrollment_code_key,
    }
    changed = {
        logical_id for logical_id in deployed
        if prepared[logical_id] != deployed[logical_id]
    }
    expected = {
        logical_id for logical_id in (WORKER_FUNCTION, ENROLLMENT_FUNCTION)
        if prepared[logical_id]["Properties"]["Code"]
        != deployed[logical_id]["Properties"]["Code"]
    }
    if WORKER_FUNCTION not in expected:
        raise ScopeError("prepared template contains no worker runtime change")
    if changed != expected:
        raise ScopeError(
            f"prepared template escaped V2 runtime boundary: {sorted(changed)}"
        )
    if set(prepared) != set(deployed):
        raise ScopeError("prepared resource set changed")
    return prepared_template


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--code-bucket", required=True)
    parser.add_argument("--worker-code-key", required=True)
    parser.add_argument("--enrollment-code-key", required=True)
    parser.add_argument("--worker-artifact", required=True, type=Path)
    parser.add_argument("--enrollment-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")
    validate_worker_artifact(args.worker_artifact)
    validate_enrollment_artifact(args.enrollment_artifact)

    response = subprocess.run([
        "aws", "cloudformation", "get-template",
        "--stack-name", args.stack_name,
        "--template-stage", "Processed",
        "--region", args.region,
        "--output", "json",
    ], check=True, capture_output=True, text=True)
    deployed = json.loads(response.stdout)["TemplateBody"]
    prepared = prepare_template(
        deployed,
        code_bucket=args.code_bucket,
        worker_code_key=args.worker_code_key,
        enrollment_code_key=args.enrollment_code_key,
    )
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
