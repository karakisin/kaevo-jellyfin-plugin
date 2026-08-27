#!/usr/bin/env python3
"""Prepare a fail-closed Production V2 email-release runtime update."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


API_FUNCTION = "KaevoAccountLifecycleV2ApiFunction"
WORKER_FUNCTION = "KaevoAccountLifecycleV2WorkerFunction"
AUTH_IDENTITIES_TABLE = "KaevoAuthIdentitiesTable"
USER_POOL = "KaevoUserPool"


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


def validate_api_artifact(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            api = _archive_source(archive, "account_lifecycle_v2_api.py")
            service = _archive_source(archive, "account_lifecycle_v2_service.py")
            status_token = _archive_source(
                archive, "account_lifecycle_v2_status_token.py"
            )
            if b"def lambda_handler(" not in api:
                raise ScopeError("API runtime handler contract is missing")
            if b'"cognito_email_absent": bool(' not in service:
                raise ScopeError("API runtime email-absence proof is missing")
            if b"self.reason = reason" not in status_token:
                raise ScopeError("API runtime status-token error contract is missing")
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        raise ScopeError("API runtime artifact is incomplete") from error


def validate_worker_artifact(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            aws_source = _archive_source(archive, "account_lifecycle_v2_aws.py")
            executor = _archive_source(archive, "account_lifecycle_v2_executor.py")
            worker = _archive_source(archive, "account_lifecycle_v2_worker.py")
            required = {
                "worker Cognito email proof": (
                    b"def identity_and_email_absent(" in aws_source
                    and b"cognito_email_binding_conflict" in aws_source
                    and b"normalized_email" in aws_source
                ),
                "executor email proof": b'"cognito_email_absent": True' in executor,
                "worker AuthIdentity binding": b"auth_identities_table=auth" in worker,
            }
            missing = [name for name, present in required.items() if not present]
            if missing:
                raise ScopeError(f"worker runtime contract is missing: {', '.join(missing)}")
            if b"def delete_subject(" in aws_source or b".delete_subject(" in executor:
                raise ScopeError("worker runtime still contains subject-only deletion")
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        raise ScopeError("worker runtime artifact is incomplete") from error


def _validate_function(
    resources: dict[str, Any],
    logical_id: str,
    *,
    handler: str,
) -> dict[str, Any]:
    function = resources.get(logical_id)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ScopeError(f"deployed function is missing: {logical_id}")
    properties = function.get("Properties")
    if not isinstance(properties, dict) or properties.get("Handler") != handler:
        raise ScopeError(f"deployed function boundary changed: {logical_id}")
    return properties


def prepare_template(
    deployed_template: dict[str, Any],
    *,
    code_bucket: str,
    api_code_key: str,
    worker_code_key: str,
) -> dict[str, Any]:
    if not code_bucket or not api_code_key or not worker_code_key:
        raise ScopeError("code locations are required")
    deployed = _resources(deployed_template)
    prepared_template = copy.deepcopy(deployed_template)
    prepared = _resources(prepared_template)

    _validate_function(
        deployed,
        API_FUNCTION,
        handler="account_lifecycle_v2_api.lambda_handler",
    )
    worker = _validate_function(
        deployed,
        WORKER_FUNCTION,
        handler="account_lifecycle_v2_worker.lambda_handler",
    )
    environment = worker.get("Environment", {}).get("Variables")
    if not isinstance(environment, dict):
        raise ScopeError("deployed worker environment boundary changed")
    if environment.get("AUTH_IDENTITIES_TABLE") != {"Ref": AUTH_IDENTITIES_TABLE}:
        raise ScopeError("deployed worker AuthIdentity boundary changed")
    if environment.get("COGNITO_USER_POOL_ID") != {"Ref": USER_POOL}:
        raise ScopeError("deployed worker Cognito boundary changed")

    prepared[API_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": api_code_key,
    }
    prepared[WORKER_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": worker_code_key,
    }
    changed = {
        logical_id
        for logical_id in deployed
        if prepared[logical_id] != deployed[logical_id]
    }
    expected = {
        logical_id
        for logical_id in (API_FUNCTION, WORKER_FUNCTION)
        if prepared[logical_id]["Properties"]["Code"]
        != deployed[logical_id]["Properties"]["Code"]
    }
    if not expected:
        raise ScopeError("prepared template contains no runtime change")
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
    parser.add_argument("--api-code-key", required=True)
    parser.add_argument("--worker-code-key", required=True)
    parser.add_argument("--api-artifact", required=True, type=Path)
    parser.add_argument("--worker-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ScopeError("output already exists; refusing to overwrite")
    validate_api_artifact(args.api_artifact)
    validate_worker_artifact(args.worker_artifact)

    response = subprocess.run(
        [
            "aws",
            "cloudformation",
            "get-template",
            "--stack-name",
            args.stack_name,
            "--template-stage",
            "Processed",
            "--region",
            args.region,
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    deployed = json.loads(response.stdout)["TemplateBody"]
    prepared = prepare_template(
        deployed,
        code_bucket=args.code_bucket,
        api_code_key=args.api_code_key,
        worker_code_key=args.worker_code_key,
    )
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
