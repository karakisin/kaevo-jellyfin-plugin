#!/usr/bin/env python3
"""Prepare a fail-closed Production V2 confirmation runtime update."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any


API_FUNCTION = "KaevoAccountLifecycleV2ApiFunction"
PROFILE_MAPPINGS_TABLE = "KaevoProfileMappingsTable"


class ScopeError(RuntimeError):
    """Raised when the deployed template cannot be updated without guessing."""


def _resources(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    return resources


def validate_runtime_artifact(path: Path) -> None:
    required = {
        "account_lifecycle_v2.py": [
            b'"lifecycle_revision": int(root["revision"])',
            b'plan_digest=_canonical_digest(digest_payload)',
        ],
        "account_lifecycle_v2_api.py": [b"def lambda_handler("],
        "account_lifecycle_v2_service.py": [
            b'"#scope": "scope"',
            b'"AND #phase = :awaiting AND #scope = :everything "',
            b'"AND provider_capability IN (:enabled, :not_applicable)"',
            b'LifecycleV2StorageError("operation_queue_failed")',
        ],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            for name, needles in required.items():
                source = archive.read(name)
                if any(needle not in source for needle in needles):
                    raise ScopeError(f"runtime artifact contract missing from {name}")
                if (
                    name == "account_lifecycle_v2.py"
                    and b'"operation_id": operation_id' in source
                ):
                    raise ScopeError(
                        "runtime artifact binds semantic plan digest to operation ID"
                    )
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

    function = deployed.get(API_FUNCTION)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ScopeError("deployed V2 API function is missing")
    properties = function.get("Properties", {})
    if properties.get("Handler") != "account_lifecycle_v2_api.lambda_handler":
        raise ScopeError("deployed V2 API handler changed")
    environment = properties.get("Environment", {}).get("Variables")
    if not isinstance(environment, dict) or environment.get("PROFILE_MAPPINGS_TABLE") != {
        "Ref": PROFILE_MAPPINGS_TABLE,
    }:
        raise ScopeError("deployed V2 API environment boundary changed")

    prepared[API_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": code_key,
    }
    changed = {
        logical_id for logical_id in deployed
        if prepared[logical_id] != deployed[logical_id]
    }
    if changed != {API_FUNCTION}:
        raise ScopeError(f"prepared template escaped V2 API boundary: {sorted(changed)}")
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

    response = subprocess.run([
        "aws", "cloudformation", "get-template",
        "--stack-name", args.stack_name,
        "--template-stage", "Processed",
        "--region", args.region,
        "--output", "json",
    ], check=True, capture_output=True, text=True)
    deployed = json.loads(response.stdout)["TemplateBody"]
    prepared = prepare_template(deployed, code_bucket=args.code_bucket, code_key=args.code_key)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
