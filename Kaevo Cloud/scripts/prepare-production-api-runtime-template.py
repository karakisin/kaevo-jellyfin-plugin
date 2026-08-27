#!/usr/bin/env python3
"""Prepare one fail-closed Production API runtime artifact update.

The generated template starts from the processed live stack and changes only
``KaevoCloudApiFunction.Properties.Code``. This keeps routes, IAM, tables,
environment variables, runtime, and handler ownership unchanged.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
from typing import Any


API_FUNCTION = "KaevoCloudApiFunction"
EXPECTED_HANDLER = "handler.lambda_handler"
EXPECTED_RUNTIME = "python3.12"


class ScopeError(RuntimeError):
    """Raised when the live stack cannot be changed without guessing."""


def prepare_template(
    deployed: dict[str, Any], *, code_bucket: str, code_key: str,
) -> dict[str, Any]:
    if not code_bucket or not code_key:
        raise ScopeError("code location is required")
    resources = deployed.get("Resources")
    if not isinstance(resources, dict):
        raise ScopeError("deployed template is missing Resources")
    function = resources.get(API_FUNCTION)
    if not isinstance(function, dict) or function.get("Type") != "AWS::Lambda::Function":
        raise ScopeError("deployed Production API function is missing")
    properties = function.get("Properties")
    if not isinstance(properties, dict):
        raise ScopeError("deployed Production API properties are missing")
    if properties.get("Handler") != EXPECTED_HANDLER:
        raise ScopeError("deployed Production API handler changed")
    if properties.get("Runtime") != EXPECTED_RUNTIME:
        raise ScopeError("deployed Production API runtime changed")
    code = properties.get("Code")
    if not isinstance(code, dict) or set(code) != {"S3Bucket", "S3Key"}:
        raise ScopeError("deployed Production API code ownership changed")

    prepared = copy.deepcopy(deployed)
    prepared["Resources"][API_FUNCTION]["Properties"]["Code"] = {
        "S3Bucket": code_bucket,
        "S3Key": code_key,
    }
    changed = sorted(
        logical_id
        for logical_id, resource in prepared["Resources"].items()
        if resource != resources.get(logical_id)
    )
    if changed != [API_FUNCTION]:
        raise ScopeError(f"runtime candidate changed unexpected resources: {changed}")
    if set(prepared["Resources"]) != set(resources):
        raise ScopeError("runtime candidate changed the resource set")
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

    result = subprocess.run(
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
    body = json.loads(result.stdout)["TemplateBody"]
    deployed = json.loads(body) if isinstance(body, str) else body
    prepared = prepare_template(
        deployed, code_bucket=args.code_bucket, code_key=args.code_key,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n")
    print(f"PRODUCTION_API_RUNTIME_TEMPLATE_APPROVED resource={API_FUNCTION}")


if __name__ == "__main__":
    main()
