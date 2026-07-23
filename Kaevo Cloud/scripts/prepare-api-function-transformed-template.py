#!/usr/bin/env python3
"""Prepare a narrow API Lambda update from the deployed transformed template.

The deployed CloudFormation template is authoritative for every live resource.
This helper changes only the API Lambda's immutable S3 code artifact and its
validated public API origin. It never creates or executes a change set.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


API_FUNCTION = "KaevoCloudApiFunction"


def _artifact_code(artifact_uri: str, current_code: dict[str, Any]) -> dict[str, Any]:
    parsed = urlsplit(artifact_uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.lstrip("/"):
        raise ValueError("artifact-uri must be an s3:// bucket/key URI")
    code = copy.deepcopy(current_code)
    code["S3Bucket"] = parsed.netloc
    code["S3Key"] = parsed.path.lstrip("/")
    code.pop("S3ObjectVersion", None)
    return code


def _public_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("public-api-base-url must be an HTTPS origin without a path")
    return f"https://{parsed.netloc}"


def prepare_template(
    deployed: dict[str, Any],
    *,
    artifact_uri: str,
    public_api_base_url: str,
) -> dict[str, Any]:
    prepared = copy.deepcopy(deployed)
    resources = prepared.get("Resources") or {}
    if API_FUNCTION not in resources:
        raise ValueError(f"deployed template is missing {API_FUNCTION}")
    function = resources[API_FUNCTION]
    if function.get("Type") != "AWS::Lambda::Function":
        raise ValueError(f"{API_FUNCTION} must be a transformed AWS::Lambda::Function")
    properties = function.get("Properties") or {}
    current_code = properties.get("Code") or {}
    if not current_code.get("S3Bucket") or not current_code.get("S3Key"):
        raise ValueError(f"{API_FUNCTION} must use an immutable S3 artifact")
    variables = ((properties.get("Environment") or {}).get("Variables") or {})

    properties["Code"] = _artifact_code(artifact_uri, current_code)
    variables["PUBLIC_API_BASE_URL"] = _public_origin(public_api_base_url)
    properties.setdefault("Environment", {})["Variables"] = variables
    function["Properties"] = properties

    deployed_resources = deployed.get("Resources") or {}
    if set(resources) != set(deployed_resources):
        raise ValueError("prepared template changed the deployed resource set")
    for name, resource in deployed_resources.items():
        if name != API_FUNCTION and resources.get(name) != resource:
            raise ValueError(f"unrelated deployed resource changed: {name}")
    if prepared.get("Parameters") != deployed.get("Parameters"):
        raise ValueError("prepared template changed deployed parameters")
    if prepared.get("Conditions") != deployed.get("Conditions"):
        raise ValueError("prepared template changed deployed conditions")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--artifact-uri", required=True)
    parser.add_argument("--public-api-base-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.deployed_template.is_file():
        raise ValueError("deployed-template must exist")
    if args.output.resolve() == args.deployed_template.resolve():
        raise ValueError("output must be distinct from deployed-template")
    deployed = json.loads(args.deployed_template.read_text(encoding="utf-8"))
    prepared = prepare_template(
        deployed,
        artifact_uri=args.artifact_uri,
        public_api_base_url=args.public_api_base_url,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
