#!/usr/bin/env python3
"""Prepare a social-identity-guard-only CloudFormation candidate.

The input must be the exact deployed CloudFormation template.  This helper
changes only the immutable S3 code object for
``KaevoSocialIdentityGuardFunction`` and verifies that every other byte of the
parsed template remains identical.  It never uploads an artifact, creates a
change set, or updates a stack.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


FUNCTION = "KaevoSocialIdentityGuardFunction"


def parse_s3_uri(value: str) -> tuple[str, str, str | None]:
    parsed = urlparse(value)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.lstrip("/"):
        raise ValueError("candidate code must be an s3:// bucket/key URI")
    version = None
    if parsed.query:
        fields = dict(part.split("=", 1) for part in parsed.query.split("&") if "=" in part)
        version = fields.get("versionId") or None
        if set(fields) - {"versionId"}:
            raise ValueError("candidate S3 URI has unsupported query parameters")
    return parsed.netloc, parsed.path.lstrip("/"), version


def prepare_template(deployed: dict[str, Any], candidate_s3_uri: str) -> dict[str, Any]:
    bucket, key, version = parse_s3_uri(candidate_s3_uri)
    prepared = copy.deepcopy(deployed)
    resource = (prepared.get("Resources") or {}).get(FUNCTION)
    if not isinstance(resource, dict) or resource.get("Type") != "AWS::Lambda::Function":
        raise ValueError(f"deployed template is missing transformed {FUNCTION}")
    properties = resource.get("Properties")
    if not isinstance(properties, dict):
        raise ValueError(f"deployed {FUNCTION} has no Properties")
    current = properties.get("Code")
    if not isinstance(current, dict) or not current.get("S3Bucket") or not current.get("S3Key"):
        raise ValueError(f"deployed {FUNCTION} has no immutable S3 code object")

    replacement: dict[str, str] = {"S3Bucket": bucket, "S3Key": key}
    if version:
        replacement["S3ObjectVersion"] = version
    properties["Code"] = replacement

    expected = copy.deepcopy(deployed)
    expected["Resources"][FUNCTION]["Properties"]["Code"] = replacement
    if prepared != expected:
        raise ValueError("candidate changed resources outside the social identity guard code")
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--candidate-code", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.deployed_template.is_file():
        raise ValueError("deployed-template must exist")
    if args.output.resolve() == args.deployed_template.resolve():
        raise ValueError("output must be distinct from deployed-template")
    deployed = json.loads(args.deployed_template.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(prepare_template(deployed, args.candidate_code), indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
