#!/usr/bin/env python3
"""Prepare a bounded Identity V3 deployment candidate.

The source tree is intentionally dirty outside the identity synchronization
scope.  This helper pins those unrelated Lambda artifacts to their currently
deployed immutable S3 objects before ``sam package`` runs.  It changes only a
generated template and fails closed when the deployed baseline is incomplete.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PINNED_FUNCTIONS = (
    "KaevoSocialIdentityGuardFunction",
    "KaevoSocialIdentityApiFunction",
    "KaevoV3ConnectorControlFunction",
)
RESOURCE_HEADER = re.compile(r"^  [A-Za-z][A-Za-z0-9]*:\n", re.MULTILINE)


def resource_bounds(template: str, logical_id: str) -> tuple[int, int]:
    start = template.find(f"  {logical_id}:\n")
    if start < 0:
        raise ValueError(f"missing resource {logical_id}")
    following = RESOURCE_HEADER.search(template, start + 1)
    return start, following.start() if following else len(template)


def replace_code_uri(template: str, logical_id: str, code_uri: str) -> str:
    start, end = resource_bounds(template, logical_id)
    section = template[start:end]
    match = re.search(r"^      CodeUri: .*$", section, re.MULTILINE)
    if match is None:
        raise ValueError(f"missing CodeUri for {logical_id}")
    section = section[:match.start()] + f"      CodeUri: {code_uri}" + section[match.end():]
    return template[:start] + section + template[end:]


def deployed_code_uri(template: dict, logical_id: str) -> str:
    try:
        code = template["Resources"][logical_id]["Properties"]["Code"]
        bucket = code["S3Bucket"]
        key = code["S3Key"]
    except KeyError as exc:
        raise ValueError(f"missing deployed immutable code for {logical_id}") from exc
    if not isinstance(bucket, str) or not isinstance(key, str) or not bucket or not key:
        raise ValueError(f"invalid deployed immutable code for {logical_id}")
    return f"s3://{bucket}/{key}"


def prepare_template(candidate: str, deployed: dict) -> str:
    for logical_id in PINNED_FUNCTIONS:
        candidate = replace_code_uri(candidate, logical_id, deployed_code_uri(deployed, logical_id))
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--deployed-processed-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or not args.deployed_processed_template.is_file():
        raise ValueError("input and deployed processed template must exist")
    if args.output.resolve() in {args.input.resolve(), args.deployed_processed_template.resolve()}:
        raise ValueError("output must be distinct from inputs")
    deployed = json.loads(args.deployed_processed_template.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(prepare_template(args.input.read_text(), deployed))


if __name__ == "__main__":
    main()
