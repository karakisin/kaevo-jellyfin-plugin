#!/usr/bin/env python3
"""Prepare the SAM candidate for managed login and explicit social linking.

The API, owner-enrollment, identity-claim, and connector-control functions have
historically shared source roots.  Social linking intentionally changes the API
and identity-claim artifacts, while owner enrollment and connector control must
remain on their exact deployed objects.  This helper also preserves every
deployed non-social API event before packaging so no legacy route can disappear.

It writes a generated template only and never changes a stack.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


PINNED_UNRELATED_FUNCTIONS = (
    "KaevoOwnerEnrollmentFunction",
    "KaevoV3ConnectorControlFunction",
)
API_FUNCTION = "KaevoCloudApiFunction"


def api_event_ids(template: str) -> set[str]:
    start = template.find(f"  {API_FUNCTION}:\n")
    if start < 0:
        raise ValueError(f"candidate is missing {API_FUNCTION}")
    next_resource = re.search(r"^  [A-Za-z][A-Za-z0-9]*:\n", template[start + 1 :], re.MULTILINE)
    end = len(template) if next_resource is None else start + 1 + next_resource.start()
    section = template[start:end]
    events = section.find("      Events:\n")
    if events < 0:
        raise ValueError(f"candidate {API_FUNCTION} has no Events mapping")
    return set(re.findall(r"^        ([A-Za-z][A-Za-z0-9]*):\n", section[events:], re.MULTILINE))


def assert_deployed_api_permissions_preserved(candidate: str, deployed: dict[str, Any]) -> None:
    prefix = API_FUNCTION
    suffix = "Permission"
    required = {
        logical_id[len(prefix):-len(suffix)]
        for logical_id, resource in (deployed.get("Resources") or {}).items()
        if logical_id.startswith(prefix)
        and logical_id.endswith(suffix)
        and resource.get("Type") == "AWS::Lambda::Permission"
    }
    missing = sorted(required - api_event_ids(candidate))
    if missing:
        raise ValueError(f"candidate removes deployed API Lambda permissions: {missing}")
CANDIDATE_FUNCTIONS = (
    "KaevoCloudApiFunction",
    "KaevoIdentityClaimIssuerFunction",
    "KaevoSocialIdentityGuardFunction",
    "KaevoSocialIdentityApiFunction",
)


def deployed_s3_uri(template: dict[str, Any], logical_id: str) -> str:
    resource = (template.get("Resources") or {}).get(logical_id) or {}
    code = (resource.get("Properties") or {}).get("Code") or {}
    bucket = str(code.get("S3Bucket") or "")
    key = str(code.get("S3Key") or "")
    version = str(code.get("S3ObjectVersion") or "")
    if not bucket or not key:
        raise ValueError(f"deployed {logical_id} has no immutable S3 code object")
    suffix = f"?versionId={version}" if version else ""
    return f"s3://{bucket}/{key}{suffix}"


def replace_code_uri(template: str, logical_id: str, s3_uri: str) -> str:
    start = template.find(f"  {logical_id}:\n")
    if start < 0:
        raise ValueError(f"candidate is missing {logical_id}")
    next_resource = re.search(r"^  [A-Za-z][A-Za-z0-9]*:\n", template[start + 1 :], re.MULTILINE)
    end = len(template) if next_resource is None else start + 1 + next_resource.start()
    section = template[start:end]
    updated, count = re.subn(
        r"^      CodeUri: .+$",
        f"      CodeUri: {s3_uri}",
        section,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError(f"candidate {logical_id} has no single CodeUri")
    return template[:start] + updated + template[end:]


def local_code_uri(template: str, logical_id: str) -> str:
    start = template.find(f"  {logical_id}:\n")
    if start < 0:
        raise ValueError(f"candidate is missing {logical_id}")
    next_resource = re.search(r"^  [A-Za-z][A-Za-z0-9]*:\n", template[start + 1 :], re.MULTILINE)
    end = len(template) if next_resource is None else start + 1 + next_resource.start()
    match = re.search(r"^      CodeUri: ([^\s]+)\s*$", template[start:end], re.MULTILINE)
    if match is None:
        raise ValueError(f"candidate {logical_id} has no single CodeUri")
    return match.group(1)


def prepare_template(
    candidate: str,
    deployed: dict[str, Any],
    *,
    candidate_directory: Path | None = None,
) -> str:
    prepared = candidate
    for logical_id in PINNED_UNRELATED_FUNCTIONS:
        prepared = replace_code_uri(prepared, logical_id, deployed_s3_uri(deployed, logical_id))
    assert_deployed_api_permissions_preserved(prepared, deployed)
    if candidate_directory is not None:
        for logical_id in CANDIDATE_FUNCTIONS:
            code_uri = local_code_uri(prepared, logical_id)
            path = Path(code_uri)
            if not path.is_absolute():
                path = (candidate_directory / path).resolve()
            if not path.is_dir():
                raise ValueError(f"built candidate artifact does not exist: {path}")
            prepared = replace_code_uri(prepared, logical_id, str(path))
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--deployed-template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or not args.deployed_template.is_file():
        raise ValueError("input and deployed-template must exist")
    if args.output.resolve() in {args.input.resolve(), args.deployed_template.resolve()}:
        raise ValueError("output must be distinct from both inputs")
    deployed = json.loads(args.deployed_template.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        prepare_template(
            args.input.read_text(encoding="utf-8"),
            deployed,
            candidate_directory=args.input.resolve().parent,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
