#!/usr/bin/env python3
"""Prepare an API-Lambda-only deployment template from the live baseline.

The API, identity issuer, and owner-enrollment functions share source roots in
the SAM project.  This helper keeps the two unrelated identity functions on
their deployed immutable artifacts, preserves every deployed legacy API event,
and permits only the candidate API Lambda code to move forward.

It writes a generated template only and never updates a stack.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "prepare-v3-api-only-template.py"
SPEC = importlib.util.spec_from_file_location("kaevo_api_template_helper", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load API template helper")
HELPER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HELPER
SPEC.loader.exec_module(HELPER)

PINNED_UNRELATED_FUNCTIONS = (
    "KaevoIdentityClaimIssuerFunction",
    "KaevoOwnerEnrollmentFunction",
    "KaevoV3ConnectorControlFunction",
)
API_FUNCTION = "KaevoCloudApiFunction"


def rebase_local_api_code_uri(template: str, candidate_dir: Path) -> str:
    """Keep the built API artifact valid when the generated template moves.

    ``sam build`` emits a CodeUri relative to its build template.  This helper
    writes the isolated template into a sibling review directory, so leaving
    that value untouched would make ``sam package`` look in the wrong place.
    Deployed S3 URIs and already-absolute paths are left unchanged.
    """
    section = HELPER.resource_section(template, API_FUNCTION)
    match = HELPER.re.search(r"^      CodeUri: ([^\s]+)\s*$", section, HELPER.re.MULTILINE)
    if match is None:
        raise ValueError(f"missing CodeUri for {API_FUNCTION}")
    code_uri = match.group(1)
    if code_uri.startswith("s3://") or Path(code_uri).is_absolute():
        return template
    resolved = (candidate_dir / code_uri).resolve()
    if not resolved.exists():
        raise ValueError(f"built API CodeUri does not exist: {resolved}")
    return HELPER.replace_code_uri(template, API_FUNCTION, str(resolved))


def prepare_template(candidate: str, deployed: str, candidate_dir: Path | None = None) -> str:
    prepared = candidate
    for logical_id in PINNED_UNRELATED_FUNCTIONS:
        prepared = HELPER.replace_resource_section(
            prepared,
            logical_id,
            HELPER.resource_section(deployed, logical_id),
        )
    prepared = HELPER.preserve_legacy_api_events(prepared, deployed)
    prepared = HELPER.preserve_http_api_metadata(prepared, deployed)
    if candidate_dir is not None:
        prepared = rebase_local_api_code_uri(prepared, candidate_dir)
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
        raise ValueError("output must be distinct from input and deployed-template")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        prepare_template(
            args.input.read_text(),
            args.deployed_template.read_text(),
            args.input.resolve().parent,
        )
    )


if __name__ == "__main__":
    main()
