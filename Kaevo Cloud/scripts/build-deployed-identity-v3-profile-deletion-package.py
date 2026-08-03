#!/usr/bin/env python3
"""Patch the canonical roster and exact profile-deletion graph into Identity V3."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


REPLACE_FUNCTIONS = (
    "list_household_profiles_v3",
    "delete_profile_v3",
)

INSERT_FUNCTIONS = (
    "_canonical_profile_deletion_context",
    "_household_installation_records",
    "_profile_mapping_records_for_installations",
    "_profile_binding_records_for_household",
    "_household_invitation_records",
    "_profile_invitation_records",
    "_profile_join_transaction_records",
    "_remove_profile_from_principal",
    "_revoke_profile_installation",
    "_execute_canonical_profile_deletion",
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def function_spans(source: str) -> dict[str, tuple[int, int, str]]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    spans = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = offsets[node.lineno - 1]
        end = offsets[node.end_lineno]
        spans[node.name] = (start, end, source[start:end])
    return spans


def replace_function(source: str, name: str, replacement: str) -> str:
    spans = function_spans(source)
    if name not in spans:
        raise ValueError(f"deployed handler is missing required function: {name}")
    start, end, _ = spans[name]
    return source[:start] + replacement.rstrip() + "\n" + source[end:]


def patched_handler(deployed: str, local: str) -> str:
    deployed_spans = function_spans(deployed)
    local_spans = function_spans(local)
    required = set(REPLACE_FUNCTIONS) | set(INSERT_FUNCTIONS)
    missing_local = sorted(required - set(local_spans))
    if missing_local:
        raise ValueError(f"local handler is missing required functions: {missing_local}")
    unexpected_existing = sorted(set(INSERT_FUNCTIONS) & set(deployed_spans))
    if unexpected_existing:
        raise ValueError(
            f"deployed handler already contains deletion helper functions: {unexpected_existing}"
        )
    for name in required:
        if ".scan(" in local_spans[name][2]:
            raise ValueError(f"profile-deletion function uses DynamoDB Scan: {name}")

    patched = deployed
    for name in REPLACE_FUNCTIONS:
        patched = replace_function(patched, name, local_spans[name][2])

    spans = function_spans(patched)
    insertion_offset = spans["delete_profile_v3"][0]
    insertion = "\n\n".join(
        local_spans[name][2].rstrip() for name in INSERT_FUNCTIONS
    ) + "\n\n\n"
    patched = patched[:insertion_offset] + insertion + patched[insertion_offset:]

    ast.parse(patched)
    patched_spans = function_spans(patched)
    for name in required:
        if patched_spans[name][2].strip() != local_spans[name][2].strip():
            raise ValueError(f"patched function does not match local source: {name}")
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("profile-deletion package introduced a DynamoDB Scan")
    return patched


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--local-handler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    local = args.local_handler.read_text(encoding="utf-8")
    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if names.count("handler.py") != 1:
            raise ValueError("deployed ZIP must contain exactly one handler.py")
        original_files = {info.filename: source.read(info.filename) for info in infos}
        original_handler = original_files["handler.py"]
        updated_handler = patched_handler(
            original_handler.decode("utf-8"), local,
        ).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(
                    info,
                    updated_handler if info.filename == "handler.py" else original_files[info.filename],
                )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original_files[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(original_handler)}")
    print(f"DELETION_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
