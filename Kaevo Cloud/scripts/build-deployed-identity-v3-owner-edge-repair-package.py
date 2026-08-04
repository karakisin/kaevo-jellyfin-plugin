#!/usr/bin/env python3
"""Build an identity Lambda package for the reviewed deletion-edge repairs."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


FUNCTIONS = (
    "_canonical_profile_deletion_context",
    "_execute_canonical_profile_deletion",
)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def function_span(source: str, name: str) -> tuple[int, int, str]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            start = offsets[node.lineno - 1]
            end = offsets[node.end_lineno]
            return start, end, source[start:end]
    raise ValueError(f"handler is missing required function: {name}")


def patch_handler(deployed: str, local: str) -> str:
    _, _, owner_replacement = function_span(local, FUNCTIONS[0])
    _, _, deletion_replacement = function_span(local, FUNCTIONS[1])
    if "attribute_not_exists(#owner_principal_id)" not in owner_replacement:
        raise ValueError("local repair lacks the exact missing-owner conditional write")
    if ".scan(" in owner_replacement or ".scan(" in deletion_replacement:
        raise ValueError("owner-edge repair must not use DynamoDB Scan")
    if "S3 delete operations are strongly consistent" not in deletion_replacement:
        raise ValueError("local repair lacks the reviewed strong-consistency avatar confirmation")
    if "head_object(Bucket=PROFILE_AVATARS_BUCKET" in deletion_replacement:
        raise ValueError("avatar cleanup must not turn an absent key into a false 403 failure")

    patched = deployed
    for name in FUNCTIONS:
        start, end, _ = function_span(patched, name)
        _, _, replacement = function_span(local, name)
        patched = patched[:start] + replacement.rstrip() + "\n" + patched[end:]
    ast.parse(patched)
    for name in FUNCTIONS:
        _, _, result = function_span(patched, name)
        _, _, replacement = function_span(local, name)
        if result.strip() != replacement.strip():
            raise ValueError(f"patched {name} does not match local source")
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("owner-edge repair introduced a DynamoDB Scan")
    return patched


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--local-handler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        files = {info.filename: source.read(info.filename) for info in infos}
    if list(files).count("handler.py") != 1:
        raise ValueError("deployed ZIP must contain exactly one handler.py")

    deployed_handler = files["handler.py"]
    updated_handler = patch_handler(
        deployed_handler.decode("utf-8"),
        args.local_handler.read_text(encoding="utf-8"),
    ).encode("utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w") as destination:
        for info in infos:
            destination.writestr(
                info,
                updated_handler if info.filename == "handler.py" else files[info.filename],
            )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in files if result.read(name) != files[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={sha256(deployed_handler)}")
    print(f"OWNER_EDGE_HANDLER_SHA256={sha256(updated_handler)}")
    print(f"PACKAGE_SHA256={sha256(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
