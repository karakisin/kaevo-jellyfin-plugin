#!/usr/bin/env python3
"""Patch only exact Jellyfin-binding promotion into the deployed Join Lambda."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


HELPER = "_consumed_invitation_jellyfin_binding"
TARGET = "profile_setup"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def function_spans(source: str) -> dict[str, tuple[int, int, str]]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    spans: dict[str, tuple[int, int, str]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = offsets[node.lineno - 1]
            end = offsets[node.end_lineno]
            spans[node.name] = (start, end, source[start:end])
    return spans


def patched_handler(deployed: str, local: str) -> str:
    deployed_spans = function_spans(deployed)
    local_spans = function_spans(local)
    if TARGET not in deployed_spans or TARGET not in local_spans:
        raise ValueError("profile_setup is missing from deployed or local handler")
    if HELPER not in local_spans:
        raise ValueError("local exact binding helper is missing")
    if HELPER in deployed_spans:
        raise ValueError("deployed handler already contains exact binding promotion")
    for name in (HELPER, TARGET):
        if ".scan(" in local_spans[name][2]:
            raise ValueError(f"{name} uses DynamoDB Scan")

    target_start, target_end, _ = deployed_spans[TARGET]
    replacement = (
        local_spans[HELPER][2].rstrip()
        + "\n\n\n"
        + local_spans[TARGET][2].rstrip()
        + "\n"
    )
    patched = deployed[:target_start] + replacement + deployed[target_end:]
    ast.parse(patched)

    patched_spans = function_spans(patched)
    for name in (HELPER, TARGET):
        if patched_spans[name][2].strip() != local_spans[name][2].strip():
            raise ValueError(f"patched function does not match local source: {name}")
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("Join promotion package introduced a DynamoDB Scan")
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
        if names.count("household_join_handler.py") != 1:
            raise ValueError(
                "deployed ZIP must contain exactly one household_join_handler.py"
            )
        original_files = {info.filename: source.read(info.filename) for info in infos}
        original_handler = original_files["household_join_handler.py"]
        updated_handler = patched_handler(
            original_handler.decode("utf-8"), local
        ).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(
                    info,
                    updated_handler
                    if info.filename == "household_join_handler.py"
                    else original_files[info.filename],
                )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original_files[name]]
    if changed != ["household_join_handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(original_handler)}")
    print(f"PROMOTION_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=household_join_handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
