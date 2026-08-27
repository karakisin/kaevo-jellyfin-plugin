#!/usr/bin/env python3
"""Patch only exact deleted-profile recovery support into the deployed API ZIP."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


INSERT_FUNCTIONS = ("_deleted_profile_recovery_tombstone",)
REPLACE_FUNCTIONS = (
    "_retain_deleted_profile_binding_tombstone",
    "create_household_invitation",
    "save_profile_jellyfin_binding_v3",
    "save_profile_seerr_binding_v3",
)
INSERT_BEFORE = "preflight_profile_jellyfin_binding_v3"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def replace_function(source: str, name: str, replacement: str) -> str:
    spans = function_spans(source)
    if name not in spans:
        raise ValueError(f"deployed handler is missing required function: {name}")
    start, end, _ = spans[name]
    return source[:start] + replacement.rstrip() + "\n" + source[end:]


def patched_handler(deployed: str, local: str) -> str:
    deployed_spans = function_spans(deployed)
    local_spans = function_spans(local)
    required = set(INSERT_FUNCTIONS) | set(REPLACE_FUNCTIONS)
    missing_local = sorted(required - set(local_spans))
    if missing_local:
        raise ValueError(f"local handler is missing recovery functions: {missing_local}")
    missing_deployed = sorted(set(REPLACE_FUNCTIONS) - set(deployed_spans))
    if missing_deployed:
        raise ValueError(f"deployed handler is missing recovery anchors: {missing_deployed}")
    if INSERT_BEFORE not in deployed_spans:
        raise ValueError("deployed handler is missing recovery insertion anchor")
    if any(name in deployed_spans for name in INSERT_FUNCTIONS):
        raise ValueError("deployed handler already contains deleted-profile recovery")

    patched = deployed
    for name in REPLACE_FUNCTIONS:
        patched = replace_function(patched, name, local_spans[name][2])

    spans = function_spans(patched)
    insertion = spans[INSERT_BEFORE][0]
    inserted = "\n\n".join(
        local_spans[name][2].rstrip() for name in INSERT_FUNCTIONS
    )
    patched = patched[:insertion] + inserted + "\n\n\n" + patched[insertion:]

    ast.parse(patched)
    patched_spans = function_spans(patched)
    for name in required:
        if patched_spans[name][2].strip() != local_spans[name][2].strip():
            raise ValueError(f"patched recovery function differs from local source: {name}")
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("deleted-profile recovery package introduced DynamoDB Scan")
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
        original = {info.filename: source.read(info.filename) for info in infos}
        before = original["handler.py"]
        after = patched_handler(before.decode("utf-8"), local).encode("utf-8")
        if args.output.exists():
            raise ValueError("output already exists; refusing to overwrite")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(
                    info,
                    after if info.filename == "handler.py" else original[info.filename],
                )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(before)}")
    print(f"RECOVERY_HANDLER_SHA256={digest(after)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
