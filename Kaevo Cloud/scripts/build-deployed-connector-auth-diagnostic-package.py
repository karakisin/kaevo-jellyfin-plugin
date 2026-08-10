#!/usr/bin/env python3
"""Add bounded V3 connector-auth diagnostics to an exact live Lambda ZIP."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


DIAGNOSTIC_CONSTANT = "PAIRING_V3_CONNECTOR_AUTH_DIAGNOSTIC_EVENT"
INSERT_BEFORE = "def app_bearer_token(event):"
COPY_FUNCTIONS = (
    "_pairing_v3_connector_route_category",
    "_pairing_v3_connector_auth_rejected",
)
REPLACE_FUNCTION = "require_pairing_v3_connector_auth"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def function_spans(source: str) -> dict[str, tuple[int, int, str]]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    return {
        node.name: (offsets[node.lineno - 1], offsets[node.end_lineno], source[offsets[node.lineno - 1]:offsets[node.end_lineno]])
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def diagnostic_block(source: str) -> str:
    start = source.find(f'{DIAGNOSTIC_CONSTANT} = "')
    end = source.find(INSERT_BEFORE, start)
    if start < 0 or end < 0:
        raise ValueError("reviewed source is missing the connector-auth diagnostic block")
    block = source[start:end]
    spans = function_spans(block)
    if set(spans) != set(COPY_FUNCTIONS):
        raise ValueError(f"unexpected diagnostic helper functions: {sorted(spans)}")
    return block.rstrip() + "\n\n\n"


def patched_handler(deployed: str, reviewed: str) -> str:
    if DIAGNOSTIC_CONSTANT in deployed or any(name in deployed for name in COPY_FUNCTIONS):
        raise ValueError("deployed handler already contains connector-auth diagnostics")
    if deployed.count(INSERT_BEFORE) != 1:
        raise ValueError("deployed app bearer anchor is ambiguous")

    deployed_spans = function_spans(deployed)
    reviewed_spans = function_spans(reviewed)
    if REPLACE_FUNCTION not in deployed_spans or REPLACE_FUNCTION not in reviewed_spans:
        raise ValueError("connector-auth function is missing")

    block = diagnostic_block(reviewed)
    patched = deployed.replace(INSERT_BEFORE, block + INSERT_BEFORE, 1)
    spans = function_spans(patched)
    start, end, _ = spans[REPLACE_FUNCTION]
    replacement = reviewed_spans[REPLACE_FUNCTION][2].rstrip() + "\n"
    patched = patched[:start] + replacement + patched[end:]
    ast.parse(patched)

    final_spans = function_spans(patched)
    if final_spans[REPLACE_FUNCTION][2].rstrip() != replacement.rstrip():
        raise ValueError("connector-auth replacement did not match reviewed source")
    for name in COPY_FUNCTIONS:
        if final_spans[name][2] != reviewed_spans[name][2]:
            raise ValueError(f"diagnostic helper differs from reviewed source: {name}")
    if patched.count(DIAGNOSTIC_CONSTANT) != reviewed.count(DIAGNOSTIC_CONSTANT):
        raise ValueError("diagnostic constant references are incomplete")
    if "downloaders.set_queue_state" not in patched:
        raise ValueError("live downloader controls were not preserved")
    return patched


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--reviewed-handler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    reviewed = args.reviewed_handler.read_text(encoding="utf-8")
    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if names.count("handler.py") != 1:
            raise ValueError("deployed ZIP must contain exactly one handler.py")
        original = {info.filename: source.read(info.filename) for info in infos}
        updated_handler = patched_handler(original["handler.py"].decode("utf-8"), reviewed).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(info, updated_handler if info.filename == "handler.py" else original[info.filename])

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(original['handler.py'])}")
    print(f"DIAGNOSTIC_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("HANDLER_CHANGED_SCOPE=diagnostic constants, two diagnostic helpers, require_pairing_v3_connector_auth")


if __name__ == "__main__":
    main()
