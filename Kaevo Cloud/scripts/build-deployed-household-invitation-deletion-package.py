#!/usr/bin/env python3
"""Patch only exact household-invitation deletion into the deployed API ZIP."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


FUNCTION = "delete_household_invitation"
HELPERS = (
    "household_manager_bound_session",
    "_household_invitation_records",
    "_household_invitation_by_id",
)
DISPATCH_ANCHOR = '''    if method == "POST" and path.startswith("/v2/household/invitations/") and path.endswith("/revoke"):
        return revoke_household_invitation(event, path)

'''
DISPATCH_REPLACEMENT = DISPATCH_ANCHOR + '''    if method == "DELETE" and re.fullmatch(r"/v2/household/invitations/[^/]+", path):
        return delete_household_invitation(event, path)

'''


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
    required = set(HELPERS) | {FUNCTION}
    missing = sorted(required - set(local_spans))
    if missing:
        raise ValueError(f"local handler is missing invitation deletion functions: {missing}")
    if "join_household" not in deployed_spans:
        raise ValueError("deployed handler is missing the household join anchor")
    if DISPATCH_ANCHOR not in deployed and DISPATCH_REPLACEMENT not in deployed:
        raise ValueError("deployed handler is missing the invitation dispatch anchor")
    for name in required:
        if ".scan(" in local_spans[name][2]:
            raise ValueError(f"invitation deletion must not use DynamoDB Scan: {name}")

    patched = deployed
    for name in (FUNCTION,):
        spans = function_spans(patched)
        if name in spans:
            start, end, _ = spans[name]
            patched = (
                patched[:start]
                + local_spans[name][2].rstrip()
                + "\n"
                + patched[end:]
            )
    spans = function_spans(patched)
    insertion = spans["join_household"][0]
    inserts = [
        local_spans[name][2].rstrip()
        for name in HELPERS
        if name not in spans
    ]
    if FUNCTION not in spans:
        inserts.append(local_spans[FUNCTION][2].rstrip())
    if inserts:
        patched = (
            patched[:insertion]
            + "\n\n".join(inserts)
            + "\n\n\n"
            + patched[insertion:]
        )
    if DISPATCH_REPLACEMENT not in patched:
        patched = patched.replace(DISPATCH_ANCHOR, DISPATCH_REPLACEMENT, 1)
    ast.parse(patched)
    patched_spans = function_spans(patched)
    for name in required:
        if patched_spans[name][2].strip() != local_spans[name][2].strip():
            raise ValueError(f"patched invitation function differs from local source: {name}")
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("invitation deletion package introduced DynamoDB Scan")
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
        names = [item.filename for item in infos]
        if names.count("handler.py") != 1:
            raise ValueError("deployed ZIP must contain exactly one handler.py")
        original = {item.filename: source.read(item.filename) for item in infos}
        before = original["handler.py"]
        after = patched_handler(before.decode("utf-8"), local).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for item in infos:
                destination.writestr(
                    item,
                    after if item.filename == "handler.py" else original[item.filename],
                )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(before)}")
    print(f"INVITATION_DELETE_HANDLER_SHA256={digest(after)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
