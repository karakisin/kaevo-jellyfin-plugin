#!/usr/bin/env python3
"""Build digest-pinned Dev repairs without packaging the working tree.

The identity package starts from the currently deployed dedicated identity
ZIP and imports only the already-live parent-managed identity projection from
the generic Dev API ZIP. The API package starts from the currently deployed
generic ZIP and replaces only Household Sync target authorization with the
reviewed source function.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import zipfile
from pathlib import Path


EXPECTED_IDENTITY_SHA256 = "865f7d9784d0f272c3f713d86e4ccb2a88fceffb8866bee3b73c0fc003974528"
EXPECTED_API_SHA256 = "874b233b2725b379b2f006a07680694cefb4bf4ed9fc1c34e9dd9f2fb3a3fab7"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def function_sources(text: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    return {
        node.name: "".join(lines[node.lineno - 1:node.end_lineno]) + "\n"
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def exactly_once(text: str, anchor: str) -> int:
    count = text.count(anchor)
    if count != 1:
        raise ValueError(f"expected exactly one anchor, found {count}: {anchor!r}")
    return text.index(anchor)


def identity_projection(text: str) -> str:
    start = "        profile_access = resolve_profile_access(\n"
    end = "        if profile_access and security_audit_table is not None:\n"
    start_index = exactly_once(text, start)
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise ValueError("identity projection end anchor is missing")
    return text[start_index:end_index]


def replace_function(text: str, name: str, replacement: str) -> str:
    functions = function_sources(text)
    current = functions.get(name)
    if current is None:
        raise ValueError(f"handler lacks function {name}")
    if text.count(current) != 1:
        raise ValueError(f"function source is not unique: {name}")
    return text.replace(current, replacement, 1)


def write_repacked(base_zip: Path, output_zip: Path, handler_text: str) -> dict:
    compile(handler_text, "handler.py", "exec")
    with zipfile.ZipFile(base_zip, "r") as input_zip:
        if input_zip.namelist().count("handler.py") != 1:
            raise ValueError("deployment ZIP must contain exactly one root handler.py")
        before = input_zip.read("handler.py")
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip, "w") as output:
            for info in input_zip.infolist():
                payload = handler_text.encode("utf-8") if info.filename == "handler.py" else input_zip.read(info.filename)
                output.writestr(info, payload)
    return {
        "base_sha256": sha256(base_zip.read_bytes()),
        "output_sha256": sha256(output_zip.read_bytes()),
        "changed_files": ["handler.py"],
        "handler_bytes_before": len(before),
        "handler_bytes_after": len(handler_text.encode("utf-8")),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-zip", type=Path, required=True)
    parser.add_argument("--api-zip", type=Path, required=True)
    parser.add_argument("--source-handler", type=Path, required=True)
    parser.add_argument("--identity-output", type=Path, required=True)
    parser.add_argument("--api-output", type=Path, required=True)
    args = parser.parse_args()

    if sha256(args.identity_zip.read_bytes()) != EXPECTED_IDENTITY_SHA256:
        raise ValueError("identity ZIP digest does not match the reviewed deployed base")
    if sha256(args.api_zip.read_bytes()) != EXPECTED_API_SHA256:
        raise ValueError("API ZIP digest does not match the reviewed deployed base")

    with zipfile.ZipFile(args.identity_zip, "r") as archive:
        identity = archive.read("handler.py").decode("utf-8")
    with zipfile.ZipFile(args.api_zip, "r") as archive:
        api = archive.read("handler.py").decode("utf-8")
    source = args.source_handler.read_text(encoding="utf-8")

    api_functions = function_sources(api)
    parent_helper = api_functions.get("_authorized_parent_managed_profile_access")
    if parent_helper is None or "owner_principal_id" not in parent_helper:
        raise ValueError("live API reference lacks reviewed parent-managed helper")
    if "def _authorized_parent_managed_profile_access(" in identity:
        raise ValueError("identity base already contains parent-managed recovery")
    helper_anchor = "def _authorized_viewing_profile_access(*, source_profile, household_id):\n"
    helper_index = exactly_once(identity, helper_anchor)
    identity = identity[:helper_index] + parent_helper + identity[helper_index:]
    old_projection = identity_projection(identity)
    new_projection = identity_projection(api)
    if "parent_managed_access = _authorized_parent_managed_profile_access(" not in new_projection:
        raise ValueError("live API identity projection lacks parent-managed recovery")
    identity = identity.replace(old_projection, new_projection, 1)

    source_function = function_sources(source).get("_household_progress_authorized_target_ids")
    if source_function is None or "principals_table.get_item" not in source_function:
        raise ValueError("source lacks reviewed Household Sync parent-managed authorization")
    api = replace_function(api, "_household_progress_authorized_target_ids", source_function)

    report = {
        "identity": write_repacked(args.identity_zip, args.identity_output, identity),
        "api": write_repacked(args.api_zip, args.api_output, api),
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
