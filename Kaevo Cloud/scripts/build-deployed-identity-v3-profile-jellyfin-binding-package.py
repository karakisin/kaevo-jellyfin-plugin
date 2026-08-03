#!/usr/bin/env python3
"""Patch only exact Cloud-profile/Jellyfin binding support into Identity V3."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


REPLACE_FUNCTIONS = (
    "claim_remote_request",
)

INSERT_FUNCTIONS = (
    "profile_jellyfin_binding_path_id",
    "_normalized_jellyfin_user_id",
    "_profile_jellyfin_binding_for_connector",
    "_household_identity_profile_records",
    "save_profile_jellyfin_binding_v3",
    "connector_remote_request_item",
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


def patch_lambda_handler(source: str) -> str:
    spans = function_spans(source)
    if "lambda_handler" not in spans:
        raise ValueError("deployed handler is missing lambda_handler")
    start, end, deployed = spans["lambda_handler"]
    route_anchor = '                "/v3/identity/profiles/{profileId}/bindings",\n'
    route_line = '                "/v3/identity/profiles/{profileId}/jellyfin-binding",\n'
    dispatch_anchor = (
        '    if method == "POST" and profile_binding_path_id(path):\n'
        '        return create_profile_binding_v3(event, path)\n'
    )
    dispatch = (
        '\n    if method == "PUT" and profile_jellyfin_binding_path_id(path):\n'
        '        return save_profile_jellyfin_binding_v3(event, path)\n'
    )
    if route_line in deployed or "save_profile_jellyfin_binding_v3(event, path)" in deployed:
        raise ValueError("deployed handler already dispatches profile Jellyfin binding")
    if deployed.count(route_anchor) != 1 or deployed.count(dispatch_anchor) != 1:
        raise ValueError("deployed lambda_handler anchors are ambiguous")
    patched = deployed.replace(route_anchor, route_anchor + route_line, 1)
    patched = patched.replace(dispatch_anchor, dispatch_anchor + dispatch, 1)
    return source[:start] + patched.rstrip() + "\n" + source[end:]


def patch_join_household(source: str, local: str) -> str:
    deployed_spans = function_spans(source)
    local_spans = function_spans(local)
    if "join_household" not in deployed_spans or "join_household" not in local_spans:
        raise ValueError("join_household is missing")
    deployed = deployed_spans["join_household"][2]
    local_join = local_spans["join_household"][2]
    block_start = "    invitation_jellyfin_user_id = _normalized_jellyfin_user_id(\n"
    block_end = "    profile.pop(\"pending_invitation_id\", None)\n"
    if local_join.count(block_start) != 1 or local_join.count(block_end) != 1:
        raise ValueError("local join binding propagation anchors changed")
    binding_block = local_join[
        local_join.index(block_start):local_join.index(block_end)
    ]
    if ".scan(" in binding_block:
        raise ValueError("join binding propagation uses DynamoDB Scan")
    if block_start in deployed:
        raise ValueError("deployed join already propagates Jellyfin binding")
    if deployed.count(block_end) != 1:
        raise ValueError("deployed join propagation anchor is ambiguous")
    patched_join = deployed.replace(block_end, binding_block + block_end, 1)
    start, end, _ = deployed_spans["join_household"]
    return source[:start] + patched_join.rstrip() + "\n" + source[end:]


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
            f"deployed handler already contains binding functions: {unexpected_existing}"
        )
    for name in required:
        if ".scan(" in local_spans[name][2]:
            raise ValueError(f"profile binding function uses DynamoDB Scan: {name}")

    # Fail closed if the replaced claim function contains changes beyond the
    # exact binding projection required by this campaign. The join path is
    # patched statement-by-statement below so unrelated dirty authority work
    # can never enter the deployment package.
    deployed_claim = deployed_spans["claim_remote_request"][2]
    expected_claim = deployed_claim.replace(
        "public_remote_request_item(claimed, include_payload=False)",
        "connector_remote_request_item(claimed)",
        1,
    )
    if local_spans["claim_remote_request"][2].strip() != expected_claim.strip():
        raise ValueError("claim_remote_request contains changes beyond binding projection")

    patched = patch_join_household(deployed, local)
    for name in REPLACE_FUNCTIONS:
        patched = replace_function(patched, name, local_spans[name][2])

    spans = function_spans(patched)
    profile_offset = spans["create_profile_binding_v3"][0]
    profile_insertion = "\n\n".join(
        local_spans[name][2].rstrip() for name in INSERT_FUNCTIONS[:-1]
    ) + "\n\n\n"
    patched = patched[:profile_offset] + profile_insertion + patched[profile_offset:]

    spans = function_spans(patched)
    connector_offset = spans["decode_remote_response_payload"][0]
    connector_insertion = local_spans["connector_remote_request_item"][2].rstrip() + "\n\n\n"
    patched = patched[:connector_offset] + connector_insertion + patched[connector_offset:]
    patched = patch_lambda_handler(patched)

    ast.parse(patched)
    patched_spans = function_spans(patched)
    for name in required:
        if patched_spans[name][2].strip() != local_spans[name][2].strip():
            raise ValueError(f"patched function does not match local source: {name}")
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("profile binding package introduced a DynamoDB Scan")
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
    print(f"BINDING_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
