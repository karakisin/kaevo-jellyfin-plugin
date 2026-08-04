#!/usr/bin/env python3
"""Build an exact Profile Switching release from the live Identity V3 ZIP.

Only the selected profile-switching functions and the existing access-role
capability table are patched.  The builder starts from the live artifact and
rejects unexpected files, imports, routes, or handler anchors so unrelated
checkout changes can never ride along with this release.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


HANDLER_REPLACEMENTS = (
    "identity_me_v3",
    "_normalized_self_profile_access",
)
HANDLER_INSERTIONS = (
    "_profile_switch_pin_configured",
    "_profile_switch_protection",
    "_authorized_switch_target_access",
    "_decorate_profile_access_with_switch_protection",
)
PATH_HELPERS = (
    "profile_switch_pin_path_id",
    "profile_switch_pin_verification_path_id",
    "profile_switch_targets_path_id",
)
ENDPOINTS = (
    "_switch_pin_material",
    "_verify_switch_pin",
    "_exact_identity_profile",
    "_profile_switch_failure",
    "set_profile_switch_pin_v3",
    "verify_profile_switch_pin_v3",
    "update_profile_switch_targets_v3",
)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def spans(source: str) -> dict[str, tuple[int, int, str]]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    result = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result[node.name] = (
                offsets[node.lineno - 1],
                offsets[node.end_lineno],
                source[offsets[node.lineno - 1]:offsets[node.end_lineno]],
            )
    return result


def function(source: str, name: str) -> str:
    try:
        return spans(source)[name][2].rstrip() + "\n"
    except KeyError as error:
        raise ValueError(f"missing required local function: {name}") from error


def replace_function(source: str, name: str, replacement: str) -> str:
    try:
        start, end, _ = spans(source)[name]
    except KeyError as error:
        raise ValueError(f"deployed handler is missing required function: {name}") from error
    return source[:start] + replacement.rstrip() + "\n" + source[end:]


def insert_before_function(source: str, name: str, blocks: tuple[str, ...]) -> str:
    try:
        start, _, _ = spans(source)[name]
    except KeyError as error:
        raise ValueError(f"deployed handler is missing insertion anchor: {name}") from error
    return source[:start] + "\n\n".join(block.rstrip() for block in blocks) + "\n\n\n" + source[start:]


def patch_dispatch(source: str) -> str:
    anchor = '''    if method == "POST" and profile_binding_path_id(path):
        return create_profile_binding_v3(event, path)

'''
    addition = '''    if method == "PUT" and profile_switch_pin_path_id(path):
        return set_profile_switch_pin_v3(event, path)

    if method == "POST" and profile_switch_pin_verification_path_id(path):
        return verify_profile_switch_pin_v3(event, path)

    if method == "PUT" and profile_switch_targets_path_id(path):
        return update_profile_switch_targets_v3(event, path)

'''
    if "set_profile_switch_pin_v3(event, path)" in source:
        raise ValueError("deployed handler already dispatches profile switching")
    if source.count(anchor) != 1:
        raise ValueError("deployed handler has an ambiguous profile-binding dispatch anchor")
    return source.replace(anchor, addition + anchor, 1)


def patch_diagnostics(source: str) -> str:
    anchor = '                "/v3/identity/profiles/{profileId}/bindings",\n'
    additions = (
        '                "/v3/identity/profiles/{profileId}/switch-pin",\n'
        '                "/v3/identity/profiles/{profileId}/switch-pin/verify",\n'
        '                "/v3/identity/profiles/{profileId}/switch-targets",\n'
    )
    if source.count(anchor) != 1:
        raise ValueError("deployed handler has an ambiguous profile-binding diagnostic anchor")
    return source.replace(anchor, anchor + "".join(additions), 1)


def patch_access_role_capabilities(deployed: str, local: str) -> str:
    marker = "        Capability.PROFILE_SWITCH,\n"
    desired = marker + "        Capability.PROFILE_SWITCH_GRANT,\n"
    if desired not in local:
        raise ValueError("local account foundation is missing the Admin profile-switch capability")
    admin_start = deployed.find("    HouseholdAccessRole.ADMIN: frozenset({")
    admin_end = deployed.find("    }),", admin_start)
    if admin_start < 0 or admin_end < 0:
        raise ValueError("deployed Admin capability block is unavailable")
    admin_block = deployed[admin_start:admin_end]
    if desired in admin_block:
        raise ValueError("deployed Admin capability already includes profile switch grants")
    if admin_block.count(marker) != 1:
        raise ValueError("deployed Admin capability marker is ambiguous")
    patched_block = admin_block.replace(marker, desired, 1)
    return deployed[:admin_start] + patched_block + deployed[admin_end:]


def patched_handler(deployed: str, local: str) -> str:
    if any(f"def {name}(" in deployed for name in (*HANDLER_INSERTIONS, *PATH_HELPERS, *ENDPOINTS)):
        raise ValueError("deployed handler already contains Profile Switching implementation")
    deployed = patch_diagnostics(deployed)
    for name in HANDLER_REPLACEMENTS:
        deployed = replace_function(deployed, name, function(local, name))
    deployed = insert_before_function(
        deployed,
        "_identity_migration_audit",
        tuple(function(local, name) for name in HANDLER_INSERTIONS),
    )
    deployed = insert_before_function(
        deployed,
        "profile_deletion_path_id",
        tuple(function(local, name) for name in PATH_HELPERS),
    )
    deployed = patch_dispatch(deployed)
    deployed = insert_before_function(
        deployed,
        "_mapping_context",
        tuple(function(local, name) for name in ENDPOINTS),
    )
    ast.parse(deployed)
    return deployed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--local-handler", required=True, type=Path)
    parser.add_argument("--local-account-foundation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    local_handler = args.local_handler.read_text(encoding="utf-8")
    local_account_foundation = args.local_account_foundation.read_text(encoding="utf-8")
    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        files = {item.filename: source.read(item.filename) for item in infos}
        if {"handler.py", "account_foundation.py"} - set(files):
            raise ValueError("deployed ZIP is missing a required Identity V3 module")
        updated_handler = patched_handler(files["handler.py"].decode("utf-8"), local_handler).encode("utf-8")
        updated_account_foundation = patch_access_role_capabilities(
            files["account_foundation.py"].decode("utf-8"), local_account_foundation,
        ).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as output:
            for item in infos:
                output.writestr(
                    item,
                    updated_handler if item.filename == "handler.py" else (
                        updated_account_foundation if item.filename == "account_foundation.py" else files[item.filename]
                    ),
                )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name, data in files.items() if result.read(name) != data]
    if set(changed) != {"handler.py", "account_foundation.py"}:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={sha256(files['handler.py'])}")
    print(f"PROFILE_SWITCH_HANDLER_SHA256={sha256(updated_handler)}")
    print(f"DEPLOYED_ACCOUNT_FOUNDATION_SHA256={sha256(files['account_foundation.py'])}")
    print(f"PROFILE_SWITCH_ACCOUNT_FOUNDATION_SHA256={sha256(updated_account_foundation)}")
    print(f"PACKAGE_SHA256={sha256(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py,account_foundation.py")


if __name__ == "__main__":
    main()
