#!/usr/bin/env python3
"""Recover explicit profile grants in the pinned trusted Lambda artifact.

This is intentionally a narrow recovery builder.  It begins with the
immutable, known-good deployment ZIP and changes only ``handler.py``.  The
patch restores the server-authoritative Profile Switching and Who's Watching
contracts plus the already-reviewed Household Sync block; it does not package
the working tree or alter any DynamoDB records.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
import zipfile
from pathlib import Path


EXPECTED_TRUSTED_SHA256 = "7e8849e730b1d9341b757af2a97eef35bb2150be96e5aa6b20dccc477eb3c702"
HOUSEHOLD_BLOCK_START = "HOUSEHOLD_PROGRESS_EVENT_TYPE ="
HOUSEHOLD_BLOCK_END = "def extract_profile_id_from_settings_path("
IDENTITY_INSERT_ANCHOR = "def identity_me_v3("
HOUSEHOLD_INSERT_ANCHOR = "def extract_profile_id_from_settings_path("
REMOTE_COMMAND_ANCHOR = '    if method == "POST" and path == "/v1/remote-commands":\n        return create_remote_command(event)\n'
IDENTITY_ME_ANCHOR = '    if method == "GET" and path == "/v3/identity/me":\n        return identity_me_v3(event)\n'
PROFILE_BINDING_ROUTE_ANCHOR = '    if method == "POST" and profile_binding_path_id(path):\n        return create_profile_binding_v3(event, path)\n'
CATALOG_ANCHOR = '                "/v1/events/recent",\n'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def function_sources(text: str) -> dict[str, str]:
    lines = text.splitlines()
    tree = ast.parse(text)
    return {
        node.name: "\n".join(lines[node.lineno - 1:node.end_lineno]) + "\n\n"
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def exactly_once(text: str, anchor: str) -> int:
    count = text.count(anchor)
    if count != 1:
        raise ValueError(f"expected exactly one anchor, found {count}: {anchor!r}")
    return text.index(anchor)


def insert_before(text: str, anchor: str, insertion: str) -> str:
    index = exactly_once(text, anchor)
    return text[:index] + insertion + text[index:]


def insert_after(text: str, anchor: str, insertion: str) -> str:
    index = exactly_once(text, anchor) + len(anchor)
    return text[:index] + insertion + text[index:]


def replace_once(text: str, old: str, new: str) -> str:
    index = exactly_once(text, old)
    return text[:index] + new + text[index + len(old):]


def roster_function() -> str:
    # This read-only projection purposefully does not include deletion
    # finalization.  It reads exact active membership/profile records only,
    # leaving destructive lifecycle work to its existing dedicated endpoint.
    return '''def list_household_profiles_v3(event):
    """Return the exact active household roster to an authorized manager."""
    if any(table is None for table in (
        household_memberships_table,
        identity_profiles_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    if "household.manage" not in set((context.get("household") or {}).get("capabilities") or []):
        return response(403, {"state": "household_profile_roster_not_authorized"})
    household_id = str((context.get("household") or {}).get("household_id") or "")
    if not household_id:
        return response(409, {"state": "household_profile_roster_unavailable"})

    roster_by_profile_id = {}
    for membership in _household_membership_records(household_id):
        if (
            not isinstance(membership, dict)
            or membership.get("entity_type") != "HouseholdMembership"
            or membership.get("status") != "active"
            or str(membership.get("household_id") or "") != household_id
        ):
            continue
        membership = _repair_legacy_active_membership_profile_pointer(membership)
        profile_id = str(membership.get("profile_id") or "")
        if not profile_id:
            continue
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(profile, dict)
            or profile.get("state") != "active"
            or str(profile.get("profile_id") or "") != profile_id
            or str(profile.get("household_id") or "") != household_id
            or str(profile.get("account_id") or "") != str(membership.get("account_id") or "")
        ):
            continue
        try:
            item = _public_household_profile_roster_item(
                profile,
                canonical_role=str(membership.get("canonical_role") or ""),
                household_access_role=str(membership.get("household_access_role") or ""),
            )
        except AccountFoundationError:
            continue
        roster_by_profile_id[item["profile_id"]] = item

    profiles = sorted(roster_by_profile_id.values(), key=lambda item: (
        str(item["display_name"]).casefold(), item["profile_id"],
    ))
    return response(200, {
        "schema_version": 1,
        "state": "household_profiles_ready",
        "profiles": profiles,
    })


'''


def profile_access_tail(source: str) -> str:
    start = '        profile_access = resolve_profile_access(\n'
    end = '        if profile_access and security_audit_table is not None:\n'
    start_index = exactly_once(source, start)
    end_index = source.find(end, start_index)
    if end_index < 0:
        raise ValueError("source identity projection end anchor is missing")
    return source[start_index:end_index]


def patched_handler(deployed: str, source: str) -> str:
    if "household-progress" in deployed or "_authorized_viewing_profile_access" in deployed:
        raise ValueError("trusted artifact is not the expected unpatched base")
    functions = function_sources(source)
    required = [
        "_profile_switch_pin_configured",
        "_profile_switch_protection",
        "_authorized_switch_target_access",
        "_authorized_viewing_profile_access",
        "_decorate_profile_access_with_switch_protection",
        "_household_membership_records",
        "_public_household_profile_roster_item",
        "_exact_identity_profile",
        "_profile_switch_failure",
        "profile_switch_targets_path_id",
        "profile_watching_targets_path_id",
        "update_profile_switch_targets_v3",
        "update_profile_watching_targets_v3",
    ]
    missing = [name for name in required if name not in functions]
    if missing:
        raise ValueError(f"source handler lacks required functions: {missing}")
    household_start = source.find(HOUSEHOLD_BLOCK_START)
    household_end = source.find(HOUSEHOLD_BLOCK_END, household_start)
    if household_start < 0 or household_end < 0:
        raise ValueError("source Household Sync block anchors are missing")
    household_block = source[household_start:household_end]
    if "session_started_at_epoch_milliseconds" not in household_block:
        raise ValueError("Household Sync block lacks millisecond ordering")
    if "Key(\"event_key\").begins_with" not in household_block:
        raise ValueError("Household Sync reads are not key constrained")

    helper_names = required[:5]
    helper_block = "".join(functions[name] for name in helper_names)
    roster_block = (
        functions["_household_membership_records"]
        + functions["_public_household_profile_roster_item"]
        + roster_function()
    )
    write_block = "".join(functions[name] for name in required[7:])

    patched = insert_before(deployed, IDENTITY_INSERT_ANCHOR, helper_block)
    patched = insert_before(patched, IDENTITY_INSERT_ANCHOR, roster_block)
    patched = insert_before(patched, "def _mapping_context(event, *, verified_session=None):", write_block)
    # Preserve the trusted runtime's authentication and migration logic; only
    # replace its profile projection with the exact explicit-grant extension.
    old_start = '        profile_access = resolve_profile_access(\n'
    old_end = '        if profile_access and security_audit_table is not None:\n'
    old_start_index = exactly_once(patched, old_start)
    old_end_index = patched.find(old_end, old_start_index)
    if old_end_index < 0:
        raise ValueError("trusted identity projection end anchor is missing")
    patched = patched[:old_start_index] + profile_access_tail(source) + patched[old_end_index:]
    patched = insert_before(patched, HOUSEHOLD_INSERT_ANCHOR, household_block)
    patched = insert_after(
        patched,
        REMOTE_COMMAND_ANCHOR,
        '\n    if method == "POST" and path == "/v1/household-progress":\n        return save_household_progress(event)\n\n'
        '    if method == "GET" and path == "/v1/household-progress":\n        return get_household_progress(event)\n',
    )
    patched = insert_after(
        patched,
        IDENTITY_ME_ANCHOR,
        '\n    if method == "GET" and path == "/v3/identity/households/profiles":\n        return list_household_profiles_v3(event)\n',
    )
    patched = insert_after(
        patched,
        PROFILE_BINDING_ROUTE_ANCHOR,
        '\n    if method == "PUT" and profile_switch_targets_path_id(path):\n        return update_profile_switch_targets_v3(event, path)\n\n'
        '    if method == "PUT" and profile_watching_targets_path_id(path):\n        return update_profile_watching_targets_v3(event, path)\n',
    )
    catalog_insertion = (
        '                "/v1/household-progress",\n'
        '                "/v3/identity/households/profiles",\n'
        '                "/v3/identity/profiles/{profileId}/switch-targets",\n'
        '                "/v3/identity/profiles/{profileId}/watching-targets",\n'
    )
    patched = insert_after(patched, CATALOG_ANCHOR, catalog_insertion)
    compile(patched, "handler.py", "exec")
    return patched


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-zip", type=Path, required=True)
    parser.add_argument("--source-handler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    trusted_bytes = args.trusted_zip.read_bytes()
    if sha256(trusted_bytes) != EXPECTED_TRUSTED_SHA256:
        raise ValueError("trusted ZIP digest does not match the reviewed recovery base")
    source = args.source_handler.read_text(encoding="utf-8")
    with zipfile.ZipFile(args.trusted_zip, "r") as input_zip:
        names = input_zip.namelist()
        if names.count("handler.py") != 1:
            raise ValueError("trusted ZIP must contain exactly one root handler.py")
        deployed = input_zip.read("handler.py").decode("utf-8")
        patched = patched_handler(deployed, source).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as output_zip:
            for info in input_zip.infolist():
                output_zip.writestr(info, patched if info.filename == "handler.py" else input_zip.read(info.filename))

    output_bytes = args.output.read_bytes()
    print(json.dumps({
        "trusted_sha256": sha256(trusted_bytes),
        "patched_sha256": sha256(output_bytes),
        "changed_files": ["handler.py"],
        "handler_bytes_before": len(deployed.encode("utf-8")),
        "handler_bytes_after": len(patched),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
