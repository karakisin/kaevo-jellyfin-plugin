#!/usr/bin/env python3
"""Patch only exact legacy membership pointer reconciliation into Identity V3."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


REPAIR_START = "\ndef _repair_legacy_active_membership_profile_pointer(\n"
REPAIR_END = "\ndef _public_household_profile_roster_item("

IDENTITY_ANCHOR = '''        normalized_membership = household_memberships_table.get_item(Key={
            "household_id": claims.household_id,
            "membership_id": household_membership_id(claims.account_id, claims.household_id),
        }, ConsistentRead=True).get("Item")
        claims, resolved_role, normalized_membership = resolve_household_membership(
'''
IDENTITY_REPLACEMENT = '''        normalized_membership = household_memberships_table.get_item(Key={
            "household_id": claims.household_id,
            "membership_id": household_membership_id(claims.account_id, claims.household_id),
        }, ConsistentRead=True).get("Item")
        normalized_membership = _repair_legacy_active_membership_profile_pointer(
            normalized_membership,
            expected_profile_id=claims.profile_id,
        )
        claims, resolved_role, normalized_membership = resolve_household_membership(
'''

ROSTER_ANCHOR = '''            or str(membership.get("household_id") or "") != household_id
        ):
            continue
        profile_id = str(membership.get("profile_id") or "")
'''
ROSTER_REPLACEMENT = '''            or str(membership.get("household_id") or "") != household_id
        ):
            continue
        membership = _repair_legacy_active_membership_profile_pointer(membership)
        profile_id = str(membership.get("profile_id") or "")
'''

CONNECTOR_ANCHOR = '''    normalized_membership = household_memberships_table.get_item(Key={
        "household_id": household_id,
        "membership_id": household_membership_id(account_id, household_id),
    }, ConsistentRead=True).get("Item")
    try:
'''
CONNECTOR_REPLACEMENT = '''    normalized_membership = household_memberships_table.get_item(Key={
        "household_id": household_id,
        "membership_id": household_membership_id(account_id, household_id),
    }, ConsistentRead=True).get("Item")
    normalized_membership = _repair_legacy_active_membership_profile_pointer(
        normalized_membership,
        expected_profile_id=profile_id,
    )
    try:
'''


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def repair_block(local: str) -> str:
    try:
        start = local.index(REPAIR_START)
        end = local.index(REPAIR_END, start)
    except ValueError as error:
        raise ValueError("local handler does not contain the exact pointer repair block") from error
    return local[start:end]


def replace_once(source: str, anchor: str, replacement: str, label: str) -> str:
    if source.count(anchor) != 1:
        raise ValueError(f"deployed handler does not contain exactly one {label} anchor")
    return source.replace(anchor, replacement, 1)


def patched_handler(deployed: str, local: str) -> str:
    if "def _repair_legacy_active_membership_profile_pointer(" in deployed:
        raise ValueError("deployed package already contains membership pointer reconciliation")
    if REPAIR_END not in deployed:
        raise ValueError("deployed handler does not contain the roster projection anchor")
    patched = deployed.replace(REPAIR_END, repair_block(local) + REPAIR_END, 1)
    patched = replace_once(patched, IDENTITY_ANCHOR, IDENTITY_REPLACEMENT, "identity")
    patched = replace_once(patched, ROSTER_ANCHOR, ROSTER_REPLACEMENT, "roster")
    return replace_once(patched, CONNECTOR_ANCHOR, CONNECTOR_REPLACEMENT, "connector")


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
    print(f"REPAIRED_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")


if __name__ == "__main__":
    main()
