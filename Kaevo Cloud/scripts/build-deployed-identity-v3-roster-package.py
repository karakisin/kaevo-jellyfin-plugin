#!/usr/bin/env python3
"""Patch only the canonical household roster path into Identity V3's ZIP."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


ROSTER_START = "\ndef _household_cloud_profile_records(household_id):\n"
ROSTER_END = "\ndef _resolve_ownership_candidate(household, normalized_membership):\n"
DIAGNOSTIC_ANCHOR = '    "/v3/identity/profile-mappings",\n})\n'
DIAGNOSTIC_REPLACEMENT = (
    '    "/v3/identity/profile-mappings",\n'
    '    "/v3/identity/households/profiles",\n'
    '})\n'
)
DISPATCH_ANCHOR = '''    if method == "GET" and path == "/v3/identity/households/ownership-transfer/candidates":
        return list_ownership_transfer_candidates_v3(event)

'''
DISPATCH_REPLACEMENT = DISPATCH_ANCHOR + '''    if method == "GET" and path == "/v3/identity/households/profiles":
        return list_household_profiles_v3(event)

'''


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def roster_block(local: str) -> str:
    try:
        start = local.index(ROSTER_START)
        end = local.index(ROSTER_END, start)
    except ValueError as error:
        raise ValueError("local handler does not contain the canonical roster block") from error
    return local[start:end]


def patched_handler(deployed: str, local: str) -> str:
    if "def list_household_profiles_v3(" in deployed:
        raise ValueError("deployed package already contains the canonical roster path")
    if DIAGNOSTIC_ANCHOR not in deployed:
        raise ValueError("deployed handler does not match the protected-diagnostic anchor")
    if ROSTER_END not in deployed:
        raise ValueError("deployed handler does not match the membership resolver anchor")
    if DISPATCH_ANCHOR not in deployed:
        raise ValueError("deployed handler does not match the ownership-route anchor")
    patched = deployed.replace(DIAGNOSTIC_ANCHOR, DIAGNOSTIC_REPLACEMENT, 1)
    patched = patched.replace(ROSTER_END, roster_block(local) + ROSTER_END, 1)
    return patched.replace(DISPATCH_ANCHOR, DISPATCH_REPLACEMENT, 1)


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
    print(f"ROSTER_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")


if __name__ == "__main__":
    main()
