#!/usr/bin/env python3
"""Patch only Household Sync into the known-good deployed Lambda artifact.

This deliberately does not package the working tree or run a broad SAM
deployment.  It starts from a pinned, previously verified ZIP and changes only
``handler.py`` after checking every insertion anchor. If the deployed handler
already has Household Sync, only that exact bounded block is replaced. That
makes a rollback the original artifact and avoids carrying unrelated local
Cloud drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path


HOUSEHOLD_BLOCK_START = "HOUSEHOLD_PROGRESS_EVENT_TYPE ="
HOUSEHOLD_BLOCK_END = "def extract_profile_id_from_settings_path("
DEPLOYED_INSERT_ANCHOR = "def extract_profile_id_from_settings_path("
REMOTE_COMMAND_ANCHOR = '    if method == "POST" and path == "/v1/remote-commands":\n        return create_remote_command(event)\n'
ROUTE_INSERTION = (
    '\n'
    '    if method == "POST" and path == "/v1/household-progress":\n'
    '        return save_household_progress(event)\n'
    '\n'
    '    if method == "GET" and path == "/v1/household-progress":\n'
    '        return get_household_progress(event)\n'
)
CATALOG_ANCHOR = '                "/v1/events/recent",\n'
CATALOG_INSERTION = '                "/v1/household-progress",\n'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_slice(text: str, start: str, end: str) -> str:
    start_index = text.find(start)
    if start_index < 0:
        raise ValueError(f"source start anchor missing: {start}")
    if text.find(start, start_index + 1) >= 0:
        raise ValueError(f"source start anchor is ambiguous: {start}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise ValueError(f"source end anchor missing: {end}")
    return text[start_index:end_index]


def insert_once(text: str, anchor: str, insertion: str, *, before: bool = False) -> str:
    count = text.count(anchor)
    if count != 1:
        raise ValueError(f"expected one insertion anchor, found {count}: {anchor!r}")
    index = text.index(anchor)
    return text[:index] + insertion + text[index:] if before else text[:index + len(anchor)] + insertion + text[index + len(anchor):]


def patched_handler(deployed: str, source: str) -> str:
    block = unique_slice(source, HOUSEHOLD_BLOCK_START, HOUSEHOLD_BLOCK_END)
    if "_household_progress_authorized_target_ids" not in block:
        raise ValueError("Household Sync block is missing its exact-ID authorization helper")
    if "session_started_at_epoch_milliseconds" not in block:
        raise ValueError("Household Sync block is missing millisecond session ordering")
    if "Key(\"event_key\").begins_with" not in block:
        raise ValueError("Household Sync read is not constrained to Household Sync keys")

    if HOUSEHOLD_BLOCK_START in deployed:
        deployed_block = unique_slice(
            deployed, HOUSEHOLD_BLOCK_START, HOUSEHOLD_BLOCK_END,
        )
        if deployed.count(ROUTE_INSERTION) != 1:
            raise ValueError("deployed Household Sync routes are missing or ambiguous")
        if deployed.count(CATALOG_INSERTION) != 1:
            raise ValueError("deployed Household Sync route catalog is missing or ambiguous")
        patched = deployed.replace(deployed_block, block, 1)
    else:
        if "household-progress" in deployed:
            raise ValueError("trusted artifact has an unrecognized Household Sync shape")
        patched = insert_once(deployed, DEPLOYED_INSERT_ANCHOR, block, before=True)
        patched = insert_once(patched, REMOTE_COMMAND_ANCHOR, ROUTE_INSERTION)
        patched = insert_once(patched, CATALOG_ANCHOR, CATALOG_INSERTION)
    compile(patched, "handler.py", "exec")
    return patched


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-zip", type=Path, required=True)
    parser.add_argument("--source-handler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    trusted_bytes = args.trusted_zip.read_bytes()
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
