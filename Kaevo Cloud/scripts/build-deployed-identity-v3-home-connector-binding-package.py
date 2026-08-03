#!/usr/bin/env python3
"""Patch only the binding handler code into the deployed Identity V3 ZIP."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


START = "\nHOME_CONNECTOR_BINDING_SCHEMA_VERSION = 1\n"
END = "\ndef migrate_existing_account_v3(event, *, verified_session=None, audit_attempt=True, retry_on_conflict=True):\n"
ROUTE_ANCHOR = '''    if method == "POST" and path == "/v3/identity/migrate-household-membership":
        return migrate_household_membership_v3(event)
'''
ROUTES = '''
    if method == "GET" and path == "/v3/identity/home-connector-binding":
        return get_home_connector_binding_v3(event)

    if method == "POST" and path == "/v3/identity/bind-home-connector":
        return bind_home_connector_v3(event)
'''


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def binding_block(source: str) -> str:
    try:
        start = source.index(START)
        end = source.index(END, start)
    except ValueError as error:
        raise ValueError("local handler does not contain the isolated connector binding block") from error
    return source[start:end]


def patched_handler(deployed: str, local: str) -> str:
    if "def bind_home_connector_v3(" in deployed or "/v3/identity/bind-home-connector" in deployed:
        raise ValueError("deployed package already contains the Connector <-> Identity binding path")
    if END not in deployed:
        raise ValueError("deployed handler does not match the expected Identity V3 migration anchor")
    if ROUTE_ANCHOR not in deployed:
        raise ValueError("deployed handler does not match the expected Identity V3 route anchor")
    with_binding = deployed.replace(END, binding_block(local) + END, 1)
    return with_binding.replace(ROUTE_ANCHOR, ROUTE_ANCHOR + ROUTES, 1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--local-handler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    local = args.local_handler.read_text()
    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if names.count("handler.py") != 1:
            raise ValueError("deployed ZIP must contain exactly one handler.py")
        original_files = {info.filename: source.read(info.filename) for info in infos}
        original = original_files["handler.py"]
        updated = patched_handler(original.decode("utf-8"), local).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(info, updated if info.filename == "handler.py" else original_files[info.filename])

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original_files[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={sha256(original)}")
    print(f"BINDING_HANDLER_SHA256={sha256(updated)}")
    print(f"PACKAGE_SHA256={sha256(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")


if __name__ == "__main__":
    main()
