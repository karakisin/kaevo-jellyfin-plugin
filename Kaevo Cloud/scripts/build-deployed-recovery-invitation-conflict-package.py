#!/usr/bin/env python3
"""Patch only the historical-invitation recovery predicate in the deployed API ZIP."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


OLD_PREDICATE = '''                    and candidate.get("state") in {"pending", "consumed"}
                    for candidate in _household_invitation_records(household_id)
'''
NEW_PREDICATE = '''                    and candidate.get("state") in {"pending", "consumed"}
                    and candidate.get("deleted_profile_recovery") is True
                    for candidate in _household_invitation_records(household_id)
'''


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patched_handler(deployed: str) -> str:
    if NEW_PREDICATE in deployed:
        raise ValueError("deployed handler already contains the corrected recovery predicate")
    if deployed.count(OLD_PREDICATE) != 1:
        raise ValueError("deployed handler does not contain exactly one recovery predicate anchor")
    patched = deployed.replace(OLD_PREDICATE, NEW_PREDICATE, 1)
    ast.parse(patched)
    if patched.count(".scan(") != deployed.count(".scan("):
        raise ValueError("recovery predicate package introduced DynamoDB Scan")
    return patched


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if names.count("handler.py") != 1:
            raise ValueError("deployed ZIP must contain exactly one handler.py")
        original = {info.filename: source.read(info.filename) for info in infos}
        before = original["handler.py"]
        after = patched_handler(before.decode("utf-8")).encode("utf-8")
        if args.output.exists():
            raise ValueError("output already exists; refusing to overwrite")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(
                    info,
                    after if info.filename == "handler.py" else original[info.filename],
                )

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(before)}")
    print(f"CORRECTED_HANDLER_SHA256={digest(after)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")
    print("DYNAMODB_SCAN_DELTA=0")


if __name__ == "__main__":
    main()
