#!/usr/bin/env python3
"""Replace only reviewed Household Join sources in a deployed ZIP."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--local-handler", required=True, type=Path)
    parser.add_argument("--local-profile-binding", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    replacements = {
        "household_join_handler.py": args.local_handler.read_bytes(),
        "profile_binding.py": args.local_profile_binding.read_bytes(),
    }
    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        for name in replacements:
            if names.count(name) != 1:
                raise ValueError(f"deployed ZIP must contain exactly one {name}")
        original = {info.filename: source.read(info.filename) for info in infos}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                payload = replacements.get(info.filename, original[info.filename])
                destination.writestr(info, payload)

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != ["profile_binding.py", "household_join_handler.py"] and changed != [
        "household_join_handler.py",
        "profile_binding.py",
    ]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"PACKAGE_SHA256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")
    print("PACKAGE_CHANGED_FILES=household_join_handler.py,profile_binding.py")


if __name__ == "__main__":
    main()
