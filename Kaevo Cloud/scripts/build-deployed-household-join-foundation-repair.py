#!/usr/bin/env python3
"""Replace only account_foundation.py in a deployed Household Join ZIP."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--local-account-foundation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    replacement_name = "account_foundation.py"
    replacement = args.local_account_foundation.read_bytes()
    with zipfile.ZipFile(args.deployed_zip) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if names.count(replacement_name) != 1:
            raise ValueError(f"deployed ZIP must contain exactly one {replacement_name}")
        original = {info.filename: source.read(info.filename) for info in infos}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                payload = replacement if info.filename == replacement_name else original[info.filename]
                destination.writestr(info, payload)

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != [replacement_name]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"PACKAGE_SHA256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")
    print(f"PACKAGE_CHANGED_FILES={replacement_name}")


if __name__ == "__main__":
    main()
