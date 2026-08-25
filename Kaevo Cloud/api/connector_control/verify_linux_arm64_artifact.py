#!/usr/bin/env python3
"""Fail the connector-control build unless every native extension is Linux ARM64."""

from __future__ import annotations

import struct
import sys
from pathlib import Path


ELF_MACHINE_AARCH64 = 183


def validation_errors(root: Path) -> list[str]:
    native_extensions = sorted(
        path for path in root.rglob("*") if path.is_file() and path.suffix in {".so", ".dylib"}
    )
    if not native_extensions:
        return ["package contains no native extensions to validate"]

    errors: list[str] = []
    for path in native_extensions:
        relative = path.relative_to(root)
        header = path.read_bytes()[:20]
        if len(header) < 20 or header[:4] != b"\x7fELF":
            errors.append(f"{relative}: expected an ELF native extension")
            continue
        if header[4] != 2 or header[5] != 1:
            errors.append(f"{relative}: expected a little-endian 64-bit ELF native extension")
            continue
        machine = struct.unpack_from("<H", header, 18)[0]
        if machine != ELF_MACHINE_AARCH64:
            errors.append(f"{relative}: expected ELF AArch64 machine {ELF_MACHINE_AARCH64}, got {machine}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} ARTIFACTS_DIR", file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    errors = validation_errors(root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"validated Linux ARM64 native extensions in {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
