from __future__ import annotations

import importlib.util
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "api" / "connector_control" / "verify_linux_arm64_artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_linux_arm64_artifact", VERIFIER_PATH)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def elf_header(machine: int) -> bytes:
    header = bytearray(20)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def test_packaging_rule_cross_installs_linux_arm64_wheels_and_validates_them():
    makefile = (ROOT / "api" / "Makefile").read_text()
    assert "--platform manylinux_2_34_aarch64" in makefile
    assert "--platform manylinux2014_aarch64" in makefile
    assert "--python-version 3.12" in makefile
    assert "--only-binary=:all:" in makefile
    assert "verify_linux_arm64_artifact.py" in makefile


def test_verifier_accepts_only_little_endian_64_bit_aarch64_elf(tmp_path):
    valid = tmp_path / "valid.so"
    valid.write_bytes(elf_header(VERIFIER.ELF_MACHINE_AARCH64))
    assert VERIFIER.validation_errors(tmp_path) == []

    valid.unlink()
    (tmp_path / "macos.dylib").write_bytes(b"\xca\xfe\xba\xbe" + bytes(16))
    assert "expected an ELF native extension" in VERIFIER.validation_errors(tmp_path)[0]


def test_verifier_rejects_wrong_architecture_and_missing_native_extensions(tmp_path):
    assert VERIFIER.validation_errors(tmp_path) == ["package contains no native extensions to validate"]
    (tmp_path / "x86_64.so").write_bytes(elf_header(62))
    assert "expected ELF AArch64 machine 183, got 62" in VERIFIER.validation_errors(tmp_path)[0]
