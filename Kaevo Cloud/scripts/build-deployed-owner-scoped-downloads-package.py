#!/usr/bin/env python3
"""Build an owner-scoped download-capabilities Lambda package from live code."""

from __future__ import annotations

import hashlib
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIVE_PACKAGE = Path(
    "/Volumes/EDITING NVME 4TB/Kaevo-Requests-120/cloud-readback/"
    "deployed-api-after-profile-scoped-seerr-requests.zip"
)
OUTPUT_PACKAGE = Path(
    "/Volumes/EDITING NVME 4TB/Kaevo-Requests-120/"
    "kaevo-cloud-dev-api-owner-scoped-downloads.zip"
)
SOURCE_MODULE = ROOT / "api/src/account_foundation.py"
ENTRY_NAME = "account_foundation.py"


def main() -> int:
    if not LIVE_PACKAGE.is_file():
        raise SystemExit(f"missing_live_package={LIVE_PACKAGE}")
    source = SOURCE_MODULE.read_bytes()
    compile(source, str(SOURCE_MODULE), "exec")
    text = source.decode("utf-8")
    admin_marker = "HouseholdAccessRole.ADMIN: frozenset({"
    owner_only_marker = "Capability.REQUESTS_VIEW_HOUSEHOLD,"
    if admin_marker not in text or owner_only_marker not in text:
        raise SystemExit("unexpected_account_foundation_source")
    admin_block = text.split(admin_marker, 1)[1].split("}),", 1)[0]
    if "Capability.REQUESTS_VIEW_HOUSEHOLD" in admin_block or "Capability.DOWNLOADS_VIEW_HOUSEHOLD" in admin_block:
        raise SystemExit("admin_download_scope_not_removed")

    with tempfile.TemporaryDirectory(prefix="kaevo-owner-downloads-") as temporary:
        temporary_path = Path(temporary)
        extracted = temporary_path / "extracted"
        extracted.mkdir()
        with zipfile.ZipFile(LIVE_PACKAGE) as archive:
            archive.extractall(extracted)
        target = extracted / ENTRY_NAME
        if not target.is_file():
            raise SystemExit("live_entry_missing=account_foundation.py")
        target.write_bytes(source)

        OUTPUT_PACKAGE.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(LIVE_PACKAGE) as before, zipfile.ZipFile(
            OUTPUT_PACKAGE, "w", compression=zipfile.ZIP_DEFLATED
        ) as after:
            for info in before.infolist():
                payload = source if info.filename == ENTRY_NAME else before.read(info.filename)
                after.writestr(info, payload)

        with zipfile.ZipFile(LIVE_PACKAGE) as before, zipfile.ZipFile(OUTPUT_PACKAGE) as after:
            changed = [
                info.filename
                for info in before.infolist()
                if before.read(info.filename) != after.read(info.filename)
            ]
    if changed != [ENTRY_NAME]:
        raise SystemExit(f"unexpected_changed_entries={changed}")

    digest = hashlib.sha256(OUTPUT_PACKAGE.read_bytes()).digest()
    print(f"package={OUTPUT_PACKAGE}")
    print(f"sha256_base64={__import__('base64').b64encode(digest).decode()}")
    print("changed=account_foundation.py only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
