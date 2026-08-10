#!/usr/bin/env python3
"""Build a revision-safe Lambda package for exact downloader controls.

The Cloud checkout can contain unrelated unreleased work. This tool starts
from a freshly downloaded known-live Lambda zip and changes only ``handler.py``
after proving every expected live anchor is present exactly once. It is
intentionally narrow: it refuses to patch an already-updated or drifted
handler rather than constructing a broad source archive.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import zipfile
from pathlib import Path


SAFE_APPROVAL_LINE = 'SAFE_APPROVAL_TOKEN = re.compile(r"^[A-Za-z0-9_-]{24,128}$")\n'
SAFE_DOWNLOAD_LINE = 'SAFE_DOWNLOAD_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")\n'
INVENTORY_ANCHOR = '    if operation == "sonarr.episode_inventory":\n'
PLAYBACK_PRIORITY = '    if method == "COMMAND" and path == "/commands/jellyfin.prepare_playback":\n        return 0\n'
PLAYBACK_PROGRESS = '    if method == "COMMAND" and path in {\n        "/commands/jellyfin.playback_started",\n'
AUTH_ANCHOR = '    if not SAFE_IDEMPOTENCY_KEY.fullmatch(idempotency_key):\n'
LEGACY_AUTH_GUARD = (
    '    if not require_dev_key(event):\n'
    '        if operation not in profile_authorized_operations or not require_profile_auth(event, profile_id):\n'
    '            return response(401, {"state": "unauthorized"})\n'
)


def one(source: str, needle: str, label: str) -> None:
    count = source.count(needle)
    if count != 1:
        raise ValueError(f"expected one {label} anchor, found {count}")


def between(source: str, start: str, end: str, label: str) -> str:
    start_index = source.find(start)
    end_index = source.find(end, start_index + len(start))
    if start_index < 0 or end_index < 0:
        raise ValueError(f"reviewed source does not contain {label}")
    return source[start_index:end_index]


def source_fragments(source_handler: Path) -> tuple[str, str, str]:
    source = source_handler.read_text(encoding="utf-8")
    if SAFE_DOWNLOAD_LINE not in source:
        raise ValueError("reviewed source does not contain the safe download identifier")
    command = between(source, '    if operation == "downloaders.set_queue_state":\n', INVENTORY_ANCHOR, "download command")
    priority = between(source, '    if method == "COMMAND" and path == "/commands/downloaders.set_queue_state":\n', PLAYBACK_PROGRESS, "download priority")
    owner_guard = between(source, '    owner_authorized_operations = {"downloaders.set_queue_state"}\n', AUTH_ANCHOR, "owner authorization guard")
    if "arr_queue_id" not in command or "download_id" not in command or "target_state" not in command:
        raise ValueError("reviewed download command is incomplete")
    if '"household.manage"' not in owner_guard:
        raise ValueError("reviewed owner authorization guard is incomplete")
    return command, priority, owner_guard


def patch_handler(deployed: str, source_handler: Path) -> str:
    if "downloaders.set_queue_state" in deployed or "SAFE_DOWNLOAD_IDENTIFIER" in deployed:
        raise ValueError("deployed handler already contains downloader controls; refusing to reapply")

    command, priority, owner_guard = source_fragments(source_handler)
    one(deployed, SAFE_APPROVAL_LINE, "safe approval token")
    one(deployed, INVENTORY_ANCHOR, "episode inventory")
    one(deployed, PLAYBACK_PRIORITY, "playback priority")
    one(deployed, PLAYBACK_PROGRESS, "playback progress")
    one(deployed, LEGACY_AUTH_GUARD, "legacy authorization")

    patched = deployed.replace(SAFE_APPROVAL_LINE, SAFE_APPROVAL_LINE + SAFE_DOWNLOAD_LINE, 1)
    patched = patched.replace(INVENTORY_ANCHOR, command + INVENTORY_ANCHOR, 1)
    patched = patched.replace(PLAYBACK_PRIORITY + PLAYBACK_PROGRESS, PLAYBACK_PRIORITY + priority + PLAYBACK_PROGRESS, 1)
    patched = patched.replace(LEGACY_AUTH_GUARD, owner_guard, 1)

    if patched.count("downloaders.set_queue_state") != 4:
        raise ValueError("patched handler did not contain exactly the expected download-control routes")
    if patched.count("SAFE_DOWNLOAD_IDENTIFIER") != 2:
        raise ValueError("patched handler did not contain exactly the expected identifier validation")
    compile(patched, "handler.py", "exec")
    return patched


def sha256_b64(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return base64.b64encode(digest).decode("ascii")


def build(deployed_zip: Path, source_handler: Path, output_zip: Path) -> None:
    with zipfile.ZipFile(deployed_zip, "r") as source:
        names = source.namelist()
        if names.count("handler.py") != 1:
            raise ValueError("expected exactly one handler.py in deployed package")
        original_handler = source.read("handler.py").decode("utf-8")
        patched_handler = patch_handler(original_handler, source_handler).encode("utf-8")
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip, "w") as target:
            target.comment = source.comment
            for info in source.infolist():
                payload = patched_handler if info.filename == "handler.py" else source.read(info.filename)
                target.writestr(info, payload, compress_type=info.compress_type)

    with zipfile.ZipFile(deployed_zip, "r") as original, zipfile.ZipFile(output_zip, "r") as output:
        if original.namelist() != output.namelist():
            raise ValueError("output package entries changed")
        changed = [name for name in original.namelist() if original.read(name) != output.read(name)]
        if changed != ["handler.py"]:
            raise ValueError(f"unexpected changed archive entries: {changed}")

    print(f"package={output_zip}")
    print(f"sha256_b64={sha256_b64(output_zip)}")
    print("changed=handler.py only (verified)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed-zip", required=True, type=Path)
    parser.add_argument("--source-handler", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.deployed_zip, args.source_handler, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
