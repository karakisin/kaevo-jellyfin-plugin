#!/usr/bin/env python3
"""Build a minimal Lambda package for protected Seerr request-list scope.

The local Cloud checkout can legitimately contain unreleased work.  This tool
starts from a downloaded, known-live Lambda zip and changes only ``handler.py``
after proving the two expected anchors exist.  It is intentionally not a
general source packager.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path


CREATE_REMOTE_REQUEST = "def create_remote_request(event):"
SCOPE_FUNCTION = "def _authorized_seerr_request_query(profile_id, query):"
SCOPE_INSERTION = """    if provider == \"seerr\" and path == \"/api/v1/request\":
        query, reason = _authorized_seerr_request_query(profile_id, query)
        if query is None:
            return response(409, {\"state\": reason})

"""
SAFE_PATH_BLOCK = """    allowed, reason = is_safe_remote_path(provider, path, query)
    if not allowed:
        return response(400, {\"state\": \"bad_request\", \"message\": reason})

    connector = latest_online_connector_for_profile(profile_id)
"""


def source_scope_function(source_handler: Path) -> str:
    source = source_handler.read_text(encoding="utf-8")
    start = source.find(SCOPE_FUNCTION)
    end = source.find(CREATE_REMOTE_REQUEST, start)
    if start < 0 or end < 0:
        raise ValueError("source handler does not contain the reviewed Seerr scope function")
    function = source[start:end].rstrip() + "\n\n\n"
    if "HouseholdAccessRole.OWNER.value" not in function or "requestedBy" not in function:
        raise ValueError("reviewed scope function is incomplete")
    return function


def patch_handler(deployed_handler: str, scope_function: str) -> str:
    if SCOPE_FUNCTION in deployed_handler:
        raise ValueError("deployed handler already contains the scope function; refusing to reapply")
    create_count = deployed_handler.count(CREATE_REMOTE_REQUEST)
    if create_count != 1:
        raise ValueError(f"expected one create_remote_request anchor, found {create_count}")
    safe_count = deployed_handler.count(SAFE_PATH_BLOCK)
    if safe_count != 1:
        raise ValueError(f"expected one safe metadata anchor, found {safe_count}")

    patched = deployed_handler.replace(CREATE_REMOTE_REQUEST, scope_function + CREATE_REMOTE_REQUEST, 1)
    patched = patched.replace(
        SAFE_PATH_BLOCK,
        SAFE_PATH_BLOCK.replace("    connector = latest_online_connector_for_profile(profile_id)\n", SCOPE_INSERTION + "    connector = latest_online_connector_for_profile(profile_id)\n"),
        1,
    )
    if patched.count(SCOPE_FUNCTION) != 1 or patched.count("_authorized_seerr_request_query(profile_id, query)") != 2:
        raise ValueError("patched handler did not contain exactly the expected protected scope call")
    compile(patched, "handler.py", "exec")
    return patched


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(deployed_zip: Path, source_handler: Path, output_zip: Path) -> None:
    scope_function = source_scope_function(source_handler)
    with zipfile.ZipFile(deployed_zip, "r") as source:
        names = source.namelist()
        if names.count("handler.py") != 1:
            raise ValueError("expected exactly one handler.py in deployed package")
        original_handler = source.read("handler.py").decode("utf-8")
        patched_handler = patch_handler(original_handler, scope_function).encode("utf-8")
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip, "w") as target:
            target.comment = source.comment
            for info in source.infolist():
                payload = patched_handler if info.filename == "handler.py" else source.read(info.filename)
                target.writestr(info, payload, compress_type=info.compress_type)

    with zipfile.ZipFile(output_zip, "r") as output:
        if output.namelist() != names:
            raise ValueError("output package entries changed")
        if output.read("handler.py") != patched_handler:
            raise ValueError("output handler verification failed")

    print(f"package={output_zip}")
    print(f"sha256={sha256(output_zip)}")
    print("changed=handler.py only (verified by construction)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployed-zip", type=Path, required=True)
    parser.add_argument("--source-handler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.deployed_zip, args.source_handler, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
