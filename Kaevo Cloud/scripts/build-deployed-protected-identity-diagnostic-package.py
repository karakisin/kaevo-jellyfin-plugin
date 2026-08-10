#!/usr/bin/env python3
"""Add bounded, credential-free identity-route status diagnostics to a live ZIP."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
import zipfile


TARGET_RETURNS = {
    "return refresh_bound_session_v2(event)": "return _diagnose_protected_identity_route(event, refresh_bound_session_v2(event))",
    "return identity_me_v3(event)": "return _diagnose_protected_identity_route(event, identity_me_v3(event))",
    "return list_profile_mappings_v3(event)": "return _diagnose_protected_identity_route(event, list_profile_mappings_v3(event))",
}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def function_span(source: str, name: str) -> tuple[int, int, str]:
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            start = offsets[node.lineno - 1]
            end = offsets[node.end_lineno]
            return start, end, source[start:end]
    raise ValueError(f"deployed handler is missing {name}")


def diagnostic_function() -> str:
    return '''def _diagnose_protected_identity_route(event, result):
    """Log only route/status/correlation for temporary recovery diagnosis."""
    request_id = str((event.get("requestContext") or {}).get("requestId") or "unknown")[:128]
    LOGGER.warning(
        "protected_identity_route_result route=%s method=%s status=%s request_id=%s",
        normalized_path(event), method_for(event), result.get("statusCode"), request_id,
    )
    return result
'''


def patched_handler(source: str) -> str:
    start, end, dispatcher = function_span(source, "lambda_handler")
    if "def _diagnose_protected_identity_route" in source:
        raise ValueError("deployed handler already contains protected identity diagnostics")
    for original, replacement in TARGET_RETURNS.items():
        if dispatcher.count(original) != 1:
            raise ValueError(f"dispatcher anchor is ambiguous: {original}")
        dispatcher = dispatcher.replace(original, replacement, 1)
    patched = source[:start] + diagnostic_function().rstrip() + "\n\n\n" + dispatcher.rstrip() + "\n" + source[end:]
    ast.parse(patched)
    if patched.count("protected_identity_route_result") != 1:
        raise ValueError("diagnostic log was not inserted exactly once")
    for replacement in TARGET_RETURNS.values():
        if patched.count(replacement) != 1:
            raise ValueError(f"dispatcher replacement missing: {replacement}")
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
        updated_handler = patched_handler(original["handler.py"].decode("utf-8")).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.output, "w") as destination:
            for info in infos:
                destination.writestr(info, updated_handler if info.filename == "handler.py" else original[info.filename])

    with zipfile.ZipFile(args.output) as result:
        changed = [name for name in names if result.read(name) != original[name]]
    if changed != ["handler.py"]:
        raise ValueError(f"package changed unexpected files: {changed}")
    print(f"DEPLOYED_HANDLER_SHA256={digest(original['handler.py'])}")
    print(f"DIAGNOSTIC_HANDLER_SHA256={digest(updated_handler)}")
    print(f"PACKAGE_SHA256={digest(args.output.read_bytes())}")
    print("PACKAGE_CHANGED_FILES=handler.py")


if __name__ == "__main__":
    main()
