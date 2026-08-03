#!/usr/bin/env python3
"""Prepare a surgical household-connector Lambda candidate.

The output starts from the exact deployed Lambda package.  Only the connector
authorization helpers and the three connector lookup call sites are replaced
from the reviewed local handler.  This prevents unrelated worktree changes
from entering the deployment package.
"""

from __future__ import annotations

import argparse
import py_compile
import shutil
from pathlib import Path


def function_slice(source: str, name: str, next_name: str) -> tuple[int, int, str]:
    start_marker = f"def {name}("
    end_marker = f"\ndef {next_name}("
    start = source.index(start_marker)
    end = source.index(end_marker, start) + 1
    return start, end, source[start:end]


def replace_once(source: str, old: str, new: str, *, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact match, found {count}")
    return source.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployed-dir", required=True, type=Path)
    parser.add_argument("--reviewed-handler", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    deployed_handler_path = args.deployed_dir / "handler.py"
    if not deployed_handler_path.is_file():
        raise RuntimeError(f"deployed handler not found: {deployed_handler_path}")
    if not args.reviewed_handler.is_file():
        raise RuntimeError(f"reviewed handler not found: {args.reviewed_handler}")
    if args.output_dir.exists():
        raise RuntimeError(f"output directory already exists: {args.output_dir}")

    shutil.copytree(args.deployed_dir, args.output_dir)
    output_handler_path = args.output_dir / "handler.py"
    deployed = output_handler_path.read_text()
    reviewed = args.reviewed_handler.read_text()

    deployed = replace_once(
        deployed,
        "    AccountFoundationError,\n    assert_auth_identity_binding,",
        "    AccountFoundationError,\n    CanonicalRole,\n    assert_auth_identity_binding,",
        label="CanonicalRole import",
    )

    reviewed_connector_start = reviewed.index(
        'HOME_CONNECTORS_PROFILE_INDEX = "profile_id-updated_at-index"'
    )
    reviewed_connector_end = reviewed.index(
        "\ndef create_pairing_record(", reviewed_connector_start
    ) + 1
    reviewed_connector_block = reviewed[
        reviewed_connector_start:reviewed_connector_end
    ]

    deployed_connector_start = deployed.index("def public_connector_item(")
    deployed_connector_end = deployed.index(
        "\ndef create_pairing_record(", deployed_connector_start
    ) + 1
    deployed = (
        deployed[:deployed_connector_start]
        + reviewed_connector_block
        + deployed[deployed_connector_end:]
    )

    reviewed_status_start, reviewed_status_end, reviewed_status = function_slice(
        reviewed, "get_home_connector_status", "get_remote_routes"
    )
    del reviewed_status_start, reviewed_status_end
    deployed_status_start, deployed_status_end, deployed_status = function_slice(
        deployed, "get_home_connector_status", "get_remote_routes"
    )
    deployed_status = replace_once(
        deployed_status,
        """    result = home_connectors_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    connectors = [public_connector_item(item) for item in result.get("Items", [])]
""",
        """    connectors = [
        public_connector_item(item, requesting_profile_id=profile_id)
        for item in _home_connectors_for_profile_access(profile_id)
    ]
""",
        label="connector status lookup",
    )
    expected_status_fragment = """    connectors = [
        public_connector_item(item, requesting_profile_id=profile_id)
        for item in _home_connectors_for_profile_access(profile_id)
    ]
"""
    if expected_status_fragment not in reviewed_status:
        raise RuntimeError("reviewed status function does not contain expected lookup")
    deployed = (
        deployed[:deployed_status_start]
        + deployed_status
        + deployed[deployed_status_end:]
    )

    reviewed_routes_start, reviewed_routes_end, reviewed_routes = function_slice(
        reviewed, "get_remote_routes", "decode_remote_response_payload"
    )
    del reviewed_routes_start, reviewed_routes_end
    deployed_routes_start, deployed_routes_end, deployed_routes = function_slice(
        deployed, "get_remote_routes", "decode_remote_response_payload"
    )
    deployed_routes = replace_once(
        deployed_routes,
        """    result = home_connectors_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    connectors = [public_connector_item(item) for item in result.get("Items", [])]
""",
        """    connectors = [
        public_connector_item(item, requesting_profile_id=profile_id)
        for item in _home_connectors_for_profile_access(profile_id)
    ]
""",
        label="remote routes lookup",
    )
    if expected_status_fragment not in reviewed_routes:
        raise RuntimeError("reviewed routes function does not contain expected lookup")
    deployed = (
        deployed[:deployed_routes_start]
        + deployed_routes
        + deployed[deployed_routes_end:]
    )

    reviewed_latest_start, reviewed_latest_end, reviewed_latest = function_slice(
        reviewed, "latest_online_connector_for_profile", "create_remote_request"
    )
    del reviewed_latest_start, reviewed_latest_end
    deployed_latest_start, deployed_latest_end, deployed_latest = function_slice(
        deployed, "latest_online_connector_for_profile", "create_remote_request"
    )
    deployed_latest = replace_once(
        deployed_latest,
        """    result = home_connectors_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    for item in result.get("Items", []):
""",
        """    for item in _home_connectors_for_profile_access(profile_id):
""",
        label="latest online connector lookup",
    )
    if (
        "for item in _home_connectors_for_profile_access(profile_id):"
        not in reviewed_latest
    ):
        raise RuntimeError("reviewed latest connector function is unexpected")
    deployed = (
        deployed[:deployed_latest_start]
        + deployed_latest
        + deployed[deployed_latest_end:]
    )

    output_handler_path.write_text(deployed)
    py_compile.compile(str(output_handler_path), doraise=True)
    print(output_handler_path)


if __name__ == "__main__":
    main()
