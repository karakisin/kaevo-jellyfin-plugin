#!/usr/bin/env python3
"""Publish a server-authored Kaevo problem-report resolution.

This deliberately writes through an operator's AWS identity instead of a
client-facing endpoint. A signed-in app can submit and read its own report
lifecycle, but it cannot mark its own report Resolved.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from datetime import datetime, timezone

import boto3


REFERENCE_PATTERN = re.compile(r"^KV-[A-F0-9]{8}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--table-name", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--resolution", required=True)
    parser.add_argument("--probable-cause", required=True)
    parser.add_argument("--user-action", required=True)
    parser.add_argument("--fixed-in-version", required=True)
    parser.add_argument("--region", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    reference = args.reference.strip().upper()
    if not REFERENCE_PATTERN.fullmatch(reference):
        raise SystemExit("reference must match KV- followed by 8 hexadecimal characters")
    if not args.profile_id.strip():
        raise SystemExit("profile-id is required")
    if (
        not args.resolution.strip()
        or not args.probable_cause.strip()
        or not args.user_action.strip()
        or not args.fixed_in_version.strip()
    ):
        raise SystemExit(
            "resolution, probable-cause, user-action, and fixed-in-version are required"
        )

    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    item = {
        "profile_id": args.profile_id.strip(),
        "event_key": f"{timestamp}#{event_id}",
        "event_id": event_id,
        "event_type": "bug_report_resolved",
        "timestamp": timestamp,
        "received_at": timestamp,
        "item_id": reference,
        "device_type": "support-workflow",
        "source": "kaevo-support",
        "session_id": "",
        "metadata_json": json.dumps({
            "status": "resolved",
            "resolution": args.resolution.strip(),
            "probable_cause": args.probable_cause.strip(),
            "user_action": args.user_action.strip(),
            "fixed_in_version": args.fixed_in_version.strip(),
        }, separators=(",", ":")),
        "expires_at": int(time.time()) + (2 * 365 * 24 * 60 * 60),
    }
    boto3.resource("dynamodb", region_name=args.region).Table(args.table_name).put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(profile_id) AND attribute_not_exists(event_key)",
    )
    print(json.dumps({"state": "resolved", "reference": reference, "event_id": event_id}))


if __name__ == "__main__":
    main()
