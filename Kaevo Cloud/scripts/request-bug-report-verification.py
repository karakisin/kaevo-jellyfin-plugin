#!/usr/bin/env python3
"""Move one exact Kaevo report into reporter verification.

The operator supplies the explanation and required user action. The report is
not marked Resolved here: only the authenticated reporting profile can confirm
the fix through the app's verification endpoint.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key


REFERENCE_PATTERN = re.compile(r"^KV-[A-F0-9]{8}$")
SENTRY_ISSUE_ID_PATTERN = re.compile(r"^[0-9]+$")
LIFECYCLE_EVENT_TYPES = {
    "bug_report_submitted",
    "bug_report_verification_requested",
    "bug_report_verified_resolved",
    "bug_report_reopened",
    "bug_report_resolved",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--table-name", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--resolution", required=True)
    parser.add_argument("--probable-cause", required=True)
    parser.add_argument("--user-action", required=True)
    parser.add_argument("--fixed-in-version", required=True)
    parser.add_argument("--sentry-issue-id", required=True)
    parser.add_argument("--sentry-linked-issue-id", required=True)
    parser.add_argument("--region", default=None)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def latest_lifecycle_event(table, profile_id: str, reference: str) -> dict | None:
    exclusive_start_key = None
    while True:
        request = {
            "KeyConditionExpression": Key("profile_id").eq(profile_id),
            "ScanIndexForward": False,
        }
        if exclusive_start_key:
            request["ExclusiveStartKey"] = exclusive_start_key
        result = table.query(**request)
        for item in result.get("Items", []):
            if (
                item.get("item_id") == reference
                and item.get("event_type") in LIFECYCLE_EVENT_TYPES
            ):
                return item
        exclusive_start_key = result.get("LastEvaluatedKey")
        if not exclusive_start_key:
            return None


def main() -> None:
    args = parse_args()
    reference = args.reference.strip().upper()
    profile_id = args.profile_id.strip()
    if not REFERENCE_PATTERN.fullmatch(reference):
        raise SystemExit("reference must match KV- followed by 8 hexadecimal characters")
    if not profile_id:
        raise SystemExit("profile-id is required")
    sentry_issue_id = args.sentry_issue_id.strip()
    if not SENTRY_ISSUE_ID_PATTERN.fullmatch(sentry_issue_id):
        raise SystemExit("sentry-issue-id must contain only digits")
    sentry_linked_issue_id = args.sentry_linked_issue_id.strip()
    if (
        not SENTRY_ISSUE_ID_PATTERN.fullmatch(sentry_linked_issue_id)
        or sentry_linked_issue_id == sentry_issue_id
    ):
        raise SystemExit("sentry-linked-issue-id must be a different numeric issue ID")
    metadata = {
        "status": "waiting_verification",
        "resolution": args.resolution.strip(),
        "probable_cause": args.probable_cause.strip(),
        "user_action": args.user_action.strip(),
        "fixed_in_version": args.fixed_in_version.strip(),
        "sentry_issue_id": sentry_issue_id,
        "sentry_linked_issue_id": sentry_linked_issue_id,
    }
    if any(not value for value in metadata.values()):
        raise SystemExit(
            "resolution, probable-cause, user-action, and fixed-in-version are required"
        )

    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table_name)
    latest = latest_lifecycle_event(table, profile_id, reference)
    if latest is None:
        raise SystemExit("exact report reference does not exist for this profile")
    latest_type = latest.get("event_type")
    binding_upgrade = False
    if latest_type == "bug_report_verification_requested":
        try:
            latest_metadata = json.loads(latest.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            latest_metadata = {}
        if (
            str(latest_metadata.get("sentry_issue_id") or "") == sentry_issue_id
            and str(latest_metadata.get("sentry_linked_issue_id") or "")
            == sentry_linked_issue_id
        ):
            print(json.dumps({"state": "already_waiting", "reference": reference}))
            return
        if (
            latest_metadata.get("sentry_issue_id")
            and str(latest_metadata.get("sentry_issue_id")) != sentry_issue_id
        ):
            raise SystemExit("waiting report is already bound to a different Sentry issue")
        # Append one upgraded verification request so an older waiting record
        # gains the exact Sentry feedback issue binding without changing state.
        binding_upgrade = True
    if latest_type in {"bug_report_verified_resolved", "bug_report_resolved"}:
        raise SystemExit("report is already resolved")
    if (
        latest_type not in {"bug_report_submitted", "bug_report_reopened"}
        and not binding_upgrade
    ):
        raise SystemExit("report is not eligible for verification")

    if not args.apply:
        print(json.dumps({
            "state": "dry_run",
            "reference": reference,
            "current_state": latest_type,
        }))
        return

    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    table.put_item(
        Item={
            "profile_id": profile_id,
            "event_key": f"{timestamp}#{event_id}",
            "event_id": event_id,
            "event_type": "bug_report_verification_requested",
            "timestamp": timestamp,
            "received_at": timestamp,
            "item_id": reference,
            "device_type": "support-workflow",
            "source": "kaevo-support",
            "session_id": "",
            "metadata_json": json.dumps(metadata, separators=(",", ":")),
            "expires_at": int(time.time()) + (2 * 365 * 24 * 60 * 60),
        },
        ConditionExpression="attribute_not_exists(profile_id) AND attribute_not_exists(event_key)",
    )
    print(json.dumps({
        "state": "waiting_verification",
        "reference": reference,
        "event_id": event_id,
    }))


if __name__ == "__main__":
    main()
