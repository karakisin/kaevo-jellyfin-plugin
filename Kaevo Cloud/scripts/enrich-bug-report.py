#!/usr/bin/env python3
"""Backfill immutable user-authored details for an existing Kaevo report.

This operator-only workflow can add display metadata that an older client did
not send to Kaevo Cloud. It never changes the report's Pending/Resolved state
and refuses to create a report reference that does not already exist for the
exact profile.
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
EVENT_ID_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--table-name", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--sentry-event-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--category", choices=("ui", "ux"), required=True)
    parser.add_argument("--details", required=True)
    parser.add_argument("--screenshot-count", type=int, default=0)
    parser.add_argument("--region", default=None)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def validate_identity(reference: str, sentry_event_id: str) -> tuple[str, str]:
    normalized_reference = reference.strip().upper()
    normalized_event_id = sentry_event_id.strip().lower()
    if not REFERENCE_PATTERN.fullmatch(normalized_reference):
        raise ValueError("reference must match KV- followed by 8 hexadecimal characters")
    if not EVENT_ID_PATTERN.fullmatch(normalized_event_id):
        raise ValueError("sentry-event-id must contain exactly 32 hexadecimal characters")
    expected_reference = f"KV-{normalized_event_id[:8].upper()}"
    if normalized_reference != expected_reference:
        raise ValueError("reference does not match the immutable Sentry event ID")
    return normalized_reference, normalized_event_id


def existing_submissions(table, profile_id: str, reference: str) -> list[dict]:
    matches: list[dict] = []
    exclusive_start_key = None
    while True:
        request = {
            "KeyConditionExpression": Key("profile_id").eq(profile_id),
            "ScanIndexForward": False,
        }
        if exclusive_start_key:
            request["ExclusiveStartKey"] = exclusive_start_key
        result = table.query(**request)
        matches.extend(
            item for item in result.get("Items", [])
            if item.get("event_type") == "bug_report_submitted"
            and item.get("item_id") == reference
        )
        exclusive_start_key = result.get("LastEvaluatedKey")
        if not exclusive_start_key:
            return matches


def main() -> None:
    args = parse_args()
    try:
        reference, sentry_event_id = validate_identity(args.reference, args.sentry_event_id)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    profile_id = args.profile_id.strip()
    title = args.title.strip()
    details = args.details.strip()
    if not profile_id or not title or not details:
        raise SystemExit("profile-id, title, and details are required")
    if len(title) > 120 or len(details) > 4_000:
        raise SystemExit("title must be at most 120 characters and details at most 4000")
    if args.screenshot_count < 0 or args.screenshot_count > 5:
        raise SystemExit("screenshot-count must be between 0 and 5")

    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table_name)
    submissions = existing_submissions(table, profile_id, reference)
    if not submissions:
        raise SystemExit("exact report reference does not exist for this profile")

    for submission in submissions:
        try:
            metadata = json.loads(submission.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            metadata = {}
        if metadata.get("details") == details:
            print(json.dumps({"state": "already_enriched", "reference": reference}))
            return

    if not args.apply:
        print(json.dumps({
            "state": "dry_run",
            "reference": reference,
            "matching_submissions": len(submissions),
        }))
        return

    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    item = {
        "profile_id": profile_id,
        "event_key": f"{timestamp}#{event_id}",
        "event_id": event_id,
        "event_type": "bug_report_submitted",
        "timestamp": timestamp,
        "received_at": timestamp,
        "item_id": reference,
        "device_type": "support-workflow",
        "source": "kaevo-support",
        "session_id": "",
        "metadata_json": json.dumps({
            "title": title,
            "category": args.category,
            "status": "pending",
            "details": details,
            "sentry_event_id": sentry_event_id,
            "screenshot_count": str(args.screenshot_count),
        }, separators=(",", ":")),
        "expires_at": int(time.time()) + (2 * 365 * 24 * 60 * 60),
    }
    table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(profile_id) AND attribute_not_exists(event_key)",
    )
    print(json.dumps({"state": "enriched", "reference": reference, "event_id": event_id}))


if __name__ == "__main__":
    main()
