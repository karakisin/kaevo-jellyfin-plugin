#!/usr/bin/env python3
"""Resolve the exact Sentry feedback issue for a user-verified Kaevo report."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
from boto3.dynamodb.conditions import Key


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "src"))
from sentry_issue_resolution import parse_credentials, resolve_feedback_issue  # noqa: E402


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
    parser.add_argument("--sentry-issue-id", required=True)
    parser.add_argument("--sentry-linked-issue-id", required=True)
    parser.add_argument("--secret-arn", required=True)
    parser.add_argument("--region", default=None)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def report_records(table, profile_id: str, reference: str) -> list[dict]:
    matches = []
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
            if item.get("item_id") == reference
            and item.get("event_type") in LIFECYCLE_EVENT_TYPES
        )
        exclusive_start_key = result.get("LastEvaluatedKey")
        if not exclusive_start_key:
            return matches


def immutable_sentry_event_id(records: list[dict], reference: str) -> str:
    for item in records:
        if item.get("event_type") != "bug_report_submitted":
            continue
        try:
            metadata = json.loads(item.get("metadata_json") or "{}")
        except json.JSONDecodeError:
            continue
        event_id = str(metadata.get("sentry_event_id") or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{32}", event_id) and reference == f"KV-{event_id[:8].upper()}":
            return event_id
    return ""


def main() -> None:
    args = parse_args()
    reference = args.reference.strip().upper()
    profile_id = args.profile_id.strip()
    sentry_issue_id = args.sentry_issue_id.strip()
    sentry_linked_issue_id = args.sentry_linked_issue_id.strip()
    if not REFERENCE_PATTERN.fullmatch(reference):
        raise SystemExit("reference must match KV- followed by 8 hexadecimal characters")
    if not profile_id:
        raise SystemExit("profile-id is required")
    if not SENTRY_ISSUE_ID_PATTERN.fullmatch(sentry_issue_id):
        raise SystemExit("sentry-issue-id must contain only digits")
    if (
        not SENTRY_ISSUE_ID_PATTERN.fullmatch(sentry_linked_issue_id)
        or sentry_linked_issue_id == sentry_issue_id
    ):
        raise SystemExit("sentry-linked-issue-id must be a different numeric issue ID")

    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table_name)
    records = report_records(table, profile_id, reference)
    if not records or records[0].get("event_type") != "bug_report_verified_resolved":
        raise SystemExit("the exact Kaevo report is not user-verified resolved")
    sentry_event_id = immutable_sentry_event_id(records, reference)
    if not sentry_event_id:
        raise SystemExit("the exact Kaevo report has no immutable Sentry event binding")

    if not args.apply:
        print(json.dumps({
            "state": "dry_run",
            "reference": reference,
            "sentry_issue_id": sentry_issue_id,
            "sentry_linked_issue_id": sentry_linked_issue_id,
        }))
        return

    secrets = boto3.client("secretsmanager", region_name=args.region)
    secret_string = secrets.get_secret_value(SecretId=args.secret_arn)["SecretString"]
    credentials = parse_credentials(secret_string)
    sentry_result = resolve_feedback_issue(
        auth_token=credentials["auth_token"],
        organization_slug=credentials["organization_slug"],
        project_slug=credentials["project_slug"],
        issue_id=sentry_issue_id,
        linked_issue_id=sentry_linked_issue_id,
        associated_event_id=sentry_event_id,
    )

    latest_metadata = json.loads(records[0].get("metadata_json") or "{}")
    latest_metadata["sentry_issue_id"] = sentry_result["issue_id"]
    latest_metadata["sentry_issue_status"] = sentry_result["status"]
    latest_metadata["sentry_linked_issue_id"] = sentry_result["linked_issue_id"]
    latest_metadata["sentry_linked_issue_status"] = sentry_result["linked_issue_status"]
    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    table.put_item(
        Item={
            "profile_id": profile_id,
            "event_key": f"{timestamp}#{event_id}",
            "event_id": event_id,
            "event_type": "bug_report_verified_resolved",
            "timestamp": timestamp,
            "received_at": timestamp,
            "item_id": reference,
            "device_type": "support-workflow",
            "source": "kaevo-support",
            "session_id": "",
            "metadata_json": json.dumps(latest_metadata, separators=(",", ":")),
            "expires_at": int(time.time()) + (2 * 365 * 24 * 60 * 60),
        },
        ConditionExpression="attribute_not_exists(profile_id) AND attribute_not_exists(event_key)",
    )
    print(json.dumps({
        "state": "reconciled",
        "reference": reference,
        "sentry_issue_id": sentry_issue_id,
        "event_id": event_id,
    }))


if __name__ == "__main__":
    main()
