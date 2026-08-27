#!/usr/bin/env python3
"""Backfill exact recovery lineage for completed historical Kaevo-only deletes.

Dry-run is the default. ``--apply`` writes only minimal, non-discoverable
provider fingerprints after the terminal lifecycle receipt proves the Kaevo
graph and Cognito identity are absent while provider deletion was out of scope.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import time
from typing import Any, Mapping

import boto3
from botocore.exceptions import ClientError


def fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def lifecycle_operations(table: Any):
    scan = {}
    while True:
        page = table.scan(**scan)
        for item in page.get("Items", []):
            if item.get("record_type") == "account_lifecycle_operation":
                yield item
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return
        scan["ExclusiveStartKey"] = last_key


def recovery_items(operation: Mapping[str, Any], *, now_epoch: int):
    proof = operation.get("proof") or {}
    if not (
        operation.get("scope") == "kaevo_only"
        and operation.get("phase") == "completed"
        and proof.get("kaevo_graph_absent") is True
        and proof.get("cognito_identity_absent") is True
        and proof.get("cognito_email_absent") is True
        and proof.get("jellyfin_identity_absent") is None
        and proof.get("seerr_identity_absent") is None
    ):
        return []
    resources = operation.get("resource_snapshots") or []
    household_by_profile = {}
    for resource in resources:
        if resource.get("resource_type") != "profile_binding":
            continue
        attributes = resource.get("attributes") or {}
        profile_id = str(attributes.get("profile_id") or "")
        household_id = str(attributes.get("household_id") or "")
        if profile_id and household_id:
            household_by_profile[profile_id] = household_id
    completed_epoch = int(operation.get("completed_at_epoch") or now_epoch)
    deleted_at = dt.datetime.fromtimestamp(
        completed_epoch, tz=dt.timezone.utc,
    ).isoformat().replace("+00:00", "Z")
    items = []
    for resource in resources:
        if resource.get("resource_type") != "provider_binding":
            continue
        attributes = resource.get("attributes") or {}
        profile_id = str(attributes.get("profile_id") or "")
        household_id = household_by_profile.get(profile_id, "")
        connector_id = str(attributes.get("connector_id") or "")
        jellyfin_user_id = str(attributes.get("jellyfin_user_id") or "")
        seerr_user_id = str(attributes.get("seerr_user_id") or "")
        if not all((profile_id, household_id, connector_id, jellyfin_user_id)):
            raise RuntimeError("historical_provider_binding_invalid")
        item = {
            "profile_id": profile_id,
            "household_id": household_id,
            "state": "deleted",
            "deleted_at": deleted_at,
            "expires_at": now_epoch + (90 * 24 * 60 * 60),
            "provider_user_fingerprint": fingerprint(jellyfin_user_id),
            "connector_id": connector_id,
            "recovery_lineage": "account_lifecycle_v2_kaevo_only",
            "deleted_account_id": str(operation.get("account_id") or ""),
            "deletion_operation_id": str(operation.get("operation_id") or ""),
        }
        if seerr_user_id:
            item["seerr_user_fingerprint"] = fingerprint(seerr_user_id)
        items.append(item)
    return items


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lifecycle-table",
        default="kaevo-cloud-production-account-lifecycle-v2",
    )
    parser.add_argument(
        "--tombstone-table",
        default="kaevo-cloud-production-profile-binding-tombstones",
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    dynamodb = boto3.resource("dynamodb")
    lifecycle = dynamodb.Table(args.lifecycle_table)
    tombstones = dynamodb.Table(args.tombstone_table)
    now_epoch = int(time.time())
    candidates = []
    for operation in lifecycle_operations(lifecycle):
        candidates.extend(recovery_items(operation, now_epoch=now_epoch))

    for item in candidates:
        print(
            f"profile={item['profile_id']} household={item['household_id']} "
            f"lineage={item['recovery_lineage']} action={'apply' if args.apply else 'dry-run'}"
        )
        if not args.apply:
            continue
        try:
            tombstones.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(profile_id)",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            existing = tombstones.get_item(
                Key={"profile_id": item["profile_id"]}, ConsistentRead=True,
            ).get("Item")
            exact_fields = (
                "profile_id", "household_id", "state", "provider_user_fingerprint",
                "seerr_user_fingerprint", "connector_id", "recovery_lineage",
                "deleted_account_id", "deletion_operation_id",
            )
            if not isinstance(existing, Mapping) or any(
                str(existing.get(field) or "") != str(item.get(field) or "")
                for field in exact_fields
            ):
                raise RuntimeError("recovery_tombstone_conflict") from error
    print(f"candidates={len(candidates)} applied={len(candidates) if args.apply else 0}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
