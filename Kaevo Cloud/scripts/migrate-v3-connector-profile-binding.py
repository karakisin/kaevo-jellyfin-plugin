#!/usr/bin/env python3
"""Dry-run-first, single-record Pairing V3 profile-binding migration.

No live identifier is embedded in this tool.  A write requires every expected
binding, ``--apply``, and a second exact connector-id confirmation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


PROTOCOL = "kaevo-pairing-v3"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--profile", required=True)
    result.add_argument("--region", required=True)
    result.add_argument("--connectors-table", required=True)
    result.add_argument("--profiles-table", required=True)
    result.add_argument("--connector-id", required=True)
    result.add_argument("--profile-id", required=True)
    result.add_argument("--plugin-instance-id", required=True)
    result.add_argument("--server-id", required=True)
    result.add_argument("--fingerprint", required=True)
    result.add_argument("--plugin-key-id", default="1")
    result.add_argument("--account-binding", required=True)
    result.add_argument("--family-binding", required=True)
    result.add_argument("--expected-state", default="active", choices=["active"])
    result.add_argument("--apply", action="store_true")
    result.add_argument("--confirm-connector-id", default="")
    return result


def main() -> None:
    args = parser().parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    dynamodb = session.resource("dynamodb")
    connectors = dynamodb.Table(args.connectors_table)
    profiles = dynamodb.Table(args.profiles_table)
    connector = connectors.get_item(Key={"connector_id": args.connector_id}, ConsistentRead=True).get("Item")
    profile = profiles.get_item(Key={"profile_id": args.profile_id}, ConsistentRead=True).get("Item")
    if not connector or not profile:
        raise SystemExit("MIGRATION_RESULT=REFUSED reason=target_not_found")

    expected = {
        "connector_id": args.connector_id,
        "protocol_version": PROTOCOL,
        "plugin_instance_id": args.plugin_instance_id,
        "server_id": args.server_id,
        "plugin_public_key_fingerprint": args.fingerprint,
        "account_binding": args.account_binding,
        "family_binding": args.family_binding,
        "state": args.expected_state,
        "auth_state": "v3_active",
    }
    mismatches = [key for key, value in expected.items() if str(connector.get(key) or "") != value]
    profile_account = hashlib.sha256(str(profile.get("account_id") or "").encode("utf-8")).digest()
    profile_family = hashlib.sha256(str(profile.get("household_id") or "").encode("utf-8")).digest()
    import base64
    encoded_account = base64.urlsafe_b64encode(profile_account).decode("ascii").rstrip("=")
    encoded_family = base64.urlsafe_b64encode(profile_family).decode("ascii").rstrip("=")
    if encoded_account != args.account_binding:
        mismatches.append("profile_account_binding")
    if encoded_family != args.family_binding:
        mismatches.append("profile_family_binding")
    existing_profile = str(connector.get("profile_id") or "")
    if existing_profile and existing_profile != args.profile_id:
        mismatches.append("conflicting_profile_id")
    existing_key_id = str(connector.get("plugin_key_id") or "")
    if existing_key_id and existing_key_id != args.plugin_key_id:
        mismatches.append("conflicting_plugin_key_id")
    if mismatches:
        print(json.dumps({
            "migration": "pairing_v3_profile_binding", "mode": "apply" if args.apply else "dry_run",
            "result": "refused", "mismatches": sorted(set(mismatches)),
            "connector_ref": digest(args.connector_id), "profile_ref": digest(args.profile_id),
        }, separators=(",", ":"), sort_keys=True))
        raise SystemExit(2)

    if not args.apply:
        print(json.dumps({
            "migration": "pairing_v3_profile_binding", "mode": "dry_run", "result": "ready",
            "operation": "idempotent_noop" if existing_profile == args.profile_id else "conditional_profile_bind",
            "connector_ref": digest(args.connector_id), "profile_ref": digest(args.profile_id),
            "creates_connector": False,
        }, separators=(",", ":"), sort_keys=True))
        return

    if args.confirm_connector_id != args.connector_id:
        raise SystemExit("MIGRATION_RESULT=REFUSED reason=explicit_connector_confirmation_required")
    now = datetime.now(timezone.utc).isoformat()
    try:
        connectors.update_item(
            Key={"connector_id": args.connector_id},
            ConditionExpression=(
                "attribute_exists(connector_id) AND protocol_version = :protocol AND "
                "plugin_instance_id = :plugin_instance AND server_id = :server AND "
                "plugin_public_key_fingerprint = :fingerprint AND account_binding = :account AND "
                "family_binding = :family AND #state = :state AND auth_state = :auth AND "
                "(attribute_not_exists(profile_id) OR profile_id = :profile)"
            ),
            UpdateExpression="SET profile_id = if_not_exists(profile_id, :profile), plugin_key_id = if_not_exists(plugin_key_id, :plugin_key_id), updated_at = :now",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":protocol": PROTOCOL, ":plugin_instance": args.plugin_instance_id,
                ":server": args.server_id, ":fingerprint": args.fingerprint,
                ":account": args.account_binding, ":family": args.family_binding,
                ":state": args.expected_state, ":auth": "v3_active",
                ":profile": args.profile_id, ":now": now,
                ":plugin_key_id": args.plugin_key_id,
            },
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        raise SystemExit(f"MIGRATION_RESULT=REFUSED reason={code}") from None
    print(json.dumps({
        "migration": "pairing_v3_profile_binding", "mode": "apply", "result": "updated",
        "connector_ref": digest(args.connector_id), "profile_ref": digest(args.profile_id),
        "creates_connector": False,
    }, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
