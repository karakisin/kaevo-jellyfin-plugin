"""Exact, no-Scan watcher for one protected household-join fixture."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .constants import AWS_ACCOUNT_ID, AWS_PROFILE, AWS_REGION, JOIN_TRANSACTION_INVITATION_INDEX, STACK_NAME
from .errors import FixtureSafetyError


def _write_status(path: Path, count: int) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".watch-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"state": "WATCHING", "observed_transaction_count": count, "updated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z")}, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def watch(manifest_path: str | Path, *, once: bool = False) -> None:
    path = Path(manifest_path)
    if not path.is_file() or os.stat(path).st_mode & 0o077:
        raise FixtureSafetyError("FIXTURE_MANIFEST_UNAVAILABLE")
    manifest = json.loads(path.read_text())
    if (manifest.get("aws") or {}).get("account_id") != AWS_ACCOUNT_ID or (manifest.get("aws") or {}).get("region") != AWS_REGION:
        raise FixtureSafetyError("FIXTURE_MANIFEST_SCOPE_MISMATCH")
    invitation_key = ((manifest.get("resources") or {}).get("invitation") or {}).get("key") or {}
    code_hash = invitation_key.get("code_hash")
    marker = manifest.get("fixture_marker")
    if not isinstance(code_hash, str) or not isinstance(marker, str):
        raise FixtureSafetyError("FIXTURE_MANIFEST_BINDING_MISSING")
    import boto3
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    cfn = session.client("cloudformation")
    dynamodb = session.client("dynamodb")
    resources = []
    token = None
    while True:
        request = {"StackName": STACK_NAME}
        if token:
            request["NextToken"] = token
        page = cfn.list_stack_resources(**request)
        resources.extend(page.get("StackResourceSummaries") or [])
        token = page.get("NextToken")
        if not token:
            break
    physical = {item.get("LogicalResourceId"): item.get("PhysicalResourceId") for item in resources}
    invitations = physical.get("KaevoHouseholdInvitationsTable")
    joins = physical.get("KaevoHouseholdJoinTransactionsTable")
    if not isinstance(invitations, str) or not isinstance(joins, str):
        raise FixtureSafetyError("FIXTURE_TABLE_BINDING_MISSING")
    invitation = dynamodb.get_item(TableName=invitations, Key={"code_hash": {"S": code_hash}}, ConsistentRead=True).get("Item")
    if not isinstance(invitation, dict) or invitation.get("fixture_marker", {}).get("S") != marker:
        raise FixtureSafetyError("FIXTURE_INVITATION_BINDING_MISMATCH")
    invitation_id = invitation.get("invitation_id", {}).get("S")
    if not isinstance(invitation_id, str) or not invitation_id:
        raise FixtureSafetyError("FIXTURE_INVITATION_ID_MISSING")
    status_path = path.parent / "gsi-watcher.json"
    while True:
        response = dynamodb.query(
            TableName=joins,
            IndexName=JOIN_TRANSACTION_INVITATION_INDEX,
            KeyConditionExpression="#invitation_id = :invitation_id",
            ExpressionAttributeNames={"#invitation_id": "invitation_id"},
            ExpressionAttributeValues={":invitation_id": {"S": invitation_id}},
            ProjectionExpression="join_resume_hash",
        )
        _write_status(status_path, len(response.get("Items") or []))
        if once:
            return
        time.sleep(5)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args(argv)
    watch(arguments.manifest, once=arguments.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
