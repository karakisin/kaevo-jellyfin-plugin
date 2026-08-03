#!/usr/bin/env python3
"""Produce a no-write Account Foundation backfill plan from an offline export.

This utility intentionally has no AWS client and no execute implementation.
The protected migration endpoint is the only write path.  Operators can use a
sanitized authority-graph export to identify eligible, conflicting, and
manual-review records before a separately authorized migration window.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping


SRC = Path(__file__).resolve().parents[1] / "api" / "src"
sys.path.insert(0, str(SRC))

from account_foundation import AccountFoundationError, plan_existing_account_backfill  # noqa: E402


def _subject_ref(subject: Any) -> str:
    return "subref1_" + hashlib.sha256(str(subject or "").encode("utf-8")).hexdigest()


def plan_snapshot(snapshot: Mapping[str, Any], *, subject: str | None = None, maximum: int = 100) -> dict[str, Any]:
    records = snapshot.get("records")
    if not isinstance(records, list):
        raise ValueError("snapshot records must be an array")
    if maximum < 1 or maximum > 10_000:
        raise ValueError("maximum must be between 1 and 10000")

    findings = []
    for record in records:
        if len(findings) >= maximum:
            break
        if not isinstance(record, Mapping):
            findings.append({"state": "manual_review_required", "reason": "invalid_snapshot_record"})
            continue
        record_subject = str(record.get("subject") or "")
        if subject and record_subject != subject:
            continue
        try:
            plan = plan_existing_account_backfill(
                subject=record_subject,
                principal=record.get("principal"),
                membership=record.get("membership"),
                household=record.get("household"),
                profile=record.get("profile"),
                existing_account=record.get("account"),
                existing_auth_identity=record.get("auth_identity"),
                now_iso="1970-01-01T00:00:00Z",
                now_epoch=0,
            )
            operations = []
            if plan.account_record is not None:
                operations.append("create_account")
            if plan.auth_identity_record is not None:
                operations.append("create_cognito_auth_identity")
            findings.append({
                "subject_ref": _subject_ref(record_subject),
                "account_id": plan.claims.account_id,
                "state": "already_migrated" if not operations else "eligible",
                "operations": operations,
            })
        except AccountFoundationError as error:
            findings.append({
                "subject_ref": _subject_ref(record_subject),
                "state": error.reason,
                "operations": [],
            })
    return {
        "schema_version": 1,
        "mode": "dry_run",
        "write_operations": 0,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, no-write Kaevo account backfill planner")
    parser.add_argument("--input", required=True, type=Path, help="Sanitized JSON authority-graph export")
    parser.add_argument("--subject", help="One exact Cognito subject from the local export")
    parser.add_argument("--max-records", type=int, default=100)
    parser.add_argument("--execute", action="store_true", help="Rejected: this tool never writes")
    args = parser.parse_args(argv)
    if args.execute:
        parser.error("execute mode is intentionally unavailable; use the protected migration endpoint after review")
    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    print(json.dumps(plan_snapshot(snapshot, subject=args.subject, maximum=args.max_records), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
