#!/usr/bin/env python3
"""Produce a no-write HouseholdMembership normalization plan from an export.

This utility intentionally imports no AWS SDK and rejects --execute.  It is a
review aid for sanitized, offline authority-graph exports; the protected API
is the sole write path in this milestone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


SRC = Path(__file__).resolve().parents[1] / "api" / "src"
sys.path.insert(0, str(SRC))

from account_foundation import AccountFoundationError  # noqa: E402
from household_membership import plan_household_membership_normalization  # noqa: E402


def _subject_ref(subject: Any) -> str:
    return "subref1_" + hashlib.sha256(str(subject or "").encode("utf-8")).hexdigest()


def plan_snapshot(snapshot: Mapping[str, Any], *, subject: str | None = None, maximum: int = 100) -> dict[str, Any]:
    records = snapshot.get("records")
    if not isinstance(records, list):
        raise ValueError("snapshot records must be an array")
    if maximum < 1 or maximum > 10_000:
        raise ValueError("maximum must be between 1 and 10000")

    selected = [record for record in records if isinstance(record, Mapping)]
    owner_households = Counter(
        str((record.get("principal") or {}).get("household_id") or "")
        for record in selected
        if str((record.get("principal") or {}).get("role") or "").lower() == "owner"
    )
    findings: list[dict[str, Any]] = []
    seen_candidates: set[tuple[str, str]] = set()
    for record in selected:
        if len(findings) >= maximum:
            break
        record_subject = str(record.get("subject") or "")
        if subject and record_subject != subject:
            continue
        principal = record.get("principal")
        household_id = str((principal or {}).get("household_id") or "") if isinstance(principal, Mapping) else ""
        finding: dict[str, Any] = {"subject_ref": _subject_ref(record_subject), "operations": []}
        if household_id and owner_households[household_id] > 1:
            finding.update({"state": "ownership_conflict", "reason": "multiple_owner_candidates"})
            findings.append(finding)
            continue
        try:
            plan = plan_household_membership_normalization(
                subject=record_subject,
                principal=principal,
                legacy_membership=record.get("membership"),
                household=record.get("household"),
                profile=record.get("profile"),
                existing_membership=record.get("normalized_membership"),
                existing_account_guard=record.get("account_household_guard"),
                existing_owner_guard=record.get("owner_guard"),
                now_iso="1970-01-01T00:00:00Z",
                now_epoch=0,
            )
            candidate = (plan.claims.account_id, plan.claims.household_id)
            if candidate in seen_candidates:
                finding.update({"state": "membership_conflict", "reason": "duplicate_membership_candidate"})
            else:
                seen_candidates.add(candidate)
                operations = []
                if plan.membership_record is not None:
                    operations.append("create_household_membership")
                if plan.uniqueness_guard_record is not None:
                    operations.append("reserve_account_household_membership")
                if plan.owner_guard_record is not None:
                    operations.append("reserve_household_owner")
                finding.update({
                    "account_id": plan.claims.account_id,
                    "household_id": plan.claims.household_id,
                    "canonical_role": plan.role.value,
                    "membership_id": plan.membership_id,
                    "state": "already_normalized" if not operations else "eligible",
                    "operations": operations,
                })
        except AccountFoundationError as error:
            finding["state"] = error.reason
        findings.append(finding)
    return {
        "schema_version": 1,
        "mode": "dry_run",
        "write_operations": 0,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, no-write Kaevo household membership planner")
    parser.add_argument("--input", required=True, type=Path, help="Sanitized JSON authority-graph export")
    parser.add_argument("--subject", help="One exact Cognito subject from the local export")
    parser.add_argument("--max-records", type=int, default=100)
    parser.add_argument("--execute", action="store_true", help="Rejected: this tool never writes")
    args = parser.parse_args(argv)
    if args.execute:
        parser.error("execute mode is intentionally unavailable; this planner never writes")
    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    print(json.dumps(plan_snapshot(snapshot, subject=args.subject, maximum=args.max_records), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
