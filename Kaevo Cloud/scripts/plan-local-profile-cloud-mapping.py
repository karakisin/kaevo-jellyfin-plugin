#!/usr/bin/env python3
"""Offline-only planner for explicit local Profile-to-Cloud Profile review."""

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

from profile_mapping import local_profile_source_id  # noqa: E402


def _ref(value: Any) -> str:
    """Produce a report-only opaque reference; never echo supplied identifiers."""
    return "pmplanref1_" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def plan_snapshot(snapshot: Mapping[str, Any], *, maximum: int = 100) -> dict[str, Any]:
    """Classify sanitized fixture rows without selecting, creating, or writing mappings."""
    records = snapshot.get("records")
    if not isinstance(records, list):
        raise ValueError("snapshot records must be an array")
    if maximum < 1 or maximum > 10_000:
        raise ValueError("maximum must be between 1 and 10000")

    rows = [row for row in records if isinstance(row, Mapping)]
    source_counts = Counter(
        (str(row.get("installation_id") or ""), str(row.get("local_profile_source_id") or ""))
        for row in rows
    )
    findings = []
    for row in rows[:maximum]:
        installation_id = str(row.get("installation_id") or "").strip()
        source = str(row.get("local_profile_source_id") or "").strip()
        finding = {
            "installation_ref": _ref(installation_id),
            "local_source_ref": _ref(source),
            "account_ref": _ref(row.get("account_id")),
            "household_ref": _ref(row.get("household_id")),
            "write_operations": [],
        }
        try:
            local_profile_source_id(source)
            source_is_valid = True
        except Exception:
            source_is_valid = False
        if not source_is_valid:
            finding["state"] = "invalid_local_source_review_required"
        elif not installation_id:
            finding["state"] = "missing_installation_review_required"
        elif not bool(row.get("active_account_membership")):
            finding["state"] = "inactive_account_or_household_review_required"
        elif bool(row.get("cross_household_conflict")):
            finding["state"] = "cross_household_conflict_review_required"
        elif bool(row.get("existing_mapping_conflict")):
            finding["state"] = "existing_mapping_conflict_review_required"
        elif source_counts[(installation_id, source)] > 1:
            finding["state"] = "duplicate_local_source_review_required"
        else:
            finding["state"] = "candidate_requires_explicit_confirmation"
        findings.append(finding)
    return {
        "schema_version": 1,
        "mode": "dry_run",
        "write_operations": 0,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, no-write Kaevo local Profile mapping planner")
    parser.add_argument("--input", required=True, type=Path, help="Explicit sanitized fixture/export path")
    parser.add_argument("--max-records", type=int, default=100)
    parser.add_argument("--execute", action="store_true", help="Rejected: this planner never writes")
    args = parser.parse_args(argv)
    if args.execute:
        parser.error("execute mode is intentionally unavailable; this planner never writes")
    snapshot = json.loads(args.input.read_text(encoding="utf-8"))
    print(json.dumps(plan_snapshot(snapshot, maximum=args.max_records), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
