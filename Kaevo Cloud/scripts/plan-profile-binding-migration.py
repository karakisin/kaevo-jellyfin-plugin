#!/usr/bin/env python3
"""Offline-only review planner for future Profile/ProfileBinding migration."""

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

from profile_binding import AGE_CLASSIFICATIONS, PROFILE_TYPES  # noqa: E402


def _ref(value: Any) -> str:
    return "prefref1_" + hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def plan_snapshot(snapshot: Mapping[str, Any], *, maximum: int = 100) -> dict[str, Any]:
    records = snapshot.get("records")
    if not isinstance(records, list):
        raise ValueError("snapshot records must be an array")
    if maximum < 1 or maximum > 10_000:
        raise ValueError("maximum must be between 1 and 10000")
    profiles = [record for record in records if isinstance(record, Mapping)]
    names = Counter(
        (str(record.get("household_id") or ""), str(record.get("display_name") or "").strip().casefold())
        for record in profiles
    )
    findings = []
    for record in profiles[:maximum]:
        household_id = str(record.get("household_id") or "")
        name = str(record.get("display_name") or "").strip()
        profile_type = str(record.get("profile_type") or "").strip().lower()
        age = str(record.get("age_classification") or "").strip().lower()
        finding = {
            "source_ref": _ref(record.get("source_identifier") or name),
            "household_ref": _ref(household_id),
            "write_operations": [],
        }
        if not household_id or not bool(record.get("active_household_membership")):
            finding["state"] = "missing_household_membership"
        elif profile_type not in PROFILE_TYPES or age not in AGE_CLASSIFICATIONS or age == "unresolved" or age != profile_type:
            finding["state"] = "unresolved_age_classification"
        elif names[(household_id, name.casefold())] > 1:
            finding["state"] = "duplicate_display_name_review_required"
        elif bool(record.get("ambiguous_owner")):
            finding["state"] = "ambiguous_ownership"
        else:
            finding.update({"state": "candidate_requires_explicit_confirmation", "profile_type": profile_type})
        findings.append(finding)
    return {"schema_version": 1, "mode": "dry_run", "write_operations": 0, "findings": findings}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, no-write Kaevo profile-binding migration planner")
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
