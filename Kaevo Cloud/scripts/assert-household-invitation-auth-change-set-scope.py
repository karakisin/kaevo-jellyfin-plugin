#!/usr/bin/env python3
"""Fail closed unless a household invitation auth change set is API-only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ALLOWED_MODIFIES = {"KaevoCloudHttpApi"}
ALLOWED_ADDS = {"KaevoCloudApiFunctionDeleteHouseholdInvitationPermission"}


def scope_errors(change_set: dict) -> list[str]:
    errors: list[str] = []
    for change in change_set.get("Changes", []):
        resource = change["ResourceChange"]
        logical_id = resource["LogicalResourceId"]
        action = resource["Action"]
        replacement = resource.get("Replacement")
        allowed = (
            (action == "Modify" and logical_id in ALLOWED_MODIFIES)
            or (action == "Add" and logical_id in ALLOWED_ADDS)
        )
        if not allowed:
            errors.append(f"unexpected {action.lower()}: {logical_id}")
        if replacement in {"True", "Conditional", True}:
            errors.append(f"forbidden replacement: {logical_id} ({replacement})")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    errors = scope_errors(json.loads(args.change_set.read_text()))
    if errors:
        raise SystemExit("Household invitation auth change-set scope rejected:\n- " + "\n- ".join(errors))
    print("HOUSEHOLD_INVITATION_AUTH_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
