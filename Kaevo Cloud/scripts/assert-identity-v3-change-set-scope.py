#!/usr/bin/env python3
"""Fail closed unless the Identity V3 synchronization change set is bounded."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ALLOWED_ADDS = {
    "KaevoAccountsTable",
    "KaevoAuthIdentitiesTable",
    "KaevoHouseholdMembershipsTable",
    "KaevoProfilesTable",
    "KaevoProfileBindingsTable",
    "KaevoProfileMappingsTable",
    "KaevoIdentityV3ApiIntegration",
    "KaevoIdentityV3InvokePermission",
    "KaevoIdentityV3GetContextRoute",
    "KaevoIdentityV3MigrateExistingAccountRoute",
    "KaevoIdentityV3MigrateHouseholdMembershipRoute",
    "KaevoIdentityV3CreateProfileRoute",
    "KaevoIdentityV3CreateProfileBindingRoute",
    "KaevoIdentityV3ListProfileMappingsRoute",
    "KaevoIdentityV3PreviewProfileMappingRoute",
    "KaevoIdentityV3ConfirmProfileMappingRoute",
    "KaevoIdentityV3CreateAndConfirmProfileMappingRoute",
}
ALLOWED_MODIFIES = {
    "KaevoCloudApiFunction",
    "KaevoCloudApiFunctionRole",
    "KaevoIdentityClaimIssuerFunction",
    "KaevoOwnerEnrollmentFunction",
    "KaevoOwnerEnrollmentFunctionRole",
    "KaevoCloudHttpApidevStage",
}


def scope_errors(change_set: dict) -> list[str]:
    errors: list[str] = []
    for change in change_set.get("Changes", []):
        resource = change["ResourceChange"]
        logical_id = resource["LogicalResourceId"]
        action = resource["Action"]
        replacement = resource.get("Replacement")
        if action == "Remove":
            errors.append(f"forbidden removal: {logical_id}")
        if replacement in {"True", "Conditional", True}:
            errors.append(f"forbidden replacement: {logical_id} ({replacement})")
        if action == "Add" and logical_id not in ALLOWED_ADDS:
            errors.append(f"unexpected addition: {logical_id}")
        elif action == "Modify" and logical_id not in ALLOWED_MODIFIES:
            errors.append(f"unexpected modification: {logical_id}")
        elif action not in {"Add", "Modify", "Remove"}:
            errors.append(f"unexpected action {action}: {logical_id}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    errors = scope_errors(json.loads(args.change_set.read_text()))
    if errors:
        raise SystemExit("Identity V3 change-set scope rejected:\n- " + "\n- ".join(errors))
    print("IDENTITY_V3_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
