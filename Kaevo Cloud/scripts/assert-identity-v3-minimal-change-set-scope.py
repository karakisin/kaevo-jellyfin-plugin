#!/usr/bin/env python3
"""Reject any Identity V3 candidate change set outside the approved scope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ADDS = {
    "KaevoAccountsTable", "KaevoAuthIdentitiesTable", "KaevoHouseholdMembershipsTable", "KaevoProfilesTable", "KaevoProfileBindingsTable", "KaevoProfileMappingsTable",
    "KaevoIdentityV3ApiIntegration", "KaevoIdentityV3InvokePermission", "KaevoIdentityV3ApiDataPolicy", "KaevoIdentityV3OwnerEnrollmentDataPolicy",
    "KaevoIdentityV3GetContextRoute", "KaevoIdentityV3MigrateExistingAccountRoute", "KaevoIdentityV3MigrateHouseholdMembershipRoute", "KaevoIdentityV3CreateProfileRoute", "KaevoIdentityV3CreateProfileBindingRoute", "KaevoIdentityV3ListProfileMappingsRoute", "KaevoIdentityV3PreviewProfileMappingRoute", "KaevoIdentityV3ConfirmProfileMappingRoute", "KaevoIdentityV3CreateAndConfirmProfileMappingRoute",
}
MODIFIES = {"KaevoCloudApiFunction", "KaevoOwnerEnrollmentFunction"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    change_set = json.loads(args.change_set.read_text())
    errors: list[str] = []
    for change in change_set.get("Changes", []):
        resource = change["ResourceChange"]
        logical_id, action, replacement = resource["LogicalResourceId"], resource["Action"], resource.get("Replacement")
        if action == "Add" and logical_id not in ADDS:
            errors.append(f"unexpected addition: {logical_id}")
        elif action == "Modify" and logical_id not in MODIFIES:
            errors.append(f"unexpected modification: {logical_id}")
        elif action != "Add" and action != "Modify":
            errors.append(f"forbidden {action.lower()}: {logical_id}")
        if replacement in {True, "True", "Conditional"}:
            errors.append(f"forbidden replacement: {logical_id} ({replacement})")
    if errors:
        raise SystemExit("Identity V3 minimal change-set scope rejected:\n- " + "\n- ".join(errors))
    print("IDENTITY_V3_MINIMAL_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
