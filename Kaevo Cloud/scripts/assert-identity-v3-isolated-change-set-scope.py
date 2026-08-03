#!/usr/bin/env python3
"""Reject a change set unless it adds only isolated Identity V3 resources."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ADDS = {
    "KaevoAccountsTable", "KaevoAuthIdentitiesTable", "KaevoHouseholdMembershipsTable", "KaevoProfilesTable", "KaevoProfileBindingsTable", "KaevoProfileMappingsTable",
    "KaevoIdentityV3ApiRole", "KaevoIdentityV3ApiFunction", "KaevoIdentityV3ApiIntegration", "KaevoIdentityV3InvokePermission", "KaevoIdentityV3ApiDataPolicy",
    "KaevoIdentityV3GetContextRoute", "KaevoIdentityV3MigrateExistingAccountRoute", "KaevoIdentityV3MigrateHouseholdMembershipRoute", "KaevoIdentityV3CreateProfileRoute", "KaevoIdentityV3CreateProfileBindingRoute", "KaevoIdentityV3ListProfileMappingsRoute", "KaevoIdentityV3PreviewProfileMappingRoute", "KaevoIdentityV3ConfirmProfileMappingRoute", "KaevoIdentityV3CreateAndConfirmProfileMappingRoute",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    errors: list[str] = []
    for change in json.loads(args.change_set.read_text()).get("Changes", []):
        resource = change["ResourceChange"]
        if resource["Action"] != "Add":
            errors.append(f"forbidden {resource['Action'].lower()}: {resource['LogicalResourceId']}")
        elif resource["LogicalResourceId"] not in ADDS:
            errors.append(f"unexpected addition: {resource['LogicalResourceId']}")
        if resource.get("Replacement") in {True, "True", "Conditional"}:
            errors.append(f"forbidden replacement: {resource['LogicalResourceId']}")
    if errors:
        raise SystemExit("Identity V3 isolated change-set scope rejected:\n- " + "\n- ".join(errors))
    print("IDENTITY_V3_ISOLATED_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
