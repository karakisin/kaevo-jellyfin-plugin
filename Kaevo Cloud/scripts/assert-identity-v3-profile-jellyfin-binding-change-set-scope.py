#!/usr/bin/env python3
"""Fail closed unless profile/Jellyfin binding deployment is narrowly scoped."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {
    "KaevoIdentityV3ApiFunction": "Modify",
    "KaevoIdentityV3ApiIntegration": "Modify",
    "KaevoIdentityV3SaveProfileJellyfinBindingRoute": "Add",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    changes = json.loads(args.change_set.read_text(encoding="utf-8")).get("Changes", [])
    actual = {
        item["ResourceChange"].get("LogicalResourceId"): item["ResourceChange"].get("Action")
        for item in changes
    }
    errors = []
    if actual != EXPECTED:
        errors.append(f"unexpected change-set resources: {actual}")
    for item in changes:
        resource = item["ResourceChange"]
        if resource.get("Replacement") in {True, "True", "Conditional"}:
            errors.append(f"replacement is forbidden: {resource.get('LogicalResourceId')}")
        if resource.get("LogicalResourceId") == "KaevoIdentityV3ApiIntegration":
            expected_details = [{
                "Target": {
                    "Attribute": "Properties",
                    "Name": "IntegrationUri",
                    "RequiresRecreation": "Never",
                },
                "Evaluation": "Dynamic",
                "ChangeSource": "ResourceAttribute",
                "CausingEntity": "KaevoIdentityV3ApiFunction.Arn",
            }]
            if resource.get("Details") != expected_details:
                errors.append("Identity V3 integration is not the expected Lambda-ARN dependency")
    if errors:
        raise SystemExit(
            "Identity V3 profile Jellyfin binding change-set scope rejected:\n- "
            + "\n- ".join(errors)
        )
    print("IDENTITY_V3_PROFILE_JELLYFIN_BINDING_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
