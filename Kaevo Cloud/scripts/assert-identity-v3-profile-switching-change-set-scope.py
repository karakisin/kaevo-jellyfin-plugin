#!/usr/bin/env python3
"""Reject any Profile Switching CloudFormation change beyond the exact release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {
    "KaevoIdentityV3ApiFunction": "Modify",
    "KaevoIdentityV3ApiIntegration": "Modify",
    "KaevoIdentityV3SetProfileSwitchPINRoute": "Add",
    "KaevoIdentityV3VerifyProfileSwitchPINRoute": "Add",
    "KaevoIdentityV3UpdateProfileSwitchTargetsRoute": "Add",
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
            details = resource.get("Details") or []
            if not any(
                detail.get("Target", {}).get("Name") == "IntegrationUri"
                and detail.get("CausingEntity") == "KaevoIdentityV3ApiFunction.Arn"
                for detail in details
            ):
                errors.append("Identity V3 integration is not only following the refreshed Lambda ARN")
    if errors:
        raise SystemExit("Identity V3 Profile Switching change-set scope rejected:\n- " + "\n- ".join(errors))
    print("IDENTITY_V3_PROFILE_SWITCHING_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
