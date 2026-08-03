#!/usr/bin/env python3
"""Reject any runtime repair change outside the API Lambda and its role."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {
    "KaevoCloudApiFunction": "Modify",
    "KaevoCloudApiFunctionRole": "Modify",
    # These three resources are unchanged in the candidate. CloudFormation
    # reports non-replacing dynamic updates because they consume the API
    # Lambda or role ARN through existing references.
    "KaevoCloudHttpApi": "Modify",
    "KaevoSocialIdentityApiFunctionRole": "Modify",
    "KaevoSocialIdentityApiFunction": "Modify",
}

EXPECTED_DYNAMIC = {
    "KaevoCloudHttpApi": {
        ("Body", "KaevoCloudApiFunction.Arn"),
        ("Body", "KaevoSocialIdentityApiFunction.Arn"),
    },
    "KaevoSocialIdentityApiFunctionRole": {
        ("Policies", "KaevoCloudApiFunction.Arn"),
    },
    "KaevoSocialIdentityApiFunction": {
        ("Role", "KaevoSocialIdentityApiFunctionRole.Arn"),
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    changes = json.loads(args.change_set.read_text()).get("Changes", [])
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
        logical_id = resource.get("LogicalResourceId")
        if logical_id in EXPECTED_DYNAMIC:
            details = resource.get("Details") or []
            actual_dynamic = {
                (
                    str((detail.get("Target") or {}).get("Name") or ""),
                    str(detail.get("CausingEntity") or ""),
                )
                for detail in details
                if detail.get("Evaluation") == "Dynamic"
                and detail.get("ChangeSource") == "ResourceAttribute"
                and (detail.get("Target") or {}).get("RequiresRecreation") == "Never"
            }
            if actual_dynamic != EXPECTED_DYNAMIC[logical_id] or len(details) != len(actual_dynamic):
                errors.append(f"unexpected dynamic dependency: {logical_id}")
    if errors:
        raise SystemExit(
            "Household connector authority runtime scope rejected:\n- "
            + "\n- ".join(errors)
        )
    print("HOUSEHOLD_CONNECTOR_AUTHORITY_RUNTIME_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
