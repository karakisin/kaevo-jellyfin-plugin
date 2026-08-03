#!/usr/bin/env python3
"""Reject every CloudFormation change outside Connector <-> Identity binding."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {
    "KaevoIdentityV3ApiFunction": "Modify",
    "KaevoIdentityV3ApiDataPolicy": "Modify",
    # This resource is unchanged in the candidate. CloudFormation reports a
    # non-replacing dynamic update because IntegrationUri references the
    # dedicated Identity V3 Lambda ARN, whose code is being updated.
    "KaevoIdentityV3ApiIntegration": "Modify",
    "KaevoIdentityV3GetHomeConnectorBindingRoute": "Add",
    "KaevoIdentityV3BindHomeConnectorRoute": "Add",
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
        errors.append(f"unexpected change set resources: {actual}")
    for item in changes:
        resource = item["ResourceChange"]
        if resource.get("Replacement") in {True, "True", "Conditional"}:
            errors.append(f"replacement is forbidden: {resource.get('LogicalResourceId')}")
        if resource.get("LogicalResourceId") == "KaevoIdentityV3ApiIntegration":
            details = resource.get("Details") or []
            if details != [{
                "Target": {"Attribute": "Properties", "Name": "IntegrationUri", "RequiresRecreation": "Never"},
                "Evaluation": "Dynamic",
                "ChangeSource": "ResourceAttribute",
                "CausingEntity": "KaevoIdentityV3ApiFunction.Arn",
            }]:
                errors.append("Identity V3 integration is not the expected Lambda-ARN dynamic dependency")
    if errors:
        raise SystemExit("Connector <-> Identity binding change-set scope rejected:\n- " + "\n- ".join(errors))
    print("IDENTITY_V3_HOME_CONNECTOR_BINDING_CHANGE_SET_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
