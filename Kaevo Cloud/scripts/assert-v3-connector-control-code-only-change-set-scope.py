#!/usr/bin/env python3
"""Fail closed unless a change set updates only connector-control Lambda code.

CloudFormation may also report the unchanged HTTP API Body as a dynamic,
non-replacing dependent update because that Body references the connector
Lambda ARN. That single dependency row is accepted only with its exact cause;
no static HTTP API edit is allowed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RESOURCE = "KaevoV3ConnectorControlFunction"
HTTP_API = "KaevoCloudHttpApi"


def scope_errors(document: dict) -> list[str]:
    changes = document.get("Changes", [])
    errors: list[str] = []
    logical_ids = {
        change.get("ResourceChange", {}).get("LogicalResourceId")
        for change in changes
    }
    allowed_ids = {RESOURCE, HTTP_API}
    if RESOURCE not in logical_ids:
        errors.append(f"missing required resource change: {RESOURCE}")
    unexpected = sorted(str(value) for value in logical_ids - allowed_ids)
    if unexpected:
        errors.append(f"unexpected resources: {unexpected}")

    for change in changes:
        resource = change.get("ResourceChange", {})
        logical_id = resource.get("LogicalResourceId")
        if resource.get("Action") != "Modify":
            errors.append(f"expected Modify for {logical_id}, found {resource.get('Action')}")
        if resource.get("Replacement") not in {False, "False", None}:
            errors.append(f"replacement is forbidden for {logical_id}")
        details = resource.get("Details", [])
        if len(details) != 1:
            errors.append(f"expected one property detail for {logical_id}, found {len(details)}")
            continue
        detail = details[0]
        target = detail.get("Target", {})
        if logical_id == RESOURCE:
            if target.get("Attribute") != "Properties" or target.get("Name") != "Code":
                errors.append(f"only Lambda Code may change, found {target}")
            if detail.get("Evaluation") != "Static":
                errors.append(f"Lambda Code update must be static, found {detail.get('Evaluation')}")
            continue
        if logical_id == HTTP_API:
            expected_target = {
                "Attribute": "Properties",
                "Name": "Body",
                "RequiresRecreation": "Never",
            }
            if (
                target != expected_target
                or detail.get("Evaluation") != "Dynamic"
                or detail.get("ChangeSource") != "ResourceAttribute"
                or detail.get("CausingEntity") != f"{RESOURCE}.Arn"
            ):
                errors.append(f"unexpected HTTP API dependency detail: {detail}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()

    document = json.loads(args.change_set.read_text(encoding="utf-8"))
    errors = scope_errors(document)

    if errors:
        raise SystemExit("V3 connector-control code-only scope rejected:\n- " + "\n- ".join(errors))
    print("V3_CONNECTOR_CONTROL_CODE_ONLY_SCOPE=APPROVED")


if __name__ == "__main__":
    main()
