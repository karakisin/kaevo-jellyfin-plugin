#!/usr/bin/env python3
"""Fail closed unless the IAM reconciliation changes only the API role."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    payload = json.loads(args.change_set.read_text())
    # CloudFormation omits ChangeSetType for ordinary UPDATE sets in
    # DescribeChangeSet responses; creation is recorded separately.
    if payload.get("ChangeSetType") not in {None, "UPDATE"}:
        raise SystemExit("IAM_RECONCILIATION_CHANGE_SET_SCOPE=REJECTED change_set_type")
    if payload.get("DeploymentMode") == "REVERT_DRIFT":
        raise SystemExit("IAM_RECONCILIATION_CHANGE_SET_SCOPE=REJECTED deployment_mode")
    changes = payload.get("Changes") or []
    if len(changes) != 1:
        raise SystemExit("IAM_RECONCILIATION_CHANGE_SET_SCOPE=REJECTED change_count")
    change = changes[0].get("ResourceChange") or {}
    if (
        change.get("LogicalResourceId") != "KaevoCloudApiFunctionRole"
        or change.get("Action") != "Modify"
        or change.get("Replacement") not in {False, "False"}
    ):
        raise SystemExit("IAM_RECONCILIATION_CHANGE_SET_SCOPE=REJECTED resource_scope")
    names = {((detail.get("Target") or {}).get("Name")) for detail in (change.get("Details") or [])}
    if "Policies" not in names:
        raise SystemExit("IAM_RECONCILIATION_CHANGE_SET_SCOPE=REJECTED policy_detail_missing")
    print("IAM_RECONCILIATION_CHANGE_SET_SCOPE=APPROVED")
    print("CHANGE_SET_TYPE=UPDATE_OR_SERVICE_OMITTED")
    print("DEPLOYMENT_MODE=TRADITIONAL")
    print("DELETIONS=0")
    print("REPLACEMENTS=0")
    print("GSI_CHANGES=0")


if __name__ == "__main__":
    main()
