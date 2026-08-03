#!/usr/bin/env python3
"""Fail closed unless a change set is only the safe Join-table GSI addition."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


TABLE = "KaevoHouseholdJoinTransactionsTable"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--change-set", required=True, type=Path)
    args = parser.parse_args()
    changes = json.loads(args.change_set.read_text()).get("Changes") or []
    if len(changes) != 1:
        raise SystemExit("JOIN_TRANSACTION_INDEX_CHANGE_SET_SCOPE=REJECTED change_count")
    change = changes[0].get("ResourceChange") or {}
    if (
        change.get("LogicalResourceId") != TABLE
        or change.get("Action") != "Modify"
        or change.get("Replacement") not in {False, "False"}
    ):
        raise SystemExit("JOIN_TRANSACTION_INDEX_CHANGE_SET_SCOPE=REJECTED resource_scope")
    details = change.get("Details") or []
    names = {((detail.get("Target") or {}).get("Name")) for detail in details}
    if "GlobalSecondaryIndexes" not in names:
        raise SystemExit("JOIN_TRANSACTION_INDEX_CHANGE_SET_SCOPE=REJECTED missing_index_detail")
    print("JOIN_TRANSACTION_INDEX_CHANGE_SET_SCOPE=APPROVED")
    print("DELETIONS=0")
    print("REPLACEMENTS=0")


if __name__ == "__main__":
    main()
