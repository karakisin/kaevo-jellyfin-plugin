"""Local-only JSON rendering helpers for Household Join validation evidence.

These functions never participate in Lambda request handling or DynamoDB
writes.  They make boto3's Decimal values renderable in a reviewer-safe local
evidence report while preserving the original returned item in memory.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any


def _evidence_json_default(value: object) -> int | str:
    """Represent DynamoDB Decimal values exactly without mutating the item."""
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        # JSON has no Decimal type; a string retains the exact stored value.
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def render_evidence(item: Any) -> str:
    """Return deterministic local JSON suitable for redacted evidence output."""
    return json.dumps(item, default=_evidence_json_default, sort_keys=True, separators=(",", ":"))
