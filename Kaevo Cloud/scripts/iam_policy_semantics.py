"""Deterministic, lossless IAM policy canonicalization for review tooling."""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy


_ORDER_INSENSITIVE_LISTS = {"Action", "NotAction", "Resource", "NotResource"}


def _canonical(value, *, key: str | None = None):
    if isinstance(value, Mapping):
        return {name: _canonical(value[name], key=name) for name in sorted(value)}
    if isinstance(value, list):
        items = [_canonical(item) for item in value]
        if key in _ORDER_INSENSITIVE_LISTS or key == "Statement":
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return items
    return value


def canonical_policy(document: Mapping) -> dict:
    """Normalize representation only; duplicates and semantic fields remain."""
    copied = deepcopy(dict(document))
    for statement in copied.get("Statement") or []:
        if not isinstance(statement, dict):
            continue
        for name in _ORDER_INSENSITIVE_LISTS:
            if name in statement and not isinstance(statement[name], list):
                statement[name] = [statement[name]]
    return _canonical(copied)


def policy_fingerprint(document: Mapping) -> str:
    return json.dumps(canonical_policy(document), sort_keys=True, separators=(",", ":"))


def effective_permissions_identical(left: Mapping, right: Mapping) -> bool:
    return policy_fingerprint(left) == policy_fingerprint(right)
