"""Minimal source-derived contracts that make live discovery safe or refuse it."""

from __future__ import annotations

from collections.abc import Mapping

from .constants import JOIN_TRANSACTION_INVITATION_INDEX


def transaction_lookup_path(table: Mapping[str, object]) -> str | None:
    """Return an allowed lookup path, never a scan fallback.

    The physical app creates ``join_resume_hash = sha256(random resume
    handle)`` inside /begin.  The runner may not invoke /begin and therefore
    needs a GSI whose hash key is a fixture-owned invitation field.  A simple
    primary key on join_resume_hash is deliberately insufficient.
    """
    indexes = table.get("GlobalSecondaryIndexes") or []
    for index in indexes:
        if not isinstance(index, Mapping):
            continue
        if index.get("IndexName") != JOIN_TRANSACTION_INVITATION_INDEX:
            continue
        schema = index.get("KeySchema") or []
        key_types = {
            entry.get("KeyType"): entry.get("AttributeName")
            for entry in schema
            if isinstance(entry, Mapping)
        }
        projection = index.get("Projection") or {}
        if (
            key_types == {"HASH": "invitation_id", "RANGE": "created_at_epoch"}
            and isinstance(projection, Mapping)
            and projection.get("ProjectionType") == "KEYS_ONLY"
            and index.get("IndexStatus") in {None, "ACTIVE"}
        ):
            return "fixture_invitation_gsi"
    return None


def assert_exact_join_transaction_lookup(table: Mapping[str, object]) -> str:
    path = transaction_lookup_path(table)
    if path is None:
        from .errors import FixtureSafetyError

        raise FixtureSafetyError("UNQUERYABLE_WITHOUT_SCAN")
    return path
