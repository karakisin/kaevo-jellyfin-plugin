"""Synthetic-only helpers for the isolated Household Join live fixtures.

These helpers intentionally mirror the iOS manual-code contract before a
fixture is written. They are not imported by Lambda production code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


_CANONICAL_INVITATION = re.compile(r"^[A-Z0-9]{5}-[A-Z0-9]{5}$", re.ASCII)
_JOIN_TRANSACTION_KEY = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FIXTURE_MARKER = re.compile(r"^fixture-[a-z0-9-]{8,96}$", re.ASCII)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json_write(path: Path, payload: dict) -> None:
    """Atomically replace one mode-0600 private manifest and fsync its parent."""
    encoded = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".manifest-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ProtectedFixtureManifest:
    """Durable, synthetic-only manifest with append-only lifecycle journal.

    This lives outside a repository on the Apple Developer SSD.  Exact cleanup
    keys remain private in the mode-0600 JSON file and are never returned from
    diagnostic helpers.
    """

    def __init__(self, path: Path, payload: dict):
        self.path = path
        self.payload = payload

    @classmethod
    def create(
        cls,
        root: Path,
        *,
        marker: str,
        account_id: str,
        region: str,
        table_arn_fingerprints: dict,
        fixture_type: str = "household_join",
        expected_resource_plan: tuple[str, ...] = (),
    ) -> "ProtectedFixtureManifest":
        if not isinstance(marker, str) or not _FIXTURE_MARKER.fullmatch(marker):
            raise ValueError("fixture marker is invalid")
        if not isinstance(account_id, str) or not account_id or not isinstance(region, str) or not region:
            raise ValueError("fixture account and region are required")
        if not isinstance(table_arn_fingerprints, dict) or not table_arn_fingerprints:
            raise ValueError("table ARN fingerprints are required")
        root = Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.stat().st_mode & 0o077:
            raise ValueError("fixture root must not be group or world accessible")
        directory = root / marker
        if directory.exists():
            raise ValueError("fixture manifest already exists")
        directory.mkdir(mode=0o700)
        path = directory / "manifest.json"
        payload = {
            "version": 1,
            "fixture_type": fixture_type,
            "fixture_marker": marker,
            "aws": {"account_id": account_id, "region": region, "table_arn_fingerprints": dict(table_arn_fingerprints)},
            "resources": {},
            "journal": [{"operation": "manifest_created", "timestamp": _utc_now(), "source": "fixture_tool"}],
            "cleanup": {"state": "active"},
            "fixture": {"state": "MANIFEST_CREATED", "expected_resource_plan": list(expected_resource_plan)},
        }
        _atomic_json_write(path, payload)
        return cls(path, payload)

    @classmethod
    def load(cls, path: Path, *, account_id: str, region: str) -> "ProtectedFixtureManifest":
        path = Path(path)
        if not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("protected fixture manifest is unavailable")
        payload = json.loads(path.read_text(encoding="utf-8"))
        aws = payload.get("aws") or {}
        if aws.get("account_id") != account_id or aws.get("region") != region:
            raise ValueError("fixture account or region mismatch")
        return cls(path, payload)

    def _commit(self, updated: dict) -> None:
        _atomic_json_write(self.path, updated)
        self.payload = updated

    def record_resource(self, resource: str, exact_key: dict, *, source_operation: str, bindings: dict) -> None:
        if not isinstance(resource, str) or not resource or not isinstance(exact_key, dict) or not exact_key:
            raise ValueError("resource and exact key are required")
        if resource in self.payload["resources"]:
            raise ValueError("resource key cannot be overwritten")
        updated = deepcopy(self.payload)
        updated["resources"][resource] = {"key": dict(exact_key), "bindings": dict(bindings)}
        updated["journal"].append({"operation": source_operation, "resource": resource, "timestamp": _utc_now()})
        self._commit(updated)

    def replace_resource(
        self,
        resource: str,
        *,
        expected_key: dict,
        replacement_key: dict,
        source_operation: str,
        bindings: dict,
    ) -> None:
        """Atomically journal one exact, pre-authorized resource-key rotation."""
        current = (self.payload.get("resources") or {}).get(resource)
        if not isinstance(current, dict) or current.get("key") != expected_key:
            raise ValueError("fixture resource replacement does not match manifested key")
        if not isinstance(replacement_key, dict) or not replacement_key:
            raise ValueError("replacement key is required")
        updated = deepcopy(self.payload)
        updated["resources"][resource] = {"key": dict(replacement_key), "bindings": dict(bindings)}
        updated["journal"].append({"operation": source_operation, "resource": resource, "timestamp": _utc_now()})
        self._commit(updated)

    def record_transaction_key(self, transaction_key: str, *, source_operation: str = "begin") -> None:
        if not isinstance(transaction_key, str) or not _JOIN_TRANSACTION_KEY.fullmatch(transaction_key):
            raise ValueError("transaction key must be a lowercase SHA-256 hex value")
        updated = deepcopy(self.payload)
        transactions = updated["resources"].setdefault("transactions", {"keys": [], "bindings": {}})
        if transaction_key not in transactions["keys"]:
            transactions["keys"].append(transaction_key)
            updated["journal"].append({"operation": source_operation, "resource": "transaction", "timestamp": _utc_now()})
        self._commit(updated)

    def mark_active_transaction(self, transaction_key: str) -> None:
        transactions = (self.payload.get("resources") or {}).get("transactions") or {}
        if transaction_key not in transactions.get("keys", []):
            raise ValueError("active transaction must already be manifested")
        updated = deepcopy(self.payload)
        updated["resources"]["transactions"]["active_key"] = transaction_key
        updated["journal"].append({"operation": "route_auth_active_transaction", "resource": "transaction", "timestamp": _utc_now()})
        self._commit(updated)

    def transition_fixture_state(self, state: str, *, source_operation: str) -> None:
        if not isinstance(state, str) or not state or not isinstance(source_operation, str) or not source_operation:
            raise ValueError("fixture state and source operation are required")
        updated = deepcopy(self.payload)
        updated.setdefault("fixture", {})["state"] = state
        updated["journal"].append({"operation": source_operation, "resource": "fixture", "timestamp": _utc_now()})
        self._commit(updated)

    def transition_cleanup_state(self, state: str, *, source_operation: str) -> None:
        """Durably record one cleanup lifecycle transition without changing keys."""
        if not isinstance(state, str) or not state or not isinstance(source_operation, str) or not source_operation:
            raise ValueError("cleanup state and source operation are required")
        updated = deepcopy(self.payload)
        updated.setdefault("cleanup", {})["state"] = state
        updated["journal"].append({"operation": source_operation, "resource": "cleanup", "timestamp": _utc_now()})
        self._commit(updated)

    def cleanup_plan(self, *, observed_bindings: dict) -> dict:
        """Return exact synthetic keys only after every recorded binding agrees."""
        expected = self.payload.get("resources") or {}
        for resource, entry in expected.items():
            if observed_bindings.get(resource) != entry.get("bindings", {}):
                raise ValueError("fixture binding mismatch")
        return deepcopy(expected)


def canonical_invitation_code(raw_code: str) -> str:
    """Return the one ASCII canonical code used for storage and UI input."""
    if not isinstance(raw_code, str):
        raise ValueError("invitation must be text")
    canonical = raw_code.strip().upper()
    if not _CANONICAL_INVITATION.fullmatch(canonical):
        raise ValueError("invalid invitation format")
    return canonical


def invitation_code_hash(raw_code: str) -> str:
    """Lowercase SHA-256 hex of canonical UTF-8 bytes, without a newline."""
    return hashlib.sha256(canonical_invitation_code(raw_code).encode("utf-8")).hexdigest()


def record_fixture_transaction_key(manifest: dict, transaction_key: str) -> None:
    """Add one exact Join transaction key to a synthetic fixture manifest.

    The live-fixture harness calls this immediately after a successful
    ``/begin`` response, before any later route or callback operation can make
    recovery necessary.  It is deliberately test-only and accepts only the
    opaque SHA-256 table key, never a continuation handle or invitation value.
    """
    if not isinstance(manifest, dict):
        raise ValueError("fixture manifest must be a dictionary")
    if not isinstance(transaction_key, str) or not _JOIN_TRANSACTION_KEY.fullmatch(transaction_key):
        raise ValueError("transaction key must be a lowercase SHA-256 hex value")

    dynamic = manifest.setdefault("dynamic", {})
    if not isinstance(dynamic, dict):
        raise ValueError("fixture manifest dynamic section must be a dictionary")
    transaction_keys = dynamic.setdefault("transaction_keys", [])
    if not isinstance(transaction_keys, list) or not all(isinstance(key, str) for key in transaction_keys):
        raise ValueError("fixture manifest transaction keys must be a list of strings")
    if transaction_key not in transaction_keys:
        transaction_keys.append(transaction_key)
