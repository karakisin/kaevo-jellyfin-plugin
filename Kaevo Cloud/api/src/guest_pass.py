"""Guest Pass policy primitives.

This module contains no AWS calls. The API handler owns authoritative identity
and conditional writes; keeping normalization here makes every route and test
share one fail-closed contract.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any, Mapping


PASS_ID_PATTERN = re.compile(r"guest_[A-Za-z0-9_-]{16,128}")
MEDIA_ID_PATTERN = re.compile(r"[A-Fa-f0-9]{32}")
DEVICE_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{8,128}")
MAX_ACTIVE_PASSES = 3
MAX_SCOPE_ENTRIES = 500
MIN_DURATION_SECONDS = 15 * 60
MAX_DURATION_SECONDS = 30 * 24 * 60 * 60
MAX_START_WINDOW_SECONDS = 30 * 24 * 60 * 60
CLAIM_TOKEN_BYTES = 32

PERMISSION_KEYS = (
    "browse_granted_content",
    "search_granted_content",
    "search_full_library",
    "request_content",
    "casting",
    "mark_watched",
    "change_audio_subtitles",
)


@dataclass(frozen=True)
class GuestPassValidationError(ValueError):
    state: str

    def __str__(self) -> str:
        return self.state


def _bounded_text(value: Any, *, minimum: int, maximum: int, state: str) -> str:
    text = str(value or "").strip()
    if not minimum <= len(text) <= maximum or any(ord(char) < 32 for char in text):
        raise GuestPassValidationError(state)
    return text


def _integer(value: Any, *, state: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GuestPassValidationError(state)
    return value


def normalize_create_request(body: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    if not isinstance(body, Mapping):
        raise GuestPassValidationError("invalid_guest_pass")

    guest_name = _bounded_text(
        body.get("guest_name"), minimum=1, maximum=50, state="invalid_guest_name"
    )
    source_profile_id = _bounded_text(
        body.get("source_profile_id"),
        minimum=8,
        maximum=128,
        state="invalid_source_profile",
    )
    if not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", source_profile_id):
        raise GuestPassValidationError("invalid_source_profile")

    start_by = _integer(body.get("start_by"), state="invalid_start_by")
    if start_by <= now or start_by > now + MAX_START_WINDOW_SECONDS:
        raise GuestPassValidationError("invalid_start_by")

    expiration = body.get("expiration")
    if not isinstance(expiration, Mapping):
        raise GuestPassValidationError("invalid_expiration")
    expiration_kind = str(expiration.get("kind") or "").strip()
    if expiration_kind == "duration_after_first_play":
        duration = _integer(expiration.get("seconds"), state="invalid_expiration")
        if not MIN_DURATION_SECONDS <= duration <= MAX_DURATION_SECONDS:
            raise GuestPassValidationError("invalid_expiration")
        normalized_expiration = {"kind": expiration_kind, "seconds": duration}
    elif expiration_kind == "fixed":
        fixed_at = _integer(expiration.get("at"), state="invalid_expiration")
        if fixed_at <= now or fixed_at > now + MAX_DURATION_SECONDS:
            raise GuestPassValidationError("invalid_expiration")
        normalized_expiration = {"kind": expiration_kind, "at": fixed_at}
    else:
        raise GuestPassValidationError("invalid_expiration")

    scope = body.get("scope")
    if not isinstance(scope, Mapping):
        raise GuestPassValidationError("invalid_scope")
    scope_kind = str(scope.get("kind") or "").strip()
    if scope_kind not in {"full_library", "movies", "shows", "seasons", "episodes", "custom"}:
        raise GuestPassValidationError("invalid_scope")
    raw_entries = scope.get("entries") or []
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_SCOPE_ENTRIES:
        raise GuestPassValidationError("invalid_scope")
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            raise GuestPassValidationError("invalid_scope")
        entry_kind = str(raw_entry.get("kind") or "").strip()
        item_id = str(raw_entry.get("item_id") or "").strip().lower()
        if entry_kind not in {"movie", "show", "season", "episode"} or not MEDIA_ID_PATTERN.fullmatch(item_id):
            raise GuestPassValidationError("invalid_scope")
        key = (entry_kind, item_id)
        if key in seen:
            raise GuestPassValidationError("invalid_scope")
        seen.add(key)
        entries.append({"kind": entry_kind, "item_id": item_id})
    if scope_kind == "full_library":
        if entries:
            raise GuestPassValidationError("invalid_scope")
    elif not entries:
        raise GuestPassValidationError("invalid_scope")

    permissions = body.get("permissions") or {}
    if not isinstance(permissions, Mapping):
        raise GuestPassValidationError("invalid_permissions")
    if any(key not in PERMISSION_KEYS for key in permissions):
        raise GuestPassValidationError("invalid_permissions")
    normalized_permissions = {}
    for key in PERMISSION_KEYS:
        value = permissions.get(key, False)
        if not isinstance(value, bool):
            raise GuestPassValidationError("invalid_permissions")
        normalized_permissions[key] = value

    replay_policy = str(body.get("replay_policy") or "").strip()
    if replay_policy not in {"unlimited_until_expiration", "one_completed_view"}:
        raise GuestPassValidationError("invalid_replay_policy")
    expiration_behavior = str(body.get("expiration_behavior") or "").strip()
    if expiration_behavior not in {"hard_stop", "finish_current_video"}:
        raise GuestPassValidationError("invalid_expiration_behavior")

    pin = body.get("pin")
    if pin is not None and not re.fullmatch(r"\d{4}", str(pin)):
        raise GuestPassValidationError("invalid_pin")

    return {
        "guest_name": guest_name,
        "source_profile_id": source_profile_id,
        "start_by": start_by,
        "expiration": normalized_expiration,
        "scope": {"kind": scope_kind, "entries": entries},
        "permissions": normalized_permissions,
        "replay_policy": replay_policy,
        "expiration_behavior": expiration_behavior,
        "pin": str(pin) if pin is not None else None,
    }


def new_claim_secret() -> str:
    return secrets.token_urlsafe(CLAIM_TOKEN_BYTES)


def secret_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def pin_record(pin: str | None) -> tuple[str, str]:
    if pin is None:
        return "", ""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(pin.encode("ascii"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex(), digest.hex()


def pin_matches(pin: Any, salt_hex: str, digest_hex: str) -> bool:
    if not salt_hex and not digest_hex:
        return pin in {None, ""}
    if not re.fullmatch(r"\d{4}", str(pin or "")):
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    candidate = hashlib.scrypt(str(pin).encode("ascii"), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate, expected)


def effective_state(item: Mapping[str, Any], *, now: int) -> str:
    state = str(item.get("state") or "pending")
    if state in {"revoked", "completed", "expired"}:
        return state
    start_by = int(item.get("start_by") or 0)
    if not item.get("started_at") and start_by < now:
        return "expired"
    expiration = item.get("expiration") or {}
    fixed_expiration = (
        int(expiration.get("at") or 0)
        if isinstance(expiration, Mapping) and expiration.get("kind") == "fixed"
        else 0
    )
    expires_at = int(item.get("access_expires_at") or fixed_expiration or 0)
    if expires_at and expires_at < now:
        return "expired"
    return state


def public_projection(item: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    raw_progress = item.get("progress_by_item") or {}
    progress_by_item = {
        str(item_id).lower(): {
            "position_ticks": max(0, int((value or {}).get("position_ticks") or 0)),
            "runtime_ticks": max(0, int((value or {}).get("runtime_ticks") or 0)),
            "completed": bool((value or {}).get("completed")),
            "updated_at": str((value or {}).get("updated_at") or ""),
        }
        for item_id, value in list(raw_progress.items())[:MAX_SCOPE_ENTRIES]
        if MEDIA_ID_PATTERN.fullmatch(str(item_id or "")) and isinstance(value, Mapping)
    } if isinstance(raw_progress, Mapping) else {}
    return {
        "pass_id": str(item.get("pass_id") or ""),
        "guest_name": str(item.get("guest_name") or "Guest"),
        "owner_display_name": str(item.get("owner_display_name") or "Owner"),
        "state": effective_state(item, now=now),
        "created_at": str(item.get("created_at") or ""),
        "claimed_at": item.get("claimed_at"),
        "started_at": item.get("started_at"),
        "start_by": int(item.get("start_by") or 0),
        "access_expires_at": int(item.get("access_expires_at") or 0) or None,
        "expiration": item.get("expiration") or {},
        "expiration_behavior": str(item.get("expiration_behavior") or "hard_stop"),
        "replay_policy": str(item.get("replay_policy") or "unlimited_until_expiration"),
        "scope": item.get("scope") or {},
        "permissions": item.get("permissions") or {},
        "device_bound": bool(item.get("device_id")),
        "progress": progress_by_item,
    }


def scope_authorizes(
    scope: Mapping[str, Any],
    *,
    item_id: str,
    item_kind: str,
    ancestor_ids: Mapping[str, str] | None = None,
) -> bool:
    """Authorize an exact item using server-resolved immutable ancestry.

    The caller must obtain ``ancestor_ids`` from Jellyfin through the trusted
    connector. Client-supplied parent/show IDs are never authority.
    """
    if not MEDIA_ID_PATTERN.fullmatch(str(item_id or "")):
        return False
    if str(scope.get("kind") or "") == "full_library":
        return True
    candidates = {(str(item_kind), str(item_id).lower())}
    for kind, ancestor_id in (ancestor_ids or {}).items():
        if kind in {"show", "season"} and MEDIA_ID_PATTERN.fullmatch(str(ancestor_id or "")):
            candidates.add((kind, str(ancestor_id).lower()))
    allowed = {
        (str(entry.get("kind") or ""), str(entry.get("item_id") or "").lower())
        for entry in scope.get("entries") or []
        if isinstance(entry, Mapping)
    }
    return bool(candidates & allowed)
