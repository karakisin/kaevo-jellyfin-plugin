"""Privacy-safe security-audit references and records.

Audit references are correlation-only pseudonyms.  They are deliberately not
accepted by any identity, authorization, session, or application lookup path.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from typing import Any, Callable

import boto3


AUDIT_SCHEMA_VERSION = 1
AUDIT_RETENTION_SECONDS = 400 * 24 * 60 * 60
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_secret_cache: dict[str, bytes] = {}


class AuditReferenceError(RuntimeError):
    """Raised when a privacy-safe audit record cannot be prepared."""


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise AuditReferenceError("audit_configuration_unavailable")
    return value


def _decode_secret(value: str) -> bytes:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        value = str(parsed.get("audit_reference_key") or "")
    raw = value.encode("utf-8")
    if len(raw) < 32:
        raise AuditReferenceError("audit_key_unavailable")
    return raw


def load_audit_key(*, client: Any | None = None) -> bytes:
    secret_arn = _required_environment("AUDIT_REFERENCE_SECRET_ARN")
    if secret_arn in _secret_cache:
        return _secret_cache[secret_arn]
    secrets_client = client or boto3.client("secretsmanager")
    try:
        response = secrets_client.get_secret_value(SecretId=secret_arn)
        if response.get("SecretString") is not None:
            key = _decode_secret(str(response["SecretString"]))
        else:
            encoded = response.get("SecretBinary")
            raw = base64.b64decode(encoded) if encoded else b""
            if len(raw) < 32:
                raise AuditReferenceError("audit_key_unavailable")
            key = raw
    except AuditReferenceError:
        raise
    except Exception as error:
        raise AuditReferenceError("audit_key_unavailable") from error
    _secret_cache[secret_arn] = key
    return key


def clear_audit_key_cache() -> None:
    """Test hook; production code intentionally keeps a warm-runtime cache."""
    _secret_cache.clear()


def _digest(key: bytes, value: str) -> str:
    return base64.urlsafe_b64encode(
        hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")


def principal_ref(subject: str, *, key: bytes | None = None, issuer: str | None = None) -> str:
    canonical_issuer = issuer or _required_environment("EXPECTED_COGNITO_ISSUER")
    if not subject:
        raise AuditReferenceError("audit_actor_unavailable")
    return "apr1_" + _digest(key or load_audit_key(), f"{canonical_issuer}:{subject}")


def scoped_ref(kind: str, value: str, *, key: bytes | None = None, environment: str | None = None) -> str:
    if not _SAFE_CODE.fullmatch(kind) or not value:
        raise AuditReferenceError("audit_target_unavailable")
    canonical_environment = environment or _required_environment("KAEVO_ENV")
    return "asr1_" + _digest(
        key or load_audit_key(),
        f"kaevo-audit-v1:{canonical_environment}:{kind}:{value}",
    )


def _code(value: str, fallback: str) -> str:
    return value if _SAFE_CODE.fullmatch(value) else fallback


def prepare_audit_item(
    *,
    scope_id: str,
    event_type: str,
    actor_subject: str,
    actor_type: str = "cognito_subject",
    target_id: str = "",
    target_type: str = "",
    result: str = "success",
    reason_code: str = "",
    request_id: str = "",
    now: int | None = None,
    key: bytes | None = None,
    key_loader: Callable[[], bytes] | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    secret = key or (key_loader or load_audit_key)()
    safe_event = _code(event_type, "security_event")
    safe_actor_type = _code(actor_type, "security_actor")
    safe_result = _code(result, "unknown")
    scope = scoped_ref("household", scope_id, key=secret)
    correlation_seed = request_id or str(uuid.uuid4())
    item: dict[str, Any] = {
        # Compatibility attribute name: the value is a pseudonymous scope, not
        # a household identifier.  Keeping the key avoids a table replacement.
        "household_id": scope,
        "scope_ref": scope,
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "event_id": f"{current:010d}#event_{uuid.uuid4()}",
        "event_type": safe_event,
        "actor_ref": principal_ref(actor_subject, key=secret),
        "actor_type": safe_actor_type,
        "result": safe_result,
        "request_correlation_ref": "acr1_" + _digest(
            secret, f"kaevo-audit-request-v1:{correlation_seed}"
        ),
        "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current)),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current)),
        "expires_at": current + AUDIT_RETENTION_SECONDS,
    }
    if reason_code:
        item["reason_code"] = _code(reason_code, "security_policy_denied")
    if target_id and target_type:
        item["target_ref"] = scoped_ref(_code(target_type, "security_target"), target_id, key=secret)
        item["target_type"] = _code(target_type, "security_target")
    return item


def fallback_audit_item(*, event_type: str, result: str, reason_code: str, now: int | None = None) -> dict[str, Any]:
    """Non-correlatable record for containment paths when the key is unavailable."""
    current = int(time.time()) if now is None else int(now)
    nonce = secrets.token_urlsafe(24)
    return {
        "household_id": "asr0_unavailable",
        "scope_ref": "asr0_unavailable",
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "event_id": f"{current:010d}#event_{uuid.uuid4()}",
        "event_type": _code(event_type, "security_event"),
        "actor_ref": "apr0_unavailable",
        "actor_type": "unavailable",
        "result": _code(result, "unknown"),
        "reason_code": _code(reason_code, "audit_key_unavailable"),
        "request_correlation_ref": f"acr0_{nonce}",
        "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current)),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(current)),
        "expires_at": current + AUDIT_RETENTION_SECONDS,
    }


def write_audit_item(table: Any, item: dict[str, Any]) -> None:
    if table is None:
        raise AuditReferenceError("audit_storage_unavailable")
    table.put_item(Item=item)
