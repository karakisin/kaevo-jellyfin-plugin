"""Narrow signed status credential for a confirmed V2 deletion operation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Mapping


class LifecycleV2StatusTokenError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class LifecycleV2StatusTokenCodec:
    def __init__(self, secret: str, *, clock=None, ttl_seconds: int = 15 * 60):
        if len(secret.encode("utf-8")) < 32:
            raise LifecycleV2StatusTokenError("status_token_configuration_invalid")
        self.secret = secret.encode("utf-8")
        self.clock = clock or (lambda: int(time.time()))
        self.ttl_seconds = ttl_seconds

    def issue(self, *, operation_id: str, account_id: str) -> str:
        payload = json.dumps({
            "v": 2,
            "operation_id": operation_id,
            "account_id": account_id,
            "exp": int(self.clock()) + self.ttl_seconds,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = _encode(payload)
        signature = _encode(hmac.new(self.secret, encoded.encode("ascii"), hashlib.sha256).digest())
        return f"alst2.{encoded}.{signature}"

    def verify(self, token: str, *, expected_operation_id: str) -> Mapping[str, Any]:
        try:
            prefix, encoded, supplied = token.split(".", 2)
            expected = _encode(hmac.new(
                self.secret, encoded.encode("ascii"), hashlib.sha256,
            ).digest())
            if prefix != "alst2" or not hmac.compare_digest(supplied, expected):
                raise LifecycleV2StatusTokenError("status_token_invalid")
            payload = json.loads(_decode(encoded))
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise LifecycleV2StatusTokenError("status_token_invalid") from error
        if (
            not isinstance(payload, Mapping)
            or int(payload.get("v") or 0) != 2
            or str(payload.get("operation_id") or "") != expected_operation_id
            or not str(payload.get("account_id") or "")
            or int(payload.get("exp") or 0) <= int(self.clock())
        ):
            raise LifecycleV2StatusTokenError("status_token_invalid")
        return payload
