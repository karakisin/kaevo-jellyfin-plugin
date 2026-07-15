from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_signed_token(token: str, signing_key: str, *, clock=time.time, allow_expired: bool = False) -> dict[str, Any]:
    if len(signing_key) < 32:
        raise ValueError("relaySigningKeyTooShort")
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(signing_key.encode(), encoded.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_decode(signature), expected):
            raise ValueError("relayTokenSignatureInvalid")
        payload = json.loads(_decode(encoded))
    except ValueError:
        raise
    except Exception:
        raise ValueError("relayTokenMalformed") from None
    now = int(clock())
    if now < int(payload.get("nbf") or 0):
        raise ValueError("relayTokenNotYetValid")
    if not allow_expired and now >= int(payload.get("exp") or 0):
        raise ValueError("relayTokenExpired")
    return payload
