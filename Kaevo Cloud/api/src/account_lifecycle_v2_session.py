"""DPoP-bound protected-session authentication for Account Lifecycle V2."""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from security_identity import IdentityError, token_hash, verify_dpop


class LifecycleV2SessionError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _header(event: Mapping[str, Any], name: str) -> str:
    target = name.lower()
    for key, value in (event.get("headers") or {}).items():
        if str(key).lower() == target:
            return str(value or "")
    return ""


def _method(event: Mapping[str, Any]) -> str:
    return str(
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or "GET"
    ).upper()


def lifecycle_request_path(event: Mapping[str, Any]) -> str:
    """Return the route path without API Gateway's named-stage prefix.

    Production uses a named HTTP API stage (``production``).  API Gateway V2
    places that stage in ``rawPath`` for the execute-api invoke URL even though
    route matching and the iOS DPoP target use the path after the stage.  Keep
    one normalizer for authentication and routing so they cannot disagree.
    """
    path = str(event.get("rawPath") or event.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    stage = str((event.get("requestContext") or {}).get("stage") or "").strip("/")
    if stage and stage != "$default":
        prefix = f"/{stage}"
        if path == prefix:
            return "/"
        if path.startswith(prefix + "/"):
            return path[len(prefix):]
    return path


def _absolute_url(event: Mapping[str, Any], public_base_url: str) -> str:
    base = urlsplit(public_base_url)
    if (
        base.scheme != "https" or not base.hostname or base.username or base.password
        or base.query or base.fragment
    ):
        raise LifecycleV2SessionError("lifecycle_public_origin_invalid")
    path = lifecycle_request_path(event)
    origin = f"{base.scheme}://{base.netloc}"
    return f"{origin}{base.path.rstrip('/')}{path}"


class ProtectedLifecycleV2SessionAuthenticator:
    def __init__(
        self,
        *,
        app_sessions_table: Any,
        installations_table: Any,
        public_base_url: str,
        clock=None,
    ):
        self.app_sessions_table = app_sessions_table
        self.installations_table = installations_table
        self.public_base_url = public_base_url
        self.clock = clock or (lambda: int(time.time()))

    def authenticate(self, event: Mapping[str, Any]) -> dict[str, Any]:
        authorization = _header(event, "authorization")
        if not authorization.lower().startswith("bearer "):
            raise LifecycleV2SessionError("protected_session_required")
        token = authorization[7:].strip()
        if not token:
            raise LifecycleV2SessionError("protected_session_required")
        key = f"access#{token_hash(token)}"
        session = self.app_sessions_table.get_item(
            Key={"token_hash": key}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(session, Mapping) or session.get("record_type") != "access":
            raise LifecycleV2SessionError("protected_session_required")
        if (
            session.get("state") != "active"
            or bool(session.get("revoked", False))
            or int(session.get("expires_at") or 0) <= int(self.clock())
        ):
            raise LifecycleV2SessionError("protected_session_expired")
        required = ("account_id", "principal_id", "installation_id", "family_id", "key_thumbprint")
        if any(not str(session.get(key) or "") for key in required):
            raise LifecycleV2SessionError("protected_session_invalid")
        installation = self.installations_table.get_item(
            Key={"installation_id": str(session["installation_id"])}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(installation, Mapping)
            or installation.get("state") != "active"
            or bool(installation.get("revoked", False))
        ):
            raise LifecycleV2SessionError("installation_binding_unavailable")

        def replay_guard(jti: str, expires_at: int) -> bool:
            try:
                self.app_sessions_table.put_item(
                    Item={
                        "token_hash": "dpop#" + hashlib.sha256(jti.encode("utf-8")).hexdigest(),
                        "record_type": "dpop_replay",
                        "expires_at": int(expires_at),
                    },
                    ConditionExpression="attribute_not_exists(token_hash)",
                )
                return True
            except ClientError as error:
                if str((error.response or {}).get("Error", {}).get("Code") or "") == "ConditionalCheckFailedException":
                    return False
                raise

        try:
            verify_dpop(
                _header(event, "dpop"),
                method=_method(event),
                url=_absolute_url(event, self.public_base_url),
                expected_thumbprint=str(session["key_thumbprint"]),
                access_token=token,
                replay_guard=replay_guard,
                now=int(self.clock()),
            )
        except IdentityError as error:
            raise LifecycleV2SessionError("protected_session_proof_invalid") from error
        return dict(session)
