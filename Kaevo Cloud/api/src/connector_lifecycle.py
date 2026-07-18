"""Authoritative Home connector lifecycle state and atomic transitions."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
import uuid
from typing import Any, Mapping

from botocore.exceptions import ClientError

from security_audit import prepare_audit_item, principal_ref


INTENT_TTL_SECONDS = 10 * 60
SERVER_ID = re.compile(r"^srv_[A-Za-z0-9_-]{24,96}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
OPERATIONS = frozenset({"pair", "rotate", "recover", "unpair"})
PENDING_STATE = {
    "pair": "pending_pairing",
    "rotate": "rotation_pending",
    "recover": "recovery_pending",
    "unpair": "unpair_pending",
}


class LifecycleError(RuntimeError):
    def __init__(self, reason: str, status_code: int = 409):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


def _now_iso(now: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def binding_key(server_id: str) -> str:
    return f"server_binding#{server_id}"


def intent_key(intent_id: str) -> str:
    return f"connector_intent#{intent_id}"


def require_server_id(value: Any) -> str:
    server_id = str(value or "").strip()
    if not SERVER_ID.fullmatch(server_id):
        raise LifecycleError("invalid_server_challenge", 400)
    return server_id


def require_nonce(value: Any) -> str:
    nonce = str(value or "").strip()
    if not NONCE.fullmatch(nonce):
        raise LifecycleError("invalid_server_challenge", 400)
    return nonce


def _transact(client: Any, items: list[dict[str, Any]]) -> None:
    try:
        client.transact_write_items(TransactItems=items)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {
            "TransactionCanceledException", "ConditionalCheckFailedException"
        }:
            raise LifecycleError("lifecycle_conflict") from error
        raise


def _audit_put(table: Any, audit: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "Put": {
            "TableName": table.name,
            "Item": dict(audit),
            "ConditionExpression": "attribute_not_exists(event_id)",
        }
    }


def create_pairing_intent(
    *,
    client: Any,
    connectors: Any,
    intents: Any,
    audits: Any,
    identity: Any,
    environment: str,
    server_id: str,
    local_nonce: str,
    public_jwk_json: str,
    key_thumbprint: str,
    recovery_public_jwk_json: str,
    recovery_thumbprint: str,
    connector_name: str,
    pairing_code: str,
    request_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    server_id = require_server_id(server_id)
    local_nonce = require_nonce(local_nonce)
    connector_id = str(uuid.uuid4())
    intent_id = str(uuid.uuid4())
    expires_at = current + INTENT_TTL_SECONDS
    created_at = _now_iso(current)
    owner_ref = principal_ref(identity.subject)
    connector = {
        "connector_id": connector_id,
        "record_type": "home_connector",
        "environment": environment,
        "account_id": identity.account_id,
        "household_id": identity.household_id,
        "profile_id": identity.profile_id,
        "server_id": server_id,
        "server_generation": 1,
        "connector_name": str(connector_name or "Kaevo Home Server")[:80],
        "state": "pending_pairing",
        "auth_state": "pending_pairing",
        "credential_version": 0,
        "max_issued_credential_version": 0,
        "revocation_version": 0,
        "proposed_public_jwk_json": public_jwk_json,
        "proposed_key_thumbprint": key_thumbprint,
        "recovery_public_jwk_json": recovery_public_jwk_json,
        "recovery_key_thumbprint": recovery_thumbprint,
        "pending_intent_id": intent_id,
        "pending_intent_expires_at": expires_at,
        "pairing_code_hash": _hash(pairing_code),
        "revoked": False,
        "created_at": created_at,
        "updated_at": created_at,
        "last_seen_at": "",
        "last_seen_epoch": 0,
        "capabilities_json": "[]",
        "provider_status_json": "{}",
    }
    binding = {
        "connector_id": binding_key(server_id),
        "record_type": "server_binding",
        "server_id": server_id,
        "environment": environment,
        "account_id": identity.account_id,
        "household_id": identity.household_id,
        "active_connector_id": connector_id,
        "server_generation": 1,
        "state": "reserved",
        "created_at": created_at,
        "updated_at": created_at,
    }
    intent = {
        "token_hash": intent_key(intent_id),
        "record_type": "connector_lifecycle_intent",
        "intent_id": intent_id,
        "operation": "pair",
        "state": "pending",
        "environment": environment,
        "account_id": identity.account_id,
        "household_id": identity.household_id,
        "owner_principal_ref": owner_ref,
        "server_id": server_id,
        "connector_id": connector_id,
        "current_version": 0,
        "target_version": 1,
        "current_thumbprint": "",
        "proposed_thumbprint": key_thumbprint,
        "local_nonce_hash": _hash(local_nonce),
        "pairing_code_hash": _hash(pairing_code),
        "issued_at": current,
        "expires_at": expires_at,
        "created_at": created_at,
    }
    audit = prepare_audit_item(
        scope_id=identity.household_id,
        event_type="connector_pairing_intent_created",
        actor_subject=identity.subject,
        target_id=connector_id,
        target_type="connector",
        request_id=request_id,
        now=current,
    )
    _transact(client, [
        {"Put": {"TableName": connectors.name, "Item": binding, "ConditionExpression": "attribute_not_exists(connector_id)"}},
        {"Put": {"TableName": connectors.name, "Item": connector, "ConditionExpression": "attribute_not_exists(connector_id)"}},
        {"Put": {"TableName": intents.name, "Item": intent, "ConditionExpression": "attribute_not_exists(token_hash)"}},
        _audit_put(audits, audit),
    ])
    return {"connector": connector, "intent": intent}


def create_update_intent(
    *, operation: str, client: Any, connectors: Any, intents: Any, audits: Any,
    identity: Any, environment: str, connector: Mapping[str, Any], local_nonce: str,
    proposed_public_jwk_json: str, proposed_thumbprint: str, request_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    if operation not in {"rotate", "recover"}:
        raise LifecycleError("invalid_lifecycle_operation", 400)
    current = int(time.time()) if now is None else int(now)
    local_nonce = require_nonce(local_nonce)
    if connector.get("state") != "active" or bool(connector.get("revoked")):
        raise LifecycleError("connector_unavailable", 404)
    if any(not hmac.compare_digest(str(connector.get(key) or ""), str(expected)) for key, expected in (
        ("environment", environment), ("account_id", identity.account_id),
        ("household_id", identity.household_id), ("profile_id", identity.profile_id),
    )):
        raise LifecycleError("connector_unavailable", 404)
    version = int(connector.get("credential_version") or 0)
    maximum = int(connector.get("max_issued_credential_version") or 0)
    if version < 1 or maximum != version:
        raise LifecycleError("connector_version_invalid")
    intent_id = str(uuid.uuid4())
    expires_at = current + INTENT_TTL_SECONDS
    updated = dict(connector)
    updated.update({
        "state": PENDING_STATE[operation], "auth_state": PENDING_STATE[operation],
        "pending_intent_id": intent_id, "pending_intent_expires_at": expires_at,
        "proposed_public_jwk_json": proposed_public_jwk_json,
        "proposed_key_thumbprint": proposed_thumbprint, "updated_at": _now_iso(current),
    })
    intent = {
        "token_hash": intent_key(intent_id), "record_type": "connector_lifecycle_intent",
        "intent_id": intent_id, "operation": operation, "state": "pending",
        "environment": environment, "account_id": identity.account_id,
        "household_id": identity.household_id, "owner_principal_ref": principal_ref(identity.subject),
        "server_id": connector["server_id"], "connector_id": connector["connector_id"],
        "current_version": version, "target_version": version + 1,
        "current_thumbprint": connector["key_thumbprint"],
        "proposed_thumbprint": proposed_thumbprint, "local_nonce_hash": _hash(local_nonce),
        "issued_at": current, "expires_at": expires_at, "created_at": _now_iso(current),
    }
    audit = prepare_audit_item(
        scope_id=identity.household_id, event_type=f"connector_{operation}_intent_created",
        actor_subject=identity.subject, target_id=connector["connector_id"],
        target_type="connector", request_id=request_id, now=current,
    )
    _transact(client, [
        {"Put": {"TableName": connectors.name, "Item": updated,
                 "ConditionExpression": "#s = :active AND credential_version = :version AND max_issued_credential_version = :version",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":active": "active", ":version": version}}},
        {"Put": {"TableName": intents.name, "Item": intent, "ConditionExpression": "attribute_not_exists(token_hash)"}},
        _audit_put(audits, audit),
    ])
    return intent


def create_unpair_intent(
    *, client: Any, connectors: Any, intents: Any, audits: Any, identity: Any,
    environment: str, connector: Mapping[str, Any], local_nonce: str,
    request_id: str, now: int | None = None,
) -> dict[str, Any]:
    """Prepare an explicit destructive unpair without releasing the binding yet."""
    current = int(time.time()) if now is None else int(now)
    local_nonce = require_nonce(local_nonce)
    if connector.get("state") not in {"active", "revoked"}:
        raise LifecycleError("connector_unavailable", 404)
    if any(not hmac.compare_digest(str(connector.get(key) or ""), str(expected)) for key, expected in (
        ("environment", environment), ("account_id", identity.account_id),
        ("household_id", identity.household_id), ("profile_id", identity.profile_id),
    )):
        raise LifecycleError("connector_unavailable", 404)
    intent_id = str(uuid.uuid4())
    expires_at = current + INTENT_TTL_SECONDS
    prior_state = str(connector["state"])
    updated = dict(connector)
    updated.update({
        "state": "unpair_pending", "auth_state": "unpair_pending",
        "pending_intent_id": intent_id, "pending_intent_expires_at": expires_at,
        "updated_at": _now_iso(current),
    })
    intent = {
        "token_hash": intent_key(intent_id), "record_type": "connector_lifecycle_intent",
        "intent_id": intent_id, "operation": "unpair", "state": "pending",
        "environment": environment, "account_id": identity.account_id,
        "household_id": identity.household_id, "owner_principal_ref": principal_ref(identity.subject),
        "server_id": connector["server_id"], "connector_id": connector["connector_id"],
        "current_version": int(connector.get("credential_version") or 0),
        "target_version": int(connector.get("credential_version") or 0),
        "current_thumbprint": str(connector.get("key_thumbprint") or ""),
        "proposed_thumbprint": "", "local_nonce_hash": _hash(local_nonce),
        "prior_state": prior_state, "prior_auth_state": str(connector.get("auth_state") or prior_state),
        "prior_revoked": bool(connector.get("revoked")),
        "issued_at": current, "expires_at": expires_at, "created_at": _now_iso(current),
    }
    audit = prepare_audit_item(
        scope_id=identity.household_id, event_type="connector_unpair_intent_created",
        actor_subject=identity.subject, target_id=str(connector["connector_id"]),
        target_type="connector", request_id=request_id, now=current,
    )
    _transact(client, [
        {"Put": {"TableName": connectors.name, "Item": updated,
                 "ConditionExpression": "#s = :prior AND attribute_not_exists(pending_intent_id)",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":prior": prior_state}}},
        {"Put": {"TableName": intents.name, "Item": intent,
                 "ConditionExpression": "attribute_not_exists(token_hash)"}},
        _audit_put(audits, audit),
    ])
    return intent


def activate_unpair_intent(
    *, client: Any, connectors: Any, intents: Any, audits: Any, identity: Any,
    environment: str, intent: Mapping[str, Any], connector: Mapping[str, Any],
    local_nonce: str, request_id: str, now: int | None = None,
) -> dict[str, Any]:
    """Permanently tombstone the connector and atomically release its server binding."""
    current = int(time.time()) if now is None else int(now)
    if (intent.get("operation") != "unpair" or intent.get("state") != "pending"
            or int(intent.get("expires_at") or 0) < current):
        raise LifecycleError("lifecycle_intent_invalid", 401)
    if not hmac.compare_digest(str(intent.get("local_nonce_hash") or ""), _hash(require_nonce(local_nonce))):
        raise LifecycleError("lifecycle_intent_invalid", 401)
    if any(not hmac.compare_digest(str(intent.get(key) or ""), str(expected)) for key, expected in (
        ("environment", environment), ("account_id", identity.account_id),
        ("household_id", identity.household_id), ("connector_id", connector.get("connector_id")),
        ("server_id", connector.get("server_id")),
    )):
        raise LifecycleError("lifecycle_intent_invalid", 401)
    if connector.get("state") != "unpair_pending" or connector.get("pending_intent_id") != intent.get("intent_id"):
        raise LifecycleError("lifecycle_conflict")
    binding_id = binding_key(str(connector["server_id"]))
    tombstone = dict(connector)
    for key in ("pending_intent_id", "pending_intent_expires_at", "public_jwk_json",
                "key_thumbprint", "recovery_public_jwk_json", "recovery_key_thumbprint",
                "playback_grant_key", "connector_token_hash"):
        tombstone.pop(key, None)
    tombstone.update({
        "state": "unpaired", "auth_state": "unpaired", "revoked": True,
        "revocation_version": int(connector.get("revocation_version") or 0) + 1,
        "unpaired_at": _now_iso(current), "updated_at": _now_iso(current),
    })
    consumed = dict(intent)
    consumed.update({"state": "consumed", "consumed_at": _now_iso(current), "expires_at": current + 3600})
    audit = prepare_audit_item(
        scope_id=identity.household_id, event_type="connector_unpaired",
        actor_subject=identity.subject, target_id=str(connector["connector_id"]),
        target_type="connector", request_id=request_id, now=current,
    )
    _transact(client, [
        {"Put": {"TableName": connectors.name, "Item": tombstone,
                 "ConditionExpression": "#s = :pending AND pending_intent_id = :intent",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":pending": "unpair_pending", ":intent": intent["intent_id"]}}},
        {"Delete": {"TableName": connectors.name, "Key": {"connector_id": binding_id},
                    "ConditionExpression": "active_connector_id = :connector",
                    "ExpressionAttributeValues": {":connector": connector["connector_id"]}}},
        {"Put": {"TableName": intents.name, "Item": consumed,
                 "ConditionExpression": "#s = :pending",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":pending": "pending"}}},
        _audit_put(audits, audit),
    ])
    return tombstone


def activate_intent(
    *, client: Any, connectors: Any, intents: Any, audits: Any, environment: str,
    intent: Mapping[str, Any], connector: Mapping[str, Any], local_nonce: str,
    public_jwk_json: str, proposed_thumbprint: str, request_id: str,
    now: int | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    operation = str(intent.get("operation") or "")
    if operation not in OPERATIONS or intent.get("state") != "pending" or int(intent.get("expires_at") or 0) < current:
        raise LifecycleError("lifecycle_intent_invalid", 401)
    if not hmac.compare_digest(str(intent.get("local_nonce_hash") or ""), _hash(require_nonce(local_nonce))):
        raise LifecycleError("lifecycle_intent_invalid", 401)
    if any(not hmac.compare_digest(str(intent.get(key) or ""), str(expected)) for key, expected in (
        ("environment", environment), ("connector_id", connector.get("connector_id")),
        ("server_id", connector.get("server_id")), ("proposed_thumbprint", proposed_thumbprint),
    )):
        raise LifecycleError("lifecycle_intent_invalid", 401)
    current_version = int(intent.get("current_version") or 0)
    target_version = int(intent.get("target_version") or 0)
    if target_version != current_version + 1 or int(connector.get("max_issued_credential_version") or 0) != current_version:
        raise LifecycleError("lifecycle_version_invalid")
    expected_state = PENDING_STATE[operation]
    if connector.get("state") != expected_state or connector.get("pending_intent_id") != intent.get("intent_id"):
        raise LifecycleError("lifecycle_conflict")
    updated = dict(connector)
    for key in ("proposed_public_jwk_json", "proposed_key_thumbprint", "pending_intent_id", "pending_intent_expires_at", "pairing_code_hash"):
        updated.pop(key, None)
    updated.update({
        "state": "active", "auth_state": "active", "credential_version": target_version,
        "max_issued_credential_version": target_version, "public_jwk_json": public_jwk_json,
        "key_thumbprint": proposed_thumbprint, "revoked": False,
        "updated_at": _now_iso(current), f"{operation}d_at" if operation != "pair" else "activated_at": _now_iso(current),
    })
    consumed = dict(intent)
    consumed.update({"state": "consumed", "consumed_at": _now_iso(current), "expires_at": current + 3600})
    binding = connectors.get_item(Key={"connector_id": binding_key(str(connector["server_id"]))}, ConsistentRead=True).get("Item")
    if not binding or binding.get("active_connector_id") != connector.get("connector_id"):
        raise LifecycleError("server_binding_invalid")
    binding_updated = dict(binding)
    binding_updated.update({"state": "active", "updated_at": _now_iso(current)})
    audit = prepare_audit_item(
        scope_id=str(connector["household_id"]), event_type=f"connector_{operation}ed",
        actor_subject=str(connector["connector_id"]), actor_type="connector",
        target_id=str(connector["connector_id"]), target_type="connector",
        request_id=request_id, now=current,
    )
    _transact(client, [
        {"Put": {"TableName": connectors.name, "Item": updated,
                 "ConditionExpression": "#s = :expected AND credential_version = :current AND max_issued_credential_version = :current AND pending_intent_id = :intent",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":expected": expected_state, ":current": current_version, ":intent": intent["intent_id"]}}},
        {"Put": {"TableName": connectors.name, "Item": binding_updated,
                 "ConditionExpression": "active_connector_id = :connector",
                 "ExpressionAttributeValues": {":connector": connector["connector_id"]}}},
        {"Put": {"TableName": intents.name, "Item": consumed,
                 "ConditionExpression": "#s = :pending",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":pending": "pending"}}},
        _audit_put(audits, audit),
    ])
    return updated


def opaque_intent(intents: Any, intent_id: str) -> dict[str, Any]:
    return intents.get_item(Key={"token_hash": intent_key(intent_id)}, ConsistentRead=True).get("Item") or {}


def cancel_intent(
    *, client: Any, connectors: Any, intents: Any, audits: Any, identity: Any,
    intent: Mapping[str, Any], connector: Mapping[str, Any], request_id: str,
    now: int | None = None,
) -> None:
    current = int(time.time()) if now is None else int(now)
    operation = str(intent.get("operation") or "")
    if operation not in OPERATIONS or intent.get("state") != "pending":
        raise LifecycleError("lifecycle_intent_invalid", 401)
    if any(not hmac.compare_digest(str(intent.get(key) or ""), str(expected)) for key, expected in (
        ("account_id", identity.account_id), ("household_id", identity.household_id),
        ("connector_id", connector.get("connector_id")), ("server_id", connector.get("server_id")),
    )):
        raise LifecycleError("lifecycle_intent_invalid", 401)
    canceled = dict(intent)
    canceled.update({"state": "canceled", "consumed_at": _now_iso(current), "expires_at": current + 3600})
    audit = prepare_audit_item(
        scope_id=identity.household_id, event_type=f"connector_{operation}_intent_canceled",
        actor_subject=identity.subject, target_id=str(connector["connector_id"]),
        target_type="connector", request_id=request_id, now=current,
    )
    writes: list[dict[str, Any]] = []
    if operation == "pair":
        writes.extend([
            {"Delete": {"TableName": connectors.name, "Key": {"connector_id": connector["connector_id"]},
                        "ConditionExpression": "#s = :pending AND pending_intent_id = :intent",
                        "ExpressionAttributeNames": {"#s": "state"},
                        "ExpressionAttributeValues": {":pending": "pending_pairing", ":intent": intent["intent_id"]}}},
            {"Delete": {"TableName": connectors.name, "Key": {"connector_id": binding_key(str(connector["server_id"]))},
                        "ConditionExpression": "#s = :reserved AND active_connector_id = :connector",
                        "ExpressionAttributeNames": {"#s": "state"},
                        "ExpressionAttributeValues": {":reserved": "reserved", ":connector": connector["connector_id"]}}},
        ])
    else:
        restored = dict(connector)
        for key in ("pending_intent_id", "pending_intent_expires_at", "proposed_public_jwk_json", "proposed_key_thumbprint"):
            restored.pop(key, None)
        if operation == "unpair":
            restored.update({
                "state": str(intent.get("prior_state") or "revoked"),
                "auth_state": str(intent.get("prior_auth_state") or intent.get("prior_state") or "revoked"),
                "revoked": bool(intent.get("prior_revoked")), "updated_at": _now_iso(current),
            })
        else:
            restored.update({"state": "active", "auth_state": "active", "updated_at": _now_iso(current)})
        writes.append({"Put": {"TableName": connectors.name, "Item": restored,
                               "ConditionExpression": "#s = :pending AND pending_intent_id = :intent",
                               "ExpressionAttributeNames": {"#s": "state"},
                               "ExpressionAttributeValues": {":pending": PENDING_STATE[operation], ":intent": intent["intent_id"]}}})
    writes.extend([
        {"Put": {"TableName": intents.name, "Item": canceled,
                 "ConditionExpression": "#s = :pending",
                 "ExpressionAttributeNames": {"#s": "state"},
                 "ExpressionAttributeValues": {":pending": "pending"}}},
        _audit_put(audits, audit),
    ])
    _transact(client, writes)


def random_pairing_code() -> str:
    return "-".join(secrets.token_hex(2).upper() for _ in range(3))
