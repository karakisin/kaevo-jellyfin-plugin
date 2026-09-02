"""Least-privilege Pairing V3 connector-control Lambda.

This artifact handles only the six key-bound V3 connector operations.  It has
no owner-session, Cognito, Pairing Authorization signing, or legacy lifecycle
credential path.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from pairing_v3 import (
    PROTOCOL,
    PairingV3CryptoError,
    b64url_decode,
    canonical_json_digest,
    canonical_json_digest_preserving_number_lexemes,
    canonical_transcript,
    constant_time_equal,
    plugin_fingerprint,
    sha256_b64url,
    verify_ed25519,
)


KAEVO_ENV = os.environ.get("KAEVO_ENV", "dev").strip().lower()
HOME_CONNECTORS_TABLE = os.environ.get("HOME_CONNECTORS_TABLE", "")
REMOTE_REQUESTS_TABLE = os.environ.get("REMOTE_REQUESTS_TABLE", "")
BINDING_OPERATIONS_TABLE = os.environ.get("BINDING_OPERATIONS_TABLE", "")
APP_SESSIONS_TABLE = os.environ.get("APP_SESSIONS_TABLE", "")
IDENTITY_PROFILES_TABLE = os.environ.get("IDENTITY_PROFILES_TABLE", "")
REMOTE_PAYLOADS_BUCKET = os.environ.get("REMOTE_PAYLOADS_BUCKET", "")
PLAYBACK_GRANT_SIGNING_KEY = os.environ.get("PLAYBACK_GRANT_SIGNING_KEY", "")
PLAYBACK_RELAY_PUBLIC_URL = os.environ.get("PLAYBACK_RELAY_PUBLIC_URL", "").rstrip("/")

CONNECTOR_ONLINE_WINDOW_SECONDS = 120
CONNECTOR_NONCE_RETENTION_SECONDS = 24 * 60 * 60
PLUGIN_TIMESTAMP_SKEW_SECONDS = 60
CONNECTOR_CONTROL_PROTOCOL_VERSION = 2
LEGACY_RECOVERY_RETRY_SECONDS = 60
REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES = 180_000
REMOTE_RESPONSE_MAX_STORED_BYTES = 330_000
SAFE_FINGERPRINT = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
SAFE_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
ACCOUNT_LIFECYCLE_V2_PROVIDER_OPERATIONS = frozenset({
    "account_lifecycle_v2.seerr.delete_exact_identity",
    "account_lifecycle_v2.seerr.verify_exact_identity_absence",
    "account_lifecycle_v2.jellyfin.delete_exact_identity",
    "account_lifecycle_v2.jellyfin.verify_exact_identity_absence",
})
PROFILE_SCOPED_JELLYFIN_BINDING_OPERATIONS = frozenset({
    "jellyfin.mark_played",
    "jellyfin.mark_unplayed",
})
BINDING_OPERATION_PHASE_RANK = {
    "created": 0, "authorized": 1, "dispatch_pending": 2, "dispatched": 3,
    "connector_claimed": 4, "inspection_completed": 5, "mutation_authorized": 6,
    "plugin_cas_committed": 7, "cloud_persisted": 8, "snapshot_pending": 9,
    "snapshot_published": 10, "completed": 11, "safely_refused": 12,
    "reconciliation_required": 12, "failed_retryable": 12, "failed_terminal": 12,
}

dynamodb = boto3.resource("dynamodb")
home_connectors_table = dynamodb.Table(HOME_CONNECTORS_TABLE) if HOME_CONNECTORS_TABLE else None
remote_requests_table = dynamodb.Table(REMOTE_REQUESTS_TABLE) if REMOTE_REQUESTS_TABLE else None
binding_operations_table = dynamodb.Table(BINDING_OPERATIONS_TABLE) if BINDING_OPERATIONS_TABLE else None
app_sessions_table = dynamodb.Table(APP_SESSIONS_TABLE) if APP_SESSIONS_TABLE else None
identity_profiles_table = dynamodb.Table(IDENTITY_PROFILES_TABLE) if IDENTITY_PROFILES_TABLE else None
s3_client = boto3.client("s3") if REMOTE_PAYLOADS_BUCKET else None
LOGGER = logging.getLogger(__name__)


def _json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def response(status_code, state, **fields):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"state": state, **fields}, default=_json_default),
    }


def normalized_path(event):
    path = event.get("rawPath") or event.get("path") or "/"
    stage = (event.get("requestContext") or {}).get("stage")
    prefix = f"/{stage}" if stage and stage != "$default" else ""
    if prefix and path == prefix:
        return "/"
    return path[len(prefix):] if prefix and path.startswith(prefix + "/") else path


def method_for(event):
    return str(((event.get("requestContext") or {}).get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()


def header_value(event, name):
    target = name.lower()
    return next((value for key, value in (event.get("headers") or {}).items() if key.lower() == target), None)


def parse_json_body(event):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def epoch_now():
    return int(time.time())


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_json_field(value, default):
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default


def _connector_online(item):
    return epoch_now() - int(item.get("last_seen_epoch") or 0) <= CONNECTOR_ONLINE_WINDOW_SECONDS


def public_connector(item):
    online = _connector_online(item)
    return {
        "connector_id": item.get("connector_id"),
        "profile_id": item.get("profile_id"),
        "connector_name": item.get("connector_name"),
        "host_type": item.get("host_type"),
        "app_version": item.get("app_version"),
        "status": "online" if online else "offline",
        "online": online,
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "last_seen_at": item.get("last_seen_at"),
        "last_seen_epoch": item.get("last_seen_epoch"),
        "next_heartbeat_seconds": 60,
        "capabilities": _parse_json_field(item.get("capabilities_json"), []),
        "provider_status": _parse_json_field(item.get("provider_status_json"), {}),
    }


def _auth_failure():
    return response(401, "connector_unauthorized")


CONNECTOR_AUTH_DIAGNOSTIC_EVENT = "pairing_v3_connector_auth_rejected"
CONNECTOR_AUTH_NUMBER_COMPATIBILITY_EVENT = "pairing_v3_connector_auth_number_compatibility"
CONNECTOR_AUTH_REASON_FALLBACK = "CONNECTOR_AUTH_REJECTED_UNCLASSIFIED"
CONNECTOR_AUTH_REASON_CATEGORIES = frozenset({
    "AUTH_STORAGE_UNAVAILABLE",
    "CONNECTOR_ID_MISSING",
    "REQUEST_BODY_INVALID",
    "BODY_CONNECTOR_MISMATCH",
    "CONNECTOR_NOT_FOUND",
    "CONNECTOR_STATE_INVALID",
    "PLUGIN_PUBLIC_KEY_INVALID",
    "PLUGIN_FINGERPRINT_INVALID",
    "PLUGIN_INSTANCE_INVALID",
    "PLUGIN_KEY_ID_MISMATCH",
    "PLUGIN_TIMESTAMP_INVALID",
    "PLUGIN_NONCE_INVALID",
    "REQUEST_CANONICALIZATION_INVALID",
    "PLUGIN_SIGNATURE_INVALID",
    "PLUGIN_NONCE_REPLAY",
    "PLUGIN_NONCE_STORAGE_FAILURE",
    CONNECTOR_AUTH_REASON_FALLBACK,
})


def _connector_auth_route_category(event):
    path = normalized_path(event)
    if path == "/v3/remote-requests/claim":
        return "remote_request_claim"
    if re.fullmatch(r"/v3/remote-requests/[^/]+/complete", path):
        return "remote_request_complete"
    if re.fullmatch(r"/v3/remote-requests/[^/]+/fail", path):
        return "remote_request_fail"
    if re.fullmatch(r"/v3/home-connectors/[^/]+/heartbeat", path):
        return "connector_heartbeat"
    return "connector_request"


def _connector_auth_rejected(event, reason, connector_id=""):
    """Emit bounded connector-auth diagnosis while preserving a null result."""
    try:
        category = reason if reason in CONNECTOR_AUTH_REASON_CATEGORIES else CONNECTOR_AUTH_REASON_FALLBACK
        connector_fingerprint = hashlib.sha256(
            f"pairing-v3-connector-control-auth-v1:{connector_id}".encode("utf-8")
        ).hexdigest()[:24] if connector_id else ""
        LOGGER.warning(json.dumps({
            "event": CONNECTOR_AUTH_DIAGNOSTIC_EVENT,
            "reason_category": category,
            "route_category": _connector_auth_route_category(event),
            "method": method_for(event),
            "connector_fingerprint": connector_fingerprint,
            "timestamp": utc_now_iso(),
        }, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Diagnostic failure must never alter the existing fail-closed decision.
        pass
    return None


def _raw_event_json_body(event):
    raw_body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")
    if not isinstance(raw_body, str):
        raise PairingV3CryptoError("JSON body must be text")
    return raw_body


def _exact_json_body_bytes(event):
    """Return the exact strict JSON bytes used by connector signature v2."""
    raw_body = _raw_event_json_body(event)

    def reject_duplicate_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise PairingV3CryptoError("duplicate JSON key")
            value[key] = item
        return value

    def reject_nonstandard_number(value):
        raise PairingV3CryptoError(f"nonstandard JSON number: {value}")

    try:
        parsed = json.loads(
            raw_body,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_nonstandard_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as error:
        raise PairingV3CryptoError("strict JSON body invalid") from error
    if not isinstance(parsed, dict):
        raise PairingV3CryptoError("JSON body must be an object")
    return raw_body.encode("utf-8", errors="strict")


def _connector_request_transcript(event, body_digest, timestamp, nonce, connector_id,
                                  plugin_instance_id, plugin_key_id, fingerprint):
    return canonical_transcript("connector-request", (
        ("httpMethod", method_for(event)),
        ("canonicalRoute", normalized_path(event)),
        ("bodyDigest", body_digest),
        ("timestamp", timestamp),
        ("nonce", nonce),
        ("connectorId", connector_id),
        ("pluginInstanceId", plugin_instance_id),
        ("pluginKeyId", plugin_key_id),
        ("pluginPublicKeyFingerprint", fingerprint),
    ))


def _connector_auth_number_compatibility(event, connector_id):
    try:
        connector_fingerprint = hashlib.sha256(
            f"pairing-v3-connector-control-auth-v1:{connector_id}".encode("utf-8")
        ).hexdigest()[:24]
        LOGGER.warning(json.dumps({
            "event": CONNECTOR_AUTH_NUMBER_COMPATIBILITY_EVENT,
            "route_category": _connector_auth_route_category(event),
            "method": method_for(event),
            "connector_fingerprint": connector_fingerprint,
            "timestamp": utc_now_iso(),
        }, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Observability must not alter a successfully verified request.
        pass


def authenticate_connector(event, connector_id, body, *, allow_revoked=False):
    """Verify the enrolled Ed25519 key and atomically consume the nonce."""
    if home_connectors_table is None or app_sessions_table is None:
        return _connector_auth_rejected(event, "AUTH_STORAGE_UNAVAILABLE", connector_id)
    if not connector_id:
        return _connector_auth_rejected(event, "CONNECTOR_ID_MISSING")
    if not isinstance(body, dict):
        return _connector_auth_rejected(event, "REQUEST_BODY_INVALID", connector_id)
    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and not hmac.compare_digest(body_connector_id, connector_id):
        return _connector_auth_rejected(event, "BODY_CONNECTOR_MISMATCH", connector_id)
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}, ConsistentRead=True).get("Item")
    if not item:
        return _connector_auth_rejected(event, "CONNECTOR_NOT_FOUND", connector_id)
    active = (
        not bool(item.get("revoked"))
        and item.get("auth_state") == "v3_active"
        and item.get("state") == "active"
    )
    revoked = (
        bool(item.get("revoked"))
        and item.get("auth_state") == "v3_revoked"
        and item.get("state") == "revoked"
    )
    if item.get("protocol_version") != PROTOCOL or not (active or (allow_revoked and revoked)):
        return _connector_auth_rejected(event, "CONNECTOR_STATE_INVALID", connector_id)
    try:
        public_key = b64url_decode(str(item.get("plugin_public_key") or ""))
        if len(public_key) != 32:
            raise PairingV3CryptoError("invalid plugin key")
    except (PairingV3CryptoError, TypeError, ValueError):
        return _connector_auth_rejected(event, "PLUGIN_PUBLIC_KEY_INVALID", connector_id)
    fingerprint = str(item.get("plugin_public_key_fingerprint") or "")
    try:
        valid_fingerprint = SAFE_FINGERPRINT.fullmatch(fingerprint) and constant_time_equal(
            fingerprint, plugin_fingerprint(public_key)
        )
    except (PairingV3CryptoError, TypeError, ValueError):
        valid_fingerprint = False
    if not valid_fingerprint:
        return _connector_auth_rejected(event, "PLUGIN_FINGERPRINT_INVALID", connector_id)
    plugin_instance_id = str(item.get("plugin_instance_id") or "")
    if not plugin_instance_id:
        return _connector_auth_rejected(event, "PLUGIN_INSTANCE_INVALID", connector_id)
    plugin_key_id = str(header_value(event, "x-kaevo-plugin-key-id") or "")
    expected_key_id = str(item.get("plugin_key_id") or "1")
    if not plugin_key_id or not hmac.compare_digest(plugin_key_id, expected_key_id):
        return _connector_auth_rejected(event, "PLUGIN_KEY_ID_MISMATCH", connector_id)
    timestamp = str(header_value(event, "x-kaevo-plugin-timestamp") or "")
    if not re.fullmatch(r"\d{13}", timestamp) or abs((int(timestamp) // 1000) - epoch_now()) > PLUGIN_TIMESTAMP_SKEW_SECONDS:
        return _connector_auth_rejected(event, "PLUGIN_TIMESTAMP_INVALID", connector_id)
    nonce = str(header_value(event, "x-kaevo-plugin-nonce") or "")
    if not SAFE_NONCE.fullmatch(nonce):
        return _connector_auth_rejected(event, "PLUGIN_NONCE_INVALID", connector_id)
    signature_version = str(header_value(event, "x-kaevo-plugin-signature-version") or "1")
    try:
        if signature_version == "2":
            parsed_body_digest = sha256_b64url(_exact_json_body_bytes(event))
        elif signature_version == "1":
            parsed_body_digest = canonical_json_digest(body)
        else:
            raise PairingV3CryptoError("unsupported connector signature version")
        transcript = _connector_request_transcript(
            event, parsed_body_digest, timestamp, nonce, connector_id,
            plugin_instance_id, plugin_key_id, fingerprint,
        )
    except (PairingV3CryptoError, TypeError, ValueError, UnicodeDecodeError):
        return _connector_auth_rejected(event, "REQUEST_CANONICALIZATION_INVALID", connector_id)
    signature = str(header_value(event, "x-kaevo-plugin-signature") or "")
    try:
        verify_ed25519(public_key, transcript, signature)
    except (PairingV3CryptoError, TypeError, ValueError):
        if signature_version == "2":
            return _connector_auth_rejected(event, "PLUGIN_SIGNATURE_INVALID", connector_id)
        try:
            compatibility_digest = canonical_json_digest_preserving_number_lexemes(_raw_event_json_body(event))
            if hmac.compare_digest(compatibility_digest, parsed_body_digest):
                raise PairingV3CryptoError("canonical body digest unchanged")
            compatibility_transcript = _connector_request_transcript(
                event, compatibility_digest, timestamp, nonce, connector_id,
                plugin_instance_id, plugin_key_id, fingerprint,
            )
            verify_ed25519(public_key, compatibility_transcript, signature)
        except (PairingV3CryptoError, TypeError, ValueError, UnicodeDecodeError):
            return _connector_auth_rejected(event, "PLUGIN_SIGNATURE_INVALID", connector_id)
        _connector_auth_number_compatibility(event, connector_id)
    try:
        app_sessions_table.put_item(
            Item={
                "token_hash": f"v3_connector_nonce#{sha256_b64url(f'{connector_id}:{nonce}'.encode('utf-8'))}",
                "record_type": "pairing_v3_connector_nonce",
                "expires_at": epoch_now() + CONNECTOR_NONCE_RETENTION_SECONDS,
            },
            ConditionExpression="attribute_not_exists(token_hash)",
        )
        return item
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code") or "")
        reason = "PLUGIN_NONCE_REPLAY" if code == "ConditionalCheckFailedException" else "PLUGIN_NONCE_STORAGE_FAILURE"
        return _connector_auth_rejected(event, reason, connector_id)
    except (PairingV3CryptoError, TypeError, ValueError):
        return _connector_auth_rejected(event, "PLUGIN_NONCE_STORAGE_FAILURE", connector_id)


def disconnect_connector(event, connector_id):
    """Revoke one exact V3 connector and retain only a bounded tombstone."""
    body = parse_json_body(event)
    if body is None:
        return response(400, "bad_request", code="invalid_json")
    connector = authenticate_connector(
        event,
        connector_id,
        body,
        allow_revoked=True,
    )
    if not connector:
        return _auth_failure()
    if (
        bool(connector.get("revoked"))
        and connector.get("auth_state") == "v3_revoked"
        and connector.get("state") == "revoked"
    ):
        return response(200, "disconnected", idempotent=True)

    now = utc_now_iso()
    values = {
        ":protocol": PROTOCOL,
        ":active_auth": "v3_active",
        ":active_state": "active",
        ":revoked_auth": "v3_revoked",
        ":revoked_state": "revoked",
        ":false": False,
        ":true": True,
        ":now": now,
        ":plugin_instance": str(connector.get("plugin_instance_id") or ""),
        ":fingerprint": str(connector.get("plugin_public_key_fingerprint") or ""),
        ":plugin_key_id": str(connector.get("plugin_key_id") or "1"),
    }
    try:
        home_connectors_table.update_item(
            Key={"connector_id": connector_id},
            ConditionExpression=(
                "attribute_exists(connector_id) AND protocol_version = :protocol "
                "AND auth_state = :active_auth AND #state = :active_state "
                "AND (attribute_not_exists(revoked) OR revoked = :false) "
                "AND plugin_instance_id = :plugin_instance "
                "AND plugin_public_key_fingerprint = :fingerprint "
                "AND plugin_key_id = :plugin_key_id"
            ),
            UpdateExpression=(
                "SET revoked = :true, auth_state = :revoked_auth, #state = :revoked_state, "
                "updated_at = :now, revoked_at = :now "
                "REMOVE profile_id, account_binding, family_binding, connector_name, host_type, "
                "app_version, last_seen_at, last_seen_epoch, capabilities_json, provider_status_json, "
                "jellyfin_user_id, server_name"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues=values,
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, "connector_state_conflict")
        return response(503, "dependency_failure")
    return response(200, "disconnected", idempotent=False)


def resolve_profile_binding(connector, requested_profile_id):
    bound = str((connector or {}).get("profile_id") or "").strip()
    requested = str(requested_profile_id or "").strip()
    if bound:
        return bound if not requested or hmac.compare_digest(bound, requested) else ""
    if not requested or identity_profiles_table is None:
        return ""
    profile = identity_profiles_table.get_item(Key={"profile_id": requested}, ConsistentRead=True).get("Item")
    if not profile:
        return ""
    account = sha256_b64url(str(profile.get("account_id") or "").encode("utf-8"))
    family = sha256_b64url(str(profile.get("household_id") or "").encode("utf-8"))
    if not constant_time_equal(str(connector.get("account_binding") or ""), account):
        return ""
    if not constant_time_equal(str(connector.get("family_binding") or ""), family):
        return ""
    return requested


def _update_online_connector(connector, profile_id, body):
    now = utc_now_iso()
    capabilities = body.get("capabilities")
    if not isinstance(capabilities, list):
        capabilities = _parse_json_field(connector.get("capabilities_json"), ["heartbeat", "provider_status", "remote_route_control_plane"])
    provider_status = body.get("provider_status")
    if not isinstance(provider_status, dict):
        provider_status = _parse_json_field(connector.get("provider_status_json"), {})
    values = {
        ":profile": profile_id,
        ":connector_name": str(body.get("connector_name") or connector.get("connector_name") or "Kaevo Jellyfin Plugin"),
        ":host_type": str(body.get("host_type") or connector.get("host_type") or "unknown"),
        ":app_version": str(body.get("app_version") or connector.get("app_version") or "0.0.1-dev"),
        ":now": now,
        ":now_epoch": epoch_now(),
        ":capabilities": json.dumps(capabilities, separators=(",", ":")),
        ":provider_status": json.dumps(provider_status, separators=(",", ":")),
        ":protocol": PROTOCOL,
        ":auth": "v3_active",
        ":active": "active",
        ":false": False,
        ":plugin_instance": str(connector.get("plugin_instance_id") or ""),
        ":fingerprint": str(connector.get("plugin_public_key_fingerprint") or ""),
        ":plugin_key_id": str(connector.get("plugin_key_id") or "1"),
        ":server_id": str(connector.get("server_id") or ""),
    }
    return home_connectors_table.update_item(
        Key={"connector_id": str(connector["connector_id"])},
        ConditionExpression=(
            "attribute_exists(connector_id) AND protocol_version = :protocol AND auth_state = :auth "
            "AND #state = :active AND (attribute_not_exists(revoked) OR revoked = :false) "
            "AND plugin_instance_id = :plugin_instance AND plugin_public_key_fingerprint = :fingerprint "
            "AND plugin_key_id = :plugin_key_id AND server_id = :server_id "
            "AND (attribute_not_exists(profile_id) OR profile_id = :profile)"
        ),
        UpdateExpression=(
            "SET profile_id = if_not_exists(profile_id, :profile), connector_name = :connector_name, "
            "host_type = :host_type, app_version = :app_version, created_at = if_not_exists(created_at, :now), "
            "updated_at = :now, last_seen_at = :now, last_seen_epoch = :now_epoch, "
            "capabilities_json = :capabilities, provider_status_json = :provider_status"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    ).get("Attributes", {})


def register_connector(event):
    body = parse_json_body(event)
    if body is None:
        return response(400, "bad_request", code="invalid_json")
    connector_id = str(body.get("connector_id") or "").strip()
    connector = authenticate_connector(event, connector_id, body)
    if not connector:
        return _auth_failure()
    profile_id = resolve_profile_binding(connector, body.get("profile_id"))
    if not profile_id:
        return response(403, "connector_profile_mismatch")
    try:
        item = _update_online_connector(connector, profile_id, body)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, "connector_binding_conflict")
        return response(503, "dependency_failure")
    return response(200, "registered", connector=public_connector(item), playback=_playback_metadata())


def heartbeat_connector(event, connector_id):
    body = parse_json_body(event)
    if body is None:
        return response(400, "bad_request", code="invalid_json")
    connector = authenticate_connector(event, connector_id, body)
    if not connector:
        return _auth_failure()
    profile_id = resolve_profile_binding(connector, body.get("profile_id"))
    if not profile_id:
        return response(403, "connector_profile_mismatch")
    try:
        item = _update_online_connector(connector, profile_id, body)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, "connector_binding_conflict")
        return response(503, "dependency_failure")
    return response(200, "online", connector=public_connector(item), playback=_playback_metadata())


def _playback_metadata():
    return {
        "enabled": bool(PLAYBACK_RELAY_PUBLIC_URL),
        "relay_websocket_url": PLAYBACK_RELAY_PUBLIC_URL.replace("https://", "wss://", 1)
        if PLAYBACK_RELAY_PUBLIC_URL.startswith("https://") else "",
    }


def _b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def relay_ticket(event, connector_id):
    body = parse_json_body(event)
    if body is None:
        return response(400, "bad_request", code="invalid_json")
    if not authenticate_connector(event, connector_id, body):
        return _auth_failure()
    if len(PLAYBACK_GRANT_SIGNING_KEY) < 32:
        return response(503, "playback_grants_not_configured")
    now = epoch_now()
    payload = {
        "v": 1, "type": "connector_relay", "connector_id": connector_id,
        "nonce": secrets.token_urlsafe(24), "iat": now, "nbf": now - 5, "exp": now + 300,
    }
    encoded = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(PLAYBACK_GRANT_SIGNING_KEY.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return response(201, "issued", relay_ticket=f"{encoded}.{_b64url(signature)}", expires_at=now + 300)


def _remote_request_id(path, suffix):
    prefix = "/v3/remote-requests/"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return ""
    return path[len(prefix):-len(suffix)].strip("/")


def _status_sort_key(status, timestamp, request_id):
    return f"{status}#{timestamp}#{request_id}"


def frozen_profile_provider_binding(item, request_payload):
    """Project only the immutable binding frozen by Account Lifecycle V2.

    The connector must never derive deletion authority from display data or
    from the command parameters supplied to the plugin. Malformed lifecycle
    requests fail closed instead of silently dropping this authority edge.
    """
    operation = str((request_payload or {}).get("path") or "").removeprefix("/commands/")
    if operation not in ACCOUNT_LIFECYCLE_V2_PROVIDER_OPERATIONS:
        return None
    try:
        frozen = json.loads(str((item or {}).get("profile_provider_binding_json") or ""))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("frozen_provider_binding_invalid") from error
    if not isinstance(frozen, dict):
        raise ValueError("frozen_provider_binding_invalid")

    provider = str(frozen.get("provider") or "")
    connector_id = str(frozen.get("connector_id") or "")
    provider_user_id = str(frozen.get("provider_user_id") or "")
    request_body = (request_payload or {}).get("body")
    request_profile_id = str(
        request_body.get("profile_id") if isinstance(request_body, dict) else ""
    )
    item_profile_id = str((item or {}).get("profile_id") or "")
    if (
        provider != "jellyfin"
        or not connector_id
        or connector_id != str((item or {}).get("connector_id") or "")
        or not provider_user_id
        or len(provider_user_id) > 64
        or not item_profile_id
        or request_profile_id != item_profile_id
        or any(ord(character) < 32 for character in provider_user_id)
    ):
        raise ValueError("frozen_provider_binding_invalid")
    return {
        "provider": provider,
        "connector_id": connector_id,
        "provider_user_id": provider_user_id,
    }


def canonical_profile_jellyfin_binding(item):
    """Resolve one active profile edge for the exact claiming connector.

    This projection is Cloud authority, never client command input. Missing,
    malformed, inactive, stale, or cross-connector records intentionally
    produce no binding so the plugin fails the mutation closed.
    """
    profile_id = str((item or {}).get("profile_id") or "")
    connector_id = str((item or {}).get("connector_id") or "")
    if identity_profiles_table is None or not profile_id or not connector_id:
        return None
    try:
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
    except ClientError:
        return None
    compact_user_id = str((profile or {}).get("jellyfin_user_id") or "").strip().replace("-", "")
    if (
        not isinstance(profile, dict)
        or str(profile.get("profile_id") or "") != profile_id
        or str(profile.get("state") or "") != "active"
        or str(profile.get("jellyfin_binding_state") or "") != "active"
        or not hmac.compare_digest(
            str(profile.get("jellyfin_connector_id") or ""), connector_id,
        )
        or not re.fullmatch(r"[0-9a-fA-F]{32}", compact_user_id)
    ):
        return None
    return {
        "provider": "jellyfin",
        "connector_id": connector_id,
        "provider_user_id": compact_user_id.lower(),
    }


def public_remote_request(item):
    request_payload = _parse_json_field(item.get("request_json"), {})
    result = {
        "request_id": item.get("request_id"), "profile_id": item.get("profile_id"),
        "connector_id": item.get("connector_id"), "status": item.get("status"),
        "created_at": item.get("created_at"), "updated_at": item.get("updated_at"),
        "claimed_at": item.get("claimed_at", ""), "completed_at": item.get("completed_at", ""),
        "failed_at": item.get("failed_at", ""), "expires_at": item.get("expires_at"),
        "provider": request_payload.get("provider"), "method": request_payload.get("method"),
        "path": request_payload.get("path"), "query": request_payload.get("query", {}),
    }
    if request_payload.get("method") == "COMMAND":
        # Match the established V1 claim contract. The authenticated V3
        # connector needs the allowlisted command body in order to execute the
        # command; omitting it turns every parameterized command into a safe
        # but unusable providerParameterInvalid failure.
        result["operation"] = str(request_payload.get("path") or "").removeprefix("/commands/")
        result["parameters"] = request_payload.get("body", {})
        operation = result["operation"]
        lifecycle_binding = frozen_profile_provider_binding(item, request_payload)
        if lifecycle_binding is not None:
            result["profile_provider_binding"] = lifecycle_binding
        elif operation in PROFILE_SCOPED_JELLYFIN_BINDING_OPERATIONS:
            binding = canonical_profile_jellyfin_binding(item)
            if binding is not None:
                result["profile_provider_binding"] = binding
    return result


def _mirror_binding_operation(item, phase, *, inspection_result="", plugin_cas_result="", snapshot_result="", terminal_result=""):
    """Mirror connector lifecycle before its short-lived request is removed.

    The operation ID is never logged or returned from this connector boundary.
    A missing journal is intentionally non-fatal for legacy remote requests.
    """
    operation_id = str((item or {}).get("binding_operation_id") or "")
    if not operation_id or binding_operations_table is None:
        return
    try:
        current = binding_operations_table.get_item(
            Key={"operation_id": operation_id}, ConsistentRead=True,
        ).get("Item")
    except ClientError:
        return
    if not isinstance(current, dict) or BINDING_OPERATION_PHASE_RANK.get(
        phase, -1,
    ) < BINDING_OPERATION_PHASE_RANK.get(str(current.get("phase") or "created"), -1):
        return
    revision = int(current.get("revision") or 0)
    values = {
        ":phase": phase, ":updated_at": utc_now_iso(),
        ":revision": revision, ":next_revision": revision + 1,
    }
    parts = ["#phase = :phase", "updated_at = :updated_at", "revision = :next_revision"]
    for key, value in {
        "inspection_result": inspection_result,
        "plugin_cas_result": plugin_cas_result,
        "snapshot_result": snapshot_result,
        "terminal_result": terminal_result,
    }.items():
        if value:
            placeholder = ":" + key
            values[placeholder] = value[:80]
            parts.append(f"{key} = {placeholder}")
    try:
        binding_operations_table.update_item(
            Key={"operation_id": operation_id},
            ConditionExpression="revision = :revision",
            UpdateExpression="SET " + ", ".join(parts),
            ExpressionAttributeNames={"#phase": "phase"},
            ExpressionAttributeValues=values,
        )
    except ClientError:
        # Connector execution must not repeat or alter a command only because
        # durable telemetry is temporarily unavailable. Cloud reconciliation
        # will surface the missing mirror as a safe retryable state.
        return


def _binding_command_kind(item):
    try:
        request = json.loads(str((item or {}).get("request_json") or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    return str(request.get("path") or "").removeprefix("/commands/")


def claim_remote_request(event):
    body = parse_json_body(event)
    if body is None:
        return response(400, "bad_request", code="invalid_json")
    connector_id = str(body.get("connector_id") or "").strip()
    if not authenticate_connector(event, connector_id, body):
        return _auth_failure()
    try:
        control_protocol = int(body.get("connector_control_protocol") or 0)
    except (TypeError, ValueError):
        control_protocol = 0
    if control_protocol < CONNECTOR_CONTROL_PROTOCOL_VERSION:
        result = response(
            426,
            "upgrade_required",
            minimum_connector_control_protocol=CONNECTOR_CONTROL_PROTOCOL_VERSION,
            retry_after_seconds=LEGACY_RECOVERY_RETRY_SECONDS,
        )
        result["headers"]["Retry-After"] = str(LEGACY_RECOVERY_RETRY_SECONDS)
        return result
    if body.get("recovery") is not True:
        return response(
            400,
            "recovery_claim_required",
            retry_after_seconds=LEGACY_RECOVERY_RETRY_SECONDS,
        )
    try:
        items = remote_requests_table.query(
            IndexName="connector_id-status_created_at-index",
            KeyConditionExpression=Key("connector_id").eq(connector_id) & Key("status_created_at").begins_with("pending#"),
            ScanIndexForward=True, Limit=8,
        ).get("Items", [])
        for candidate in items:
            if int(candidate.get("expires_at") or 0) < epoch_now():
                continue
            now = utc_now_iso()
            try:
                claimed = remote_requests_table.update_item(
                    Key={"request_id": candidate["request_id"]},
                    ConditionExpression="#status = :pending AND expires_at >= :now_epoch AND connector_id = :connector_id",
                    UpdateExpression="SET #status = :in_progress, claimed_at = :now, updated_at = :now, status_created_at = :sort",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":pending": "pending", ":in_progress": "in_progress", ":now": now,
                        ":now_epoch": epoch_now(), ":connector_id": connector_id,
                        ":sort": _status_sort_key("in_progress", now, candidate["request_id"]),
                    }, ReturnValues="ALL_NEW",
                ).get("Attributes", {})
                if claimed:
                    _mirror_binding_operation(claimed, "connector_claimed")
                    return response(200, "claimed", request=public_remote_request(claimed))
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise
        return response(200, "empty")
    except ClientError:
        return response(503, "dependency_failure")


def _load_authenticated_remote(event, path, suffix):
    request_id = _remote_request_id(path, suffix)
    if not request_id:
        return None, None, response(400, "bad_request", code="request_id_required")
    body = parse_json_body(event)
    if body is None:
        return None, None, response(400, "bad_request", code="invalid_json")
    try:
        item = remote_requests_table.get_item(Key={"request_id": request_id}, ConsistentRead=True).get("Item")
    except ClientError:
        return None, None, response(503, "dependency_failure")
    if not item:
        return None, None, response(404, "not_found", request_id=request_id)
    connector_id = str(item.get("connector_id") or "")
    if not authenticate_connector(event, connector_id, body):
        return None, None, _auth_failure()
    body_connector = str(body.get("connector_id") or "").strip()
    if body_connector and not hmac.compare_digest(body_connector, connector_id):
        return None, None, response(403, "connector_mismatch")
    return item, body, None


def complete_remote_request(event, path):
    item, body, error = _load_authenticated_remote(event, path, "/complete")
    if error:
        return error
    request_id = str(item["request_id"])
    now = utc_now_iso()
    # Fully prepare the bounded response before the single terminal state
    # transition. A large snapshot without an object store must return 413
    # while it is still in_progress so the connector can report failure
    # normally, and an S3-backed snapshot must not be stranded in an
    # intermediate state after the object write succeeds.
    encoded = json.dumps(body.get("response") if body.get("response") is not None else {}, separators=(",", ":")).encode("utf-8")
    set_parts = [
        "#status = :completed", "completed_at = :now", "updated_at = :now", "status_created_at = :sort",
        "http_status = :http_status", "truncated = :truncated",
    ]
    values = {
        ":completed": "completed", ":now": now,
        ":sort": _status_sort_key("completed", now, request_id),
        ":http_status": int(body.get("http_status") or 200), ":truncated": bool(body.get("truncated", False)),
    }
    remove_parts = []
    if len(encoded) >= REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES:
        compressed = gzip.compress(encoded, compresslevel=6)
        if REMOTE_PAYLOADS_BUCKET and s3_client is not None:
            key = f"remote-responses/{item.get('profile_id')}/{request_id}.json.gz"
            try:
                s3_client.put_object(
                    Bucket=REMOTE_PAYLOADS_BUCKET, Key=key, Body=compressed,
                    ContentType="application/json", ContentEncoding="gzip", ServerSideEncryption="AES256",
                )
            except ClientError:
                return response(503, "ambiguous_completion_state", request_id=request_id)
            set_parts.extend(["response_s3_key = :response_s3_key", "response_encoding = :response_encoding", "response_stored_bytes = :response_stored_bytes"])
            values.update({":response_s3_key": key, ":response_encoding": "s3+gzip", ":response_stored_bytes": len(compressed)})
            remove_parts.extend(["response_json", "response_gzip_base64"])
        elif len(compressed) > REMOTE_RESPONSE_MAX_STORED_BYTES:
            return response(413, "response_too_large", request_id=request_id)
        else:
            set_parts.extend(["response_gzip_base64 = :response_gzip", "response_encoding = :response_encoding"])
            values.update({":response_gzip": base64.b64encode(compressed).decode("ascii"), ":response_encoding": "gzip+base64"})
            remove_parts.extend(["response_json", "response_s3_key", "response_stored_bytes"])
    else:
        set_parts.append("response_json = :response_json")
        values[":response_json"] = encoded.decode("utf-8")
        remove_parts.extend(["response_gzip_base64", "response_s3_key", "response_encoding", "response_stored_bytes"])
    try:
        updated = remote_requests_table.update_item(
            Key={"request_id": request_id}, ConditionExpression="#status = :in_progress",
            UpdateExpression="SET " + ", ".join(set_parts) + " REMOVE " + ", ".join(dict.fromkeys(remove_parts)),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={**values, ":in_progress": "in_progress"},
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        return response(409, "request_not_in_progress", request_id=request_id) if code == "ConditionalCheckFailedException" else response(503, "dependency_failure")
    command = _binding_command_kind(updated)
    payload = body.get("response") if isinstance(body.get("response"), dict) else {}
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    if command == "jellyfin.inspect_profile_binding_owner":
        _mirror_binding_operation(
            updated, "inspection_completed",
            inspection_result=str(result.get("owner_state") or "invalid"),
        )
    elif command == "jellyfin.reassign_stale_profile_binding":
        _mirror_binding_operation(
            updated, "plugin_cas_committed",
            plugin_cas_result=str(result.get("state") or "invalid"),
        )
    elif command == "/kaevo/internal/main-snapshot":
        _mirror_binding_operation(
            updated, "snapshot_published", snapshot_result="published",
        )
    return response(200, "completed", request=public_remote_request(updated))


def fail_remote_request(event, path):
    item, body, error = _load_authenticated_remote(event, path, "/fail")
    if error:
        return error
    request_id = str(item["request_id"])
    now = utc_now_iso()
    error_json = json.dumps({
        "message": str(body.get("message") or "remote request failed"),
        "details": body.get("details") if isinstance(body.get("details"), dict) else {},
    }, separators=(",", ":"))
    try:
        updated = remote_requests_table.update_item(
            Key={"request_id": request_id}, ConditionExpression="#status = :in_progress",
            UpdateExpression=(
                "SET #status = :failed, failed_at = :now, updated_at = :now, "
                "status_created_at = :sort, error_json = :error"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":in_progress": "in_progress", ":failed": "failed", ":now": now,
                ":sort": _status_sort_key("failed", now, request_id), ":error": error_json,
            }, ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        return response(409, "request_not_in_progress", request_id=request_id) if code == "ConditionalCheckFailedException" else response(503, "dependency_failure")
    _mirror_binding_operation(updated, "failed_retryable", terminal_result="connector_failed")
    return response(200, "failed", request=public_remote_request(updated))


def lambda_handler(event, _context):
    path = normalized_path(event)
    method = method_for(event)
    if method != "POST":
        return response(405, "method_not_allowed")
    if path == "/v3/home-connectors/register":
        return register_connector(event)
    heartbeat = re.fullmatch(r"/v3/home-connectors/([^/]+)/heartbeat", path)
    if heartbeat:
        return heartbeat_connector(event, heartbeat.group(1))
    disconnect = re.fullmatch(r"/v3/home-connectors/([^/]+)/disconnect", path)
    if disconnect:
        return disconnect_connector(event, disconnect.group(1))
    relay = re.fullmatch(r"/v3/home-connectors/([^/]+)/relay-ticket", path)
    if relay:
        return relay_ticket(event, relay.group(1))
    if path == "/v3/remote-requests/claim":
        return claim_remote_request(event)
    if re.fullmatch(r"/v3/remote-requests/[^/]+/complete", path):
        return complete_remote_request(event, path)
    if re.fullmatch(r"/v3/remote-requests/[^/]+/fail", path):
        return fail_remote_request(event, path)
    return response(404, "not_found")
