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
    canonical_transcript,
    constant_time_equal,
    plugin_fingerprint,
    sha256_b64url,
    verify_ed25519,
)


KAEVO_ENV = os.environ.get("KAEVO_ENV", "dev").strip().lower()
HOME_CONNECTORS_TABLE = os.environ.get("HOME_CONNECTORS_TABLE", "")
REMOTE_REQUESTS_TABLE = os.environ.get("REMOTE_REQUESTS_TABLE", "")
APP_SESSIONS_TABLE = os.environ.get("APP_SESSIONS_TABLE", "")
IDENTITY_PROFILES_TABLE = os.environ.get("IDENTITY_PROFILES_TABLE", "")
REMOTE_PAYLOADS_BUCKET = os.environ.get("REMOTE_PAYLOADS_BUCKET", "")
PLAYBACK_GRANT_SIGNING_KEY = os.environ.get("PLAYBACK_GRANT_SIGNING_KEY", "")
PLAYBACK_RELAY_PUBLIC_URL = os.environ.get("PLAYBACK_RELAY_PUBLIC_URL", "").rstrip("/")

CONNECTOR_ONLINE_WINDOW_SECONDS = 120
CONNECTOR_NONCE_RETENTION_SECONDS = 24 * 60 * 60
PLUGIN_TIMESTAMP_SKEW_SECONDS = 60
REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES = 180_000
REMOTE_RESPONSE_MAX_STORED_BYTES = 330_000
SAFE_FINGERPRINT = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
SAFE_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")

dynamodb = boto3.resource("dynamodb")
home_connectors_table = dynamodb.Table(HOME_CONNECTORS_TABLE) if HOME_CONNECTORS_TABLE else None
remote_requests_table = dynamodb.Table(REMOTE_REQUESTS_TABLE) if REMOTE_REQUESTS_TABLE else None
app_sessions_table = dynamodb.Table(APP_SESSIONS_TABLE) if APP_SESSIONS_TABLE else None
identity_profiles_table = dynamodb.Table(IDENTITY_PROFILES_TABLE) if IDENTITY_PROFILES_TABLE else None
s3_client = boto3.client("s3") if REMOTE_PAYLOADS_BUCKET else None


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


def authenticate_connector(event, connector_id, body):
    """Verify the enrolled Ed25519 key and atomically consume the nonce."""
    if not all((home_connectors_table, app_sessions_table, connector_id)) or not isinstance(body, dict):
        return None
    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and not hmac.compare_digest(body_connector_id, connector_id):
        return None
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}, ConsistentRead=True).get("Item")
    if not item or bool(item.get("revoked")):
        return None
    if item.get("protocol_version") != PROTOCOL or item.get("auth_state") != "v3_active" or item.get("state") != "active":
        return None
    try:
        public_key = b64url_decode(str(item.get("plugin_public_key") or ""))
        if len(public_key) != 32:
            raise PairingV3CryptoError("invalid plugin key")
        fingerprint = str(item.get("plugin_public_key_fingerprint") or "")
        if not SAFE_FINGERPRINT.fullmatch(fingerprint) or not constant_time_equal(fingerprint, plugin_fingerprint(public_key)):
            raise PairingV3CryptoError("plugin fingerprint mismatch")
        plugin_instance_id = str(item.get("plugin_instance_id") or "")
        plugin_key_id = str(header_value(event, "x-kaevo-plugin-key-id") or "")
        expected_key_id = str(item.get("plugin_key_id") or "1")
        if not plugin_instance_id or not plugin_key_id or not hmac.compare_digest(plugin_key_id, expected_key_id):
            raise PairingV3CryptoError("plugin key id mismatch")
        timestamp = str(header_value(event, "x-kaevo-plugin-timestamp") or "")
        if not re.fullmatch(r"\d{13}", timestamp) or abs((int(timestamp) // 1000) - epoch_now()) > PLUGIN_TIMESTAMP_SKEW_SECONDS:
            raise PairingV3CryptoError("plugin timestamp invalid")
        nonce = str(header_value(event, "x-kaevo-plugin-nonce") or "")
        if not SAFE_NONCE.fullmatch(nonce):
            raise PairingV3CryptoError("plugin nonce invalid")
        transcript = canonical_transcript("connector-request", (
            ("httpMethod", method_for(event)),
            ("canonicalRoute", normalized_path(event)),
            ("bodyDigest", canonical_json_digest(body)),
            ("timestamp", timestamp),
            ("nonce", nonce),
            ("connectorId", connector_id),
            ("pluginInstanceId", plugin_instance_id),
            ("pluginKeyId", plugin_key_id),
            ("pluginPublicKeyFingerprint", fingerprint),
        ))
        verify_ed25519(public_key, transcript, str(header_value(event, "x-kaevo-plugin-signature") or ""))
        app_sessions_table.put_item(
            Item={
                "token_hash": f"v3_connector_nonce#{sha256_b64url(f'{connector_id}:{nonce}'.encode('utf-8'))}",
                "record_type": "pairing_v3_connector_nonce",
                "expires_at": epoch_now() + CONNECTOR_NONCE_RETENTION_SECONDS,
            },
            ConditionExpression="attribute_not_exists(token_hash)",
        )
        return item
    except (PairingV3CryptoError, ClientError, TypeError, ValueError):
        return None


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
    return result


def claim_remote_request(event):
    body = parse_json_body(event)
    if body is None:
        return response(400, "bad_request", code="invalid_json")
    connector_id = str(body.get("connector_id") or "").strip()
    if not authenticate_connector(event, connector_id, body):
        return _auth_failure()
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
    try:
        remote_requests_table.update_item(
            Key={"request_id": request_id}, ConditionExpression="#status = :in_progress",
            UpdateExpression="SET #status = :completing, updated_at = :now, status_created_at = :sort",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":in_progress": "in_progress", ":completing": "completing", ":now": now,
                ":sort": _status_sort_key("completing", now, request_id),
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        return response(409, "request_not_in_progress", request_id=request_id) if code == "ConditionalCheckFailedException" else response(503, "dependency_failure")

    encoded = json.dumps(body.get("response") if body.get("response") is not None else {}, separators=(",", ":")).encode("utf-8")
    set_parts = [
        "#status = :completed", "completed_at = :now", "updated_at = :now", "status_created_at = :sort",
        "http_status = :http_status", "truncated = :truncated",
    ]
    values = {
        ":completing": "completing", ":completed": "completed", ":now": now,
        ":sort": _status_sort_key("completed", now, request_id),
        ":http_status": int(body.get("http_status") or 200), ":truncated": bool(body.get("truncated", False)),
    }
    remove_parts = ["response_gzip_base64", "response_s3_key", "response_encoding", "response_stored_bytes"]
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
            remove_parts.append("response_json")
        elif len(compressed) > REMOTE_RESPONSE_MAX_STORED_BYTES:
            return response(413, "response_too_large", request_id=request_id)
        else:
            set_parts.extend(["response_gzip_base64 = :response_gzip", "response_encoding = :response_encoding"])
            values.update({":response_gzip": base64.b64encode(compressed).decode("ascii"), ":response_encoding": "gzip+base64"})
            remove_parts.append("response_json")
    else:
        set_parts.append("response_json = :response_json")
        values[":response_json"] = encoded.decode("utf-8")
    try:
        updated = remote_requests_table.update_item(
            Key={"request_id": request_id}, ConditionExpression="#status = :completing",
            UpdateExpression="SET " + ", ".join(set_parts) + " REMOVE " + ", ".join(dict.fromkeys(remove_parts)),
            ExpressionAttributeNames={"#status": "status"}, ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        return response(409, "ambiguous_completion_state", request_id=request_id) if code == "ConditionalCheckFailedException" else response(503, "ambiguous_completion_state", request_id=request_id)
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
