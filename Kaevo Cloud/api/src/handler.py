import base64
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from decimal import Decimal
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


SERVICE_NAME = "kaevo-cloud"
VERSION = "0.0.29"

EVENTS_TABLE = os.environ.get("PROFILE_EVENTS_TABLE")
PROFILE_SETTINGS_TABLE = os.environ.get("PROFILE_SETTINGS_TABLE")
DEVICES_TABLE = os.environ.get("DEVICES_TABLE")
ENTITLEMENTS_TABLE = os.environ.get("ENTITLEMENTS_TABLE")
HOME_CONNECTORS_TABLE = os.environ.get("HOME_CONNECTORS_TABLE")
REMOTE_REQUESTS_TABLE = os.environ.get("REMOTE_REQUESTS_TABLE")
REMOTE_PAYLOADS_BUCKET = os.environ.get("REMOTE_PAYLOADS_BUCKET")
PROFILE_AVATARS_BUCKET = os.environ.get("PROFILE_AVATARS_BUCKET")
APP_SESSIONS_TABLE = os.environ.get("APP_SESSIONS_TABLE")
DEV_API_KEY = os.environ.get("DEV_API_KEY")
PLAYBACK_GRANT_SIGNING_KEY = os.environ.get("PLAYBACK_GRANT_SIGNING_KEY", "")
PLAYBACK_RELAY_PUBLIC_URL = os.environ.get("PLAYBACK_RELAY_PUBLIC_URL", "").rstrip("/")

MAX_BATCH_EVENTS = 50
CONNECTOR_ONLINE_WINDOW_SECONDS = 120
CONNECTOR_PAIRING_TTL_SECONDS = 10 * 60
TRIAL_ACTIVATION_TTL_SECONDS = 10 * 60
TRIAL_DURATION_SECONDS = 14 * 24 * 60 * 60
APP_SESSION_DURATION_SECONDS = 30 * 24 * 60 * 60
PLAYBACK_GRANT_TTL_SECONDS = 120
REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES = 180_000
REMOTE_RESPONSE_MAX_STORED_BYTES = 330_000
SAFE_PLAYBACK_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

dynamodb = boto3.resource("dynamodb")
events_table = dynamodb.Table(EVENTS_TABLE) if EVENTS_TABLE else None
profile_settings_table = dynamodb.Table(PROFILE_SETTINGS_TABLE) if PROFILE_SETTINGS_TABLE else None
devices_table = dynamodb.Table(DEVICES_TABLE) if DEVICES_TABLE else None
entitlements_table = dynamodb.Table(ENTITLEMENTS_TABLE) if ENTITLEMENTS_TABLE else None
home_connectors_table = dynamodb.Table(HOME_CONNECTORS_TABLE) if HOME_CONNECTORS_TABLE else None
remote_requests_table = dynamodb.Table(REMOTE_REQUESTS_TABLE) if REMOTE_REQUESTS_TABLE else None
s3_client = boto3.client("s3") if REMOTE_PAYLOADS_BUCKET or PROFILE_AVATARS_BUCKET else None
app_sessions_table = dynamodb.Table(APP_SESSIONS_TABLE) if APP_SESSIONS_TABLE else None


DEFAULT_PROFILE_SETTINGS = {
    "display_name": "Kaevo Profile",
    "profile_type": "adult",
    "enable_cloud_personalization": True,
    "autoplay_next_episode": True,
    "discovery_provider": "automatic",
    "request_provider": "disabled",
    "download_recovery_provider": "disabled",
    "download_recovery_mode": "notify_only",
    "preferred_home_layout": "standard"
}

DEFAULT_ENTITLEMENTS = {
    "plan": "free",
    "subscription_state": "inactive",
    "cloud_enabled": False,
    "family_enabled": False,
    "family_seats": 1,
    "product_id": "",
    "source": "manual_dev",
    "renews_at": "",
    "expires_at": "",
    "feature_flags": {}
}


def extract_profile_id_from_avatar_path(path):
    match = re.fullmatch(r"/v1/profiles/([^/]+)/avatar", path or "")
    return match.group(1) if match else ""


def profile_avatar_key(profile_id):
    digest = hashlib.sha256(str(profile_id).encode("utf-8")).hexdigest()
    return f"profile-avatars/{digest}.jpg"


def profile_avatar_cloud_allowed(event, profile_id):
    if require_dev_key(event):
        return True
    entitlements, _ = load_entitlements_for_profile(profile_id)
    return bool_value(entitlements.get("cloud_enabled"), False)


def put_profile_avatar(event, path):
    profile_id = extract_profile_id_from_avatar_path(path)
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "invalid profile avatar path"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})
    if not profile_avatar_cloud_allowed(event, profile_id):
        return response(403, {"state": "cloud_inactive", "message": "Cloud Access is required for profile photo sync"})
    if not PROFILE_AVATARS_BUCKET or s3_client is None:
        return response(503, {"state": "unavailable", "message": "profile avatar storage is not configured"})

    body = parse_json_body(event)
    encoded = str((body or {}).get("jpeg_base64") or "")
    try:
        image_data = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        return response(400, {"state": "bad_request", "message": "jpeg_base64 is invalid"})
    if not image_data or len(image_data) > 400_000:
        return response(400, {"state": "bad_request", "message": "profile photo must be 400 KB or smaller"})
    if not image_data.startswith(b"\xff\xd8\xff"):
        return response(400, {"state": "bad_request", "message": "profile photo must be a JPEG"})

    updated_at = utc_now_iso()
    s3_client.put_object(
        Bucket=PROFILE_AVATARS_BUCKET,
        Key=profile_avatar_key(profile_id),
        Body=image_data,
        ContentType="image/jpeg",
        CacheControl="private, max-age=300",
        Metadata={"profile-id-hash": hashlib.sha256(profile_id.encode("utf-8")).hexdigest(), "updated-at": updated_at}
    )
    return response(200, {"state": "saved", "profile_id": profile_id, "updated_at": updated_at})


def get_profile_avatar(event, path):
    profile_id = extract_profile_id_from_avatar_path(path)
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "invalid profile avatar path"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})
    if not profile_avatar_cloud_allowed(event, profile_id):
        return response(403, {"state": "cloud_inactive", "message": "Cloud Access is required for profile photo sync"})
    if not PROFILE_AVATARS_BUCKET or s3_client is None:
        return response(503, {"state": "unavailable", "message": "profile avatar storage is not configured"})
    try:
        avatar = s3_client.get_object(Bucket=PROFILE_AVATARS_BUCKET, Key=profile_avatar_key(profile_id))
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code")) in {"NoSuchKey", "404"}:
            return response(404, {"state": "not_found"})
        raise

    image_data = avatar["Body"].read()
    return response(200, {
        "state": "ready",
        "profile_id": profile_id,
        "jpeg_base64": base64.b64encode(image_data).decode("ascii"),
        "updated_at": avatar.get("LastModified").astimezone(timezone.utc).isoformat() if avatar.get("LastModified") else None
    })


def delete_profile_avatar(event, path):
    profile_id = extract_profile_id_from_avatar_path(path)
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "invalid profile avatar path"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})
    if not profile_avatar_cloud_allowed(event, profile_id):
        return response(403, {"state": "cloud_inactive", "message": "Cloud Access is required for profile photo sync"})
    if not PROFILE_AVATARS_BUCKET or s3_client is None:
        return response(503, {"state": "unavailable", "message": "profile avatar storage is not configured"})
    s3_client.delete_object(Bucket=PROFILE_AVATARS_BUCKET, Key=profile_avatar_key(profile_id))
    return response(200, {"state": "deleted", "profile_id": profile_id})

PROVIDER_SETTING_KEYS = [
    "discovery_provider",
    "request_provider",
    "download_recovery_provider",
    "download_recovery_mode"
]


def json_default(value):
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)

    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body, default=json_default)
    }


def normalized_path(event):
    path = event.get("rawPath") or event.get("path") or "/"
    stage = event.get("requestContext", {}).get("stage")

    if stage and stage != "$default":
        prefix = f"/{stage}"

        if path == prefix:
            return "/"

        if path.startswith(prefix + "/"):
            return path[len(prefix):]

    return path


def method_for(event):
    return (
        event.get("requestContext", {})
        .get("http", {})
        .get("method")
        or event.get("httpMethod")
        or "GET"
    )


def query_params(event):
    return event.get("queryStringParameters") or {}


def header_value(event, name):
    headers = event.get("headers") or {}
    target = name.lower()

    for key, value in headers.items():
        if key.lower() == target:
            return value

    return None


def require_dev_key(event):
    return bool(DEV_API_KEY) and hmac.compare_digest(
        str(header_value(event, "x-kaevo-dev-key") or ""),
        str(DEV_API_KEY)
    )


def secret_hash(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def app_bearer_token(event):
    authorization = str(header_value(event, "authorization") or "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def authenticated_app_session(event):
    token = app_bearer_token(event)
    if not token or app_sessions_table is None:
        return None
    item = app_sessions_table.get_item(Key={"token_hash": secret_hash(token)}).get("Item")
    if not item or item.get("record_type") != "app_session":
        return None
    if item.get("state") != "active" or bool_value(item.get("revoked"), False):
        return None
    if int(item.get("expires_at") or 0) < epoch_now():
        return None
    return item


def require_profile_auth(event, profile_id):
    if require_dev_key(event):
        return True
    session = authenticated_app_session(event)
    return bool(
        session
        and profile_id
        and hmac.compare_digest(str(session.get("profile_id") or ""), str(profile_id))
    )


def base64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign_playback_grant(payload):
    if len(PLAYBACK_GRANT_SIGNING_KEY) < 32:
        return None
    encoded = base64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(PLAYBACK_GRANT_SIGNING_KEY.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{base64url_encode(signature)}"


def avfoundation_safe_grant_path(token, chunk_size=180):
    """Represent a signed grant using path components AVFoundation will request."""
    return "/".join(token[index:index + chunk_size] for index in range(0, len(token), chunk_size))


def add_home_connector_signature(payload, connector_grant_key):
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(connector_grant_key.encode("utf-8"), canonical, hashlib.sha256).digest()
    return {**payload, "home_sig": base64url_encode(signature)}


def create_connector_relay_ticket(event, path):
    connector_id = path.removeprefix("/v1/home-connectors/").removesuffix("/relay-ticket").strip("/")
    if not require_connector_auth(event, connector_id):
        return response(401, {"state": "connector_unauthorized"})
    now = epoch_now()
    ticket = sign_playback_grant({
        "v": 1,
        "type": "connector_relay",
        "connector_id": connector_id,
        "nonce": secrets.token_urlsafe(24),
        "iat": now,
        "nbf": now - 5,
        "exp": now + 300
    })
    if ticket is None:
        return response(503, {"state": "playback_grants_not_configured"})
    return response(201, {"state": "issued", "relay_ticket": ticket, "expires_at": now + 300})


def connector_bearer_token(event):
    authorization = header_value(event, "authorization") or ""
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return header_value(event, "x-kaevo-connector-token") or ""


def require_connector_auth(event, connector_id):
    if home_connectors_table is None or not connector_id:
        return False
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")
    if not item or item.get("auth_state") != "active" or bool_value(item.get("revoked"), False):
        return False
    supplied = connector_bearer_token(event)
    expected = str(item.get("connector_token_hash") or "")
    return bool(supplied and expected and hmac.compare_digest(secret_hash(supplied), expected))


def parse_json_body(event):
    raw_body = event.get("body") or "{}"

    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")

    try:
        return json.loads(raw_body)
    except json.JSONDecodeError:
        return None


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def epoch_now():
    return int(time.time())


def bool_value(value, default=False):
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}

    return bool(value)


def parse_json_field(value, default):
    if not value:
        return default

    if isinstance(value, dict) or isinstance(value, list):
        return value

    try:
        parsed = json.loads(value)
        return parsed
    except Exception:
        return default


def public_event_item(item):
    metadata = parse_json_field(item.get("metadata_json"), {})

    return {
        "profile_id": item.get("profile_id"),
        "event_id": item.get("event_id"),
        "event_type": item.get("event_type"),
        "item_id": item.get("item_id"),
        "device_type": item.get("device_type"),
        "source": item.get("source"),
        "session_id": item.get("session_id"),
        "timestamp": item.get("timestamp"),
        "received_at": item.get("received_at"),
        "expires_at": item.get("expires_at"),
        "metadata": metadata
    }


def build_event_item(body, inherited_profile_id=None):
    profile_id = str(body.get("profile_id") or inherited_profile_id or "").strip()
    event_type = str(body.get("event_type") or "").strip()

    if not profile_id:
        return None, "profile_id is required"

    if not event_type:
        return None, "event_type is required"

    now = utc_now_iso()
    timestamp = str(body.get("timestamp") or now)
    event_id = str(uuid.uuid4())
    event_key = f"{timestamp}#{event_id}"

    metadata = body.get("metadata") or {}

    item = {
        "profile_id": profile_id,
        "event_key": event_key,
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "received_at": now,
        "item_id": str(body.get("item_id") or ""),
        "device_type": str(body.get("device_type") or ""),
        "source": str(body.get("source") or ""),
        "session_id": str(body.get("session_id") or ""),
        "metadata_json": json.dumps(metadata, separators=(",", ":")),
        "expires_at": epoch_now() + (90 * 24 * 60 * 60)
    }

    return item, None


def save_event(event):
    if events_table is None:
        return response(500, {"state": "server_error", "message": "events table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    item, error = build_event_item(body)

    if error:
        return response(400, {"state": "bad_request", "message": error})
    if not require_profile_auth(event, item["profile_id"]):
        return response(401, {"state": "unauthorized"})

    events_table.put_item(Item=item)

    return response(202, {"state": "accepted", "event_id": item["event_id"]})


def save_event_batch(event):
    if events_table is None:
        return response(500, {"state": "server_error", "message": "events table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    events = body.get("events")
    inherited_profile_id = body.get("profile_id")

    if not isinstance(events, list) or len(events) == 0:
        return response(400, {"state": "bad_request", "message": "events must be a non-empty array"})

    if len(events) > MAX_BATCH_EVENTS:
        return response(400, {"state": "bad_request", "message": f"events batch cannot exceed {MAX_BATCH_EVENTS}"})

    items = []
    errors = []

    for index, event_body in enumerate(events):
        if not isinstance(event_body, dict):
            errors.append({"index": index, "message": "event must be an object"})
            continue

        item, error = build_event_item(event_body, inherited_profile_id=inherited_profile_id)

        if error:
            errors.append({"index": index, "message": error})
            continue

        items.append(item)

    if errors:
        return response(400, {"state": "bad_request", "errors": errors})
    if any(not require_profile_auth(event, item["profile_id"]) for item in items):
        return response(401, {"state": "unauthorized"})

    with events_table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)

    return response(202, {
        "state": "accepted",
        "accepted": len(items),
        "event_ids": [item["event_id"] for item in items]
    })


def recent_events(event):
    if events_table is None:
        return response(500, {"state": "server_error", "message": "events table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    result = events_table.query(
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    return response(200, {
        "profile_id": profile_id,
        "items": [public_event_item(item) for item in result.get("Items", [])]
    })


def extract_profile_id_from_settings_path(path):
    prefix = "/v1/profiles/"
    suffix = "/settings"

    if path.startswith(prefix) and path.endswith(suffix):
        return path[len(prefix):-len(suffix)].strip("/")

    return ""


def load_full_profile_settings(profile_id):
    settings = DEFAULT_PROFILE_SETTINGS.copy()

    result = profile_settings_table.get_item(Key={"profile_id": profile_id})
    item = result.get("Item")

    if item:
        saved_settings = parse_json_field(item.get("settings_json"), {})
        if isinstance(saved_settings, dict):
            settings.update(saved_settings)

    return settings, item


def get_profile_settings(event, path):
    if profile_settings_table is None:
        return response(500, {"state": "server_error", "message": "profile settings table is not configured"})

    profile_id = extract_profile_id_from_settings_path(path)

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profileId is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    settings, item = load_full_profile_settings(profile_id)

    if not item:
        return response(200, {
            "profile_id": profile_id,
            "settings": settings,
            "exists": False
        })

    return response(200, {
        "profile_id": profile_id,
        "settings": settings,
        "exists": True,
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at")
    })


def put_profile_settings(event, path):
    if profile_settings_table is None:
        return response(500, {"state": "server_error", "message": "profile settings table is not configured"})

    profile_id = extract_profile_id_from_settings_path(path)

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profileId is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    incoming_settings = body.get("settings") if isinstance(body.get("settings"), dict) else body

    if not isinstance(incoming_settings, dict):
        return response(400, {"state": "bad_request", "message": "settings must be an object"})

    current_settings, current_item = load_full_profile_settings(profile_id)

    now = utc_now_iso()
    created_at = current_item.get("created_at") if current_item else now

    current_settings.update(incoming_settings)

    profile_settings_table.put_item(Item={
        "profile_id": profile_id,
        "settings_json": json.dumps(current_settings, separators=(",", ":")),
        "created_at": created_at,
        "updated_at": now
    })

    return response(200, {
        "profile_id": profile_id,
        "settings": current_settings,
        "created_at": created_at,
        "updated_at": now
    })


def provider_settings_from_full_settings(settings):
    return {
        "discovery_provider": settings.get("discovery_provider", "automatic"),
        "request_provider": settings.get("request_provider", "disabled"),
        "download_recovery_provider": settings.get("download_recovery_provider", "disabled"),
        "download_recovery_mode": settings.get("download_recovery_mode", "notify_only")
    }


def get_provider_settings(event):
    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(200, {
            "profile_id": None,
            "settings": provider_settings_from_full_settings(DEFAULT_PROFILE_SETTINGS),
            "exists": False,
            "note": "Add ?profile_id=profile_123 to read saved provider settings."
        })
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    if profile_settings_table is None:
        return response(500, {"state": "server_error", "message": "profile settings table is not configured"})

    full_settings, item = load_full_profile_settings(profile_id)

    return response(200, {
        "profile_id": profile_id,
        "settings": provider_settings_from_full_settings(full_settings),
        "exists": item is not None,
        "updated_at": item.get("updated_at") if item else None
    })


def put_provider_settings(event):
    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id query parameter is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    if profile_settings_table is None:
        return response(500, {"state": "server_error", "message": "profile settings table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    incoming = body.get("settings") if isinstance(body.get("settings"), dict) else body

    if not isinstance(incoming, dict):
        return response(400, {"state": "bad_request", "message": "settings must be an object"})

    allowed_updates = {
        key: incoming[key]
        for key in PROVIDER_SETTING_KEYS
        if key in incoming
    }

    if not allowed_updates:
        return response(400, {"state": "bad_request", "message": "no provider settings were provided"})

    current_settings, item = load_full_profile_settings(profile_id)

    now = utc_now_iso()
    created_at = item.get("created_at") if item else now

    current_settings.update(allowed_updates)

    profile_settings_table.put_item(Item={
        "profile_id": profile_id,
        "settings_json": json.dumps(current_settings, separators=(",", ":")),
        "created_at": created_at,
        "updated_at": now
    })

    return response(200, {
        "profile_id": profile_id,
        "settings": provider_settings_from_full_settings(current_settings),
        "created_at": created_at,
        "updated_at": now
    })


def public_device_item(item):
    return {
        "device_id": item.get("device_id"),
        "profile_id": item.get("profile_id"),
        "device_name": item.get("device_name"),
        "device_type": item.get("device_type"),
        "platform": item.get("platform"),
        "app_version": item.get("app_version"),
        "os_version": item.get("os_version"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "last_seen_at": item.get("last_seen_at")
    }


def register_device(event):
    if devices_table is None:
        return response(500, {"state": "server_error", "message": "devices table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    profile_id = str(body.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    device_id = str(body.get("device_id") or uuid.uuid4()).strip()
    now = utc_now_iso()

    existing = devices_table.get_item(Key={"device_id": device_id}).get("Item")
    created_at = existing.get("created_at") if existing else now

    item = {
        "device_id": device_id,
        "profile_id": profile_id,
        "device_name": str(body.get("device_name") or "Kaevo Device"),
        "device_type": str(body.get("device_type") or "unknown"),
        "platform": str(body.get("platform") or ""),
        "app_version": str(body.get("app_version") or ""),
        "os_version": str(body.get("os_version") or ""),
        "created_at": created_at,
        "updated_at": now,
        "last_seen_at": now
    }

    devices_table.put_item(Item=item)

    return response(200, {"state": "registered", "device": public_device_item(item)})


def list_devices(event):
    if devices_table is None:
        return response(500, {"state": "server_error", "message": "devices table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id query parameter is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    result = devices_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=25
    )

    return response(200, {
        "profile_id": profile_id,
        "items": [public_device_item(item) for item in result.get("Items", [])]
    })


def load_entitlements_for_profile(profile_id):
    entitlements = DEFAULT_ENTITLEMENTS.copy()

    if entitlements_table is None:
        return entitlements, None

    result = entitlements_table.get_item(Key={"profile_id": profile_id})
    item = result.get("Item")

    if item:
        saved = parse_json_field(item.get("entitlements_json"), {})
        if isinstance(saved, dict):
            entitlements.update(saved)

    return entitlements, item


def get_entitlements(event):
    if entitlements_table is None:
        return response(500, {"state": "server_error", "message": "entitlements table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id query parameter is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    entitlements, item = load_entitlements_for_profile(profile_id)

    if not item:
        return response(200, {
            "profile_id": profile_id,
            "entitlements": entitlements,
            "exists": False
        })

    return response(200, {
        "profile_id": profile_id,
        "entitlements": entitlements,
        "exists": True,
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at")
    })


def put_entitlements(event):
    if not require_dev_key(event):
        return response(401, {"state": "unauthorized"})

    if entitlements_table is None:
        return response(500, {"state": "server_error", "message": "entitlements table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id query parameter is required"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    incoming = body.get("entitlements") if isinstance(body.get("entitlements"), dict) else body

    if not isinstance(incoming, dict):
        return response(400, {"state": "bad_request", "message": "entitlements must be an object"})

    entitlements, current_item = load_entitlements_for_profile(profile_id)

    now = utc_now_iso()
    created_at = current_item.get("created_at") if current_item else now

    entitlements.update(incoming)

    entitlements_table.put_item(Item={
        "profile_id": profile_id,
        "entitlements_json": json.dumps(entitlements, separators=(",", ":")),
        "created_at": created_at,
        "updated_at": now
    })

    return response(200, {
        "profile_id": profile_id,
        "entitlements": entitlements,
        "created_at": created_at,
        "updated_at": now
    })


def recent_home_events(profile_id, limit=25):
    if events_table is None:
        return []

    result = events_table.query(
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=limit
    )

    return result.get("Items", [])


def make_event_item(item, reason):
    metadata = parse_json_field(item.get("metadata_json"), {})
    item_id = item.get("item_id") or ""

    return {
        "item_id": item_id,
        "title": item_id or item.get("event_type", "Kaevo Activity"),
        "source": item.get("source", ""),
        "device_type": item.get("device_type", ""),
        "reason": reason,
        "last_event_type": item.get("event_type"),
        "last_event_at": item.get("timestamp"),
        "metadata": metadata
    }


def unique_items_from_events(events, allowed_types, reason, require_item_id=True, max_items=10):
    seen = set()
    items = []

    for event_item in events:
        event_type = event_item.get("event_type")
        item_id = event_item.get("item_id") or ""

        if event_type not in allowed_types:
            continue

        if require_item_id and not item_id:
            continue

        key = item_id or f"{event_type}:{event_item.get('timestamp')}"

        if key in seen:
            continue

        seen.add(key)
        items.append(make_event_item(event_item, reason))

        if len(items) >= max_items:
            break

    return items


def search_items_from_events(events, max_items=5):
    items = []

    for event_item in events:
        if event_item.get("event_type") != "searched":
            continue

        metadata = parse_json_field(event_item.get("metadata_json"), {})
        query = str(metadata.get("query") or "").strip()

        if not query:
            continue

        items.append({
            "item_id": f"search:{query}",
            "title": query,
            "source": event_item.get("source", "kaevo"),
            "device_type": event_item.get("device_type", ""),
            "reason": "Recent search",
            "last_event_type": "searched",
            "last_event_at": event_item.get("timestamp"),
            "metadata": metadata
        })

        if len(items) >= max_items:
            break

    return items


def get_personalized_home(event):
    params = query_params(event)
    profile_id = str(params.get("profile_id") or "profile_stub").strip()
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    settings, settings_item = load_full_profile_settings(profile_id)
    entitlements, entitlement_item = load_entitlements_for_profile(profile_id)
    events = recent_home_events(profile_id)

    continue_items = unique_items_from_events(
        events,
        allowed_types={"play_started", "playback_progress"},
        reason="Recently played",
        require_item_id=True,
        max_items=10
    )

    recent_interest_items = unique_items_from_events(
        events,
        allowed_types={"view_details", "play_started"},
        reason="Based on recent activity",
        require_item_id=True,
        max_items=10
    )

    search_items = search_items_from_events(events)

    rows = [
        {
            "row_id": "continue_watching",
            "title": "Continue Watching",
            "type": "continue_watching",
            "reason": "Items with recent playback activity",
            "items": continue_items,
            "rank": 10,
            "source": "kaevo_cloud"
        },
        {
            "row_id": "recent_activity",
            "title": "Because Of Your Recent Activity",
            "type": "recent_activity",
            "reason": "Items you recently viewed or played",
            "items": recent_interest_items,
            "rank": 20,
            "source": "kaevo_cloud"
        },
        {
            "row_id": "recent_searches",
            "title": "Recent Searches",
            "type": "recent_searches",
            "reason": "Searches captured from your devices",
            "items": search_items,
            "rank": 30,
            "source": "kaevo_cloud"
        },
        {
            "row_id": "cloud_status",
            "title": "Kaevo Cloud",
            "type": "cloud_status",
            "reason": "Current cloud and provider status",
            "items": [
                {
                    "item_id": "kaevo_cloud_status",
                    "title": f"Plan: {entitlements.get('plan', 'free')}",
                    "source": "kaevo_cloud",
                    "device_type": "",
                    "reason": "Cloud entitlement status",
                    "metadata": {
                        "cloud_enabled": entitlements.get("cloud_enabled", False),
                        "family_enabled": entitlements.get("family_enabled", False),
                        "subscription_state": entitlements.get("subscription_state", "inactive"),
                        "discovery_provider": settings.get("discovery_provider", "automatic"),
                        "request_provider": settings.get("request_provider", "disabled"),
                        "download_recovery_mode": settings.get("download_recovery_mode", "notify_only")
                    }
                }
            ],
            "rank": 90,
            "source": "kaevo_cloud"
        }
    ]

    return response(200, {
        "profile_id": profile_id,
        "generated_at": utc_now_iso(),
        "settings_exists": settings_item is not None,
        "entitlements_exists": entitlement_item is not None,
        "rows": rows
    })


def connector_online_from_item(item):
    last_seen_epoch = int(item.get("last_seen_epoch") or 0)
    return (epoch_now() - last_seen_epoch) <= CONNECTOR_ONLINE_WINDOW_SECONDS


def public_connector_item(item):
    provider_status = parse_json_field(item.get("provider_status_json"), {})
    capabilities = parse_json_field(item.get("capabilities_json"), [])

    online = connector_online_from_item(item)

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
        "capabilities": capabilities,
        "provider_status": provider_status
    }


def create_pairing_record(profile_id, connector_name):
    connector_id = str(uuid.uuid4())
    pairing_code = "-".join([
        secrets.token_hex(2).upper(),
        secrets.token_hex(2).upper(),
        secrets.token_hex(2).upper(),
    ])
    now = utc_now_iso()
    expires_at = epoch_now() + CONNECTOR_PAIRING_TTL_SECONDS
    home_connectors_table.put_item(Item={
        "connector_id": connector_id,
        "profile_id": profile_id,
        "connector_name": str(connector_name or "Kaevo Jellyfin Plugin")[:80],
        "host_type": "jellyfin_plugin",
        "app_version": "",
        "auth_state": "pairing",
        "pairing_code_hash": secret_hash(pairing_code),
        "pairing_expires_at": expires_at,
        "revoked": False,
        "created_at": now,
        "updated_at": now,
        "last_seen_at": "",
        "last_seen_epoch": 0,
        "capabilities_json": "[]",
        "provider_status_json": "{}"
    })
    return connector_id, pairing_code, expires_at


def start_cloud_trial(event):
    if home_connectors_table is None or app_sessions_table is None:
        return response(500, {"state": "server_error", "message": "Cloud trial storage is not configured"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    installation_id = str(body.get("installation_id") or "").strip()
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(installation_id):
        return response(400, {"state": "bad_request", "message": "valid installation_id is required"})

    profile_id = f"profile-{uuid.uuid4()}"
    connector_id, pairing_code, pairing_expires_at = create_pairing_record(
        profile_id,
        body.get("connector_name")
    )
    activation_token = secrets.token_urlsafe(32)
    activation_expires_at = min(
        pairing_expires_at,
        epoch_now() + TRIAL_ACTIVATION_TTL_SECONDS
    )
    app_sessions_table.put_item(Item={
        "token_hash": secret_hash(activation_token),
        "record_type": "trial_activation",
        "state": "awaiting_plugin",
        "profile_id": profile_id,
        "connector_id": connector_id,
        "installation_id_hash": secret_hash(installation_id),
        "created_at": utc_now_iso(),
        "expires_at": activation_expires_at
    })
    return response(201, {
        "state": "trial_created",
        "profile_id": profile_id,
        "connector_id": connector_id,
        "pairing_code": pairing_code,
        "activation_token": activation_token,
        "expires_at": activation_expires_at
    })


def activate_cloud_trial(event):
    if home_connectors_table is None or app_sessions_table is None or entitlements_table is None:
        return response(500, {"state": "server_error", "message": "Cloud trial storage is not configured"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    activation_token = str(body.get("activation_token") or "").strip()
    if not activation_token:
        return response(400, {"state": "bad_request", "message": "activation_token is required"})

    activation_hash = secret_hash(activation_token)
    activation = app_sessions_table.get_item(Key={"token_hash": activation_hash}).get("Item")
    valid = (
        activation
        and activation.get("record_type") == "trial_activation"
        and activation.get("state") == "awaiting_plugin"
        and int(activation.get("expires_at") or 0) >= epoch_now()
    )
    if not valid:
        return response(401, {"state": "activation_invalid"})

    connector_id = str(activation.get("connector_id") or "")
    profile_id = str(activation.get("profile_id") or "")
    connector = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")
    if not connector or connector.get("auth_state") != "active" or connector.get("profile_id") != profile_id:
        return response(409, {"state": "plugin_pending", "message": "Kaevo Plugin activation is still in progress."})

    now_epoch = epoch_now()
    trial_expires_at = now_epoch + TRIAL_DURATION_SECONDS
    session_token = issue_app_session(
        profile_id,
        connector_id,
        activation.get("installation_id_hash"),
        trial_expires_at,
        "plugin_confirmed_trial"
    )
    activation["state"] = "consumed"
    activation["consumed_at"] = utc_now_iso()
    activation["expires_at"] = now_epoch + 60 * 60
    app_sessions_table.put_item(Item=activation)

    entitlement = {
        **DEFAULT_ENTITLEMENTS,
        "plan": "individual",
        "subscription_state": "trialing",
        "cloud_enabled": True,
        "source": "plugin_confirmed_trial",
        "feature_flags": {
            "remote_playback": True,
            "remote_playback_relay": True
        },
        "started_at": utc_now_iso(),
        "expires_at": datetime.fromtimestamp(trial_expires_at, timezone.utc).isoformat()
    }
    entitlement_now = utc_now_iso()
    entitlements_table.put_item(Item={
        "profile_id": profile_id,
        "entitlements_json": json.dumps(entitlement, separators=(",", ":")),
        "created_at": entitlement_now,
        "updated_at": entitlement_now
    })
    return response(200, {
        "state": "remote_access_ready",
        "profile_id": profile_id,
        "connector_id": connector_id,
        "session_token": session_token,
        "session_expires_at": trial_expires_at,
        "entitlements": entitlement
    })


def issue_app_session(profile_id, connector_id, installation_id_hash, expires_at, source):
    session_token = secrets.token_urlsafe(48)
    now = utc_now_iso()
    app_sessions_table.put_item(Item={
        "token_hash": secret_hash(session_token),
        "record_type": "app_session",
        "state": "active",
        "profile_id": profile_id,
        "connector_id": connector_id,
        "installation_id_hash": installation_id_hash,
        "source": source,
        "created_at": now,
        "last_seen_at": now,
        "revoked": False,
        "expires_at": expires_at
    })
    return session_token


def app_session_expiration(entitlement):
    maximum = epoch_now() + APP_SESSION_DURATION_SECONDS
    raw_expiration = str(entitlement.get("expires_at") or "").strip()
    if not raw_expiration:
        return maximum
    try:
        entitlement_expiration = int(datetime.fromisoformat(raw_expiration.replace("Z", "+00:00")).timestamp())
    except (TypeError, ValueError):
        return maximum
    return min(maximum, entitlement_expiration)


def migrate_existing_app_session(event):
    if not require_dev_key(event):
        return response(401, {"state": "unauthorized"})
    if home_connectors_table is None or app_sessions_table is None or entitlements_table is None:
        return response(500, {"state": "server_error", "message": "Cloud session storage is not configured"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    profile_id = str(body.get("profile_id") or "").strip()
    connector_id = str(body.get("connector_id") or "").strip()
    installation_id = str(body.get("installation_id") or "").strip()
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(profile_id):
        return response(400, {"state": "bad_request", "message": "valid profile_id is required"})
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(connector_id):
        return response(400, {"state": "bad_request", "message": "valid connector_id is required"})
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(installation_id):
        return response(400, {"state": "bad_request", "message": "valid installation_id is required"})

    connector = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")
    connector_online = bool(
        connector
        and connector.get("auth_state") == "active"
        and not bool_value(connector.get("revoked"), False)
        and hmac.compare_digest(str(connector.get("profile_id") or ""), profile_id)
        and int(connector.get("last_seen_epoch") or 0) >= epoch_now() - CONNECTOR_ONLINE_WINDOW_SECONDS
    )
    if not connector_online:
        return response(409, {"state": "plugin_offline", "message": "Kaevo Plugin must be online to finish migration."})

    entitlement, _ = load_entitlements_for_profile(profile_id)
    if not bool_value(entitlement.get("cloud_enabled"), False):
        return response(409, {"state": "cloud_inactive", "message": "Remote Access is not active for this profile."})

    expires_at = app_session_expiration(entitlement)
    if expires_at <= epoch_now():
        return response(409, {"state": "cloud_expired", "message": "Remote Access has expired for this profile."})
    session_token = issue_app_session(
        profile_id,
        connector_id,
        secret_hash(installation_id),
        expires_at,
        "legacy_credential_migration"
    )
    return response(200, {
        "state": "remote_access_ready",
        "profile_id": profile_id,
        "connector_id": connector_id,
        "session_token": session_token,
        "session_expires_at": expires_at,
        "entitlements": entitlement
    })


def refresh_app_session(event):
    session = authenticated_app_session(event)
    if not session:
        return response(401, {"state": "unauthorized"})
    profile_id = str(session.get("profile_id") or "")
    entitlement, _ = load_entitlements_for_profile(profile_id)
    if not bool_value(entitlement.get("cloud_enabled"), False):
        return response(403, {"state": "cloud_inactive"})

    expires_at = app_session_expiration(entitlement)
    if expires_at <= epoch_now():
        return response(403, {"state": "entitlement_expired"})
    session_token = issue_app_session(
        profile_id,
        str(session.get("connector_id") or ""),
        session.get("installation_id_hash"),
        expires_at,
        "session_rotation"
    )
    session["rotated_at"] = utc_now_iso()
    session["expires_at"] = min(int(session.get("expires_at") or expires_at), epoch_now() + 24 * 60 * 60)
    app_sessions_table.put_item(Item=session)
    return response(200, {
        "state": "session_refreshed",
        "profile_id": profile_id,
        "connector_id": session.get("connector_id"),
        "session_token": session_token,
        "session_expires_at": expires_at,
        "entitlements": entitlement
    })


def get_app_session_status(event):
    session = authenticated_app_session(event)
    if not session:
        return response(401, {"state": "unauthorized"})
    session["last_verified_at"] = utc_now_iso()
    app_sessions_table.put_item(Item=session)
    profile_id = str(session.get("profile_id") or "")
    entitlement, _ = load_entitlements_for_profile(profile_id)
    return response(200, {
        "state": "remote_access_ready",
        "profile_id": profile_id,
        "connector_id": session.get("connector_id"),
        "session_expires_at": int(session.get("expires_at") or 0),
        "entitlements": entitlement
    })


def revoke_app_session(event):
    session = authenticated_app_session(event)
    if not session:
        return response(401, {"state": "unauthorized"})
    session["state"] = "revoked"
    session["revoked"] = True
    session["revoked_at"] = utc_now_iso()
    app_sessions_table.put_item(Item=session)
    return response(200, {"state": "signed_out"})


def start_connector_pairing(event):
    if not require_dev_key(event):
        return response(401, {"state": "unauthorized"})
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    profile_id = str(body.get("profile_id") or "").strip()
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    connector_id, pairing_code, expires_at = create_pairing_record(
        profile_id,
        body.get("connector_name")
    )
    return response(201, {
        "state": "pairing_created",
        "connector_id": connector_id,
        "pairing_code": pairing_code,
        "expires_at": expires_at
    })


def exchange_connector_pairing(event):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    connector_id = str(body.get("connector_id") or "").strip()
    pairing_code = str(body.get("pairing_code") or "").strip().upper()
    if not connector_id or not pairing_code:
        return response(400, {"state": "bad_request", "message": "connector_id and pairing_code are required"})
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")
    valid = (
        item
        and item.get("auth_state") == "pairing"
        and int(item.get("pairing_expires_at") or 0) >= epoch_now()
        and hmac.compare_digest(secret_hash(pairing_code), str(item.get("pairing_code_hash") or ""))
    )
    if not valid:
        return response(401, {"state": "pairing_invalid"})
    connector_token = secrets.token_urlsafe(32)
    playback_grant_key = secrets.token_urlsafe(32)
    now = utc_now_iso()
    item["auth_state"] = "active"
    item["connector_token_hash"] = secret_hash(connector_token)
    item["playback_grant_key"] = playback_grant_key
    item["paired_at"] = now
    item["updated_at"] = now
    item.pop("pairing_code_hash", None)
    item.pop("pairing_expires_at", None)
    home_connectors_table.put_item(Item=item)
    return response(200, {
        "state": "paired",
        "connector_id": connector_id,
        "profile_id": item.get("profile_id"),
        "connector_token": connector_token,
        "playback_grant_key": playback_grant_key
    })


def revoke_home_connector(event, path):
    if not require_dev_key(event):
        return response(401, {"state": "unauthorized"})
    connector_id = path.removeprefix("/v1/home-connectors/").removesuffix("/revoke").strip("/")
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item") if home_connectors_table else None
    if not item:
        return response(404, {"state": "not_found"})
    item["revoked"] = True
    item["auth_state"] = "revoked"
    item["updated_at"] = utc_now_iso()
    item.pop("connector_token_hash", None)
    home_connectors_table.put_item(Item=item)
    return response(200, {"state": "revoked", "connector_id": connector_id})


def register_home_connector(event):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    profile_id = str(body.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})

    connector_id = str(body.get("connector_id") or uuid.uuid4()).strip()
    if not require_connector_auth(event, connector_id):
        return response(401, {"state": "connector_unauthorized"})
    now = utc_now_iso()
    now_epoch = epoch_now()

    existing = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")
    created_at = existing.get("created_at") if existing else now

    capabilities = body.get("capabilities") if isinstance(body.get("capabilities"), list) else [
        "heartbeat",
        "provider_status",
        "remote_route_control_plane"
    ]

    provider_status = body.get("provider_status") if isinstance(body.get("provider_status"), dict) else {}

    item = {
        **(existing or {}),
        "connector_id": connector_id,
        "profile_id": profile_id,
        "connector_name": str(body.get("connector_name") or "Kaevo Jellyfin Plugin"),
        "host_type": str(body.get("host_type") or "unknown"),
        "app_version": str(body.get("app_version") or "0.0.1-dev"),
        "created_at": created_at,
        "updated_at": now,
        "last_seen_at": now,
        "last_seen_epoch": now_epoch,
        "capabilities_json": json.dumps(capabilities, separators=(",", ":")),
        "provider_status_json": json.dumps(provider_status, separators=(",", ":"))
    }

    home_connectors_table.put_item(Item=item)

    return response(200, {
        "state": "registered",
        "connector": public_connector_item(item),
        "playback": {
            "enabled": bool(PLAYBACK_RELAY_PUBLIC_URL),
            "relay_websocket_url": PLAYBACK_RELAY_PUBLIC_URL.replace("https://", "wss://", 1)
                if PLAYBACK_RELAY_PUBLIC_URL.startswith("https://") else ""
        }
    })


def connector_id_from_heartbeat_path(path):
    prefix = "/v1/home-connectors/"
    suffix = "/heartbeat"

    if path.startswith(prefix) and path.endswith(suffix):
        return path[len(prefix):-len(suffix)].strip("/")

    return ""


def heartbeat_home_connector(event, path):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    connector_id = connector_id_from_heartbeat_path(path) or str(body.get("connector_id") or "").strip()

    if not connector_id:
        return response(400, {"state": "bad_request", "message": "connector_id is required"})

    if not require_connector_auth(event, connector_id):
        return response(401, {"state": "connector_unauthorized"})

    existing = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")

    profile_id = str(body.get("profile_id") or (existing or {}).get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required for first heartbeat"})

    now = utc_now_iso()
    now_epoch = epoch_now()

    capabilities = body.get("capabilities")
    if not isinstance(capabilities, list):
        capabilities = parse_json_field((existing or {}).get("capabilities_json"), [
            "heartbeat",
            "provider_status",
            "remote_route_control_plane"
        ])

    provider_status = body.get("provider_status")
    if not isinstance(provider_status, dict):
        provider_status = parse_json_field((existing or {}).get("provider_status_json"), {})

    item = {
        **(existing or {}),
        "connector_id": connector_id,
        "profile_id": profile_id,
        "connector_name": str(body.get("connector_name") or (existing or {}).get("connector_name") or "Kaevo Jellyfin Plugin"),
        "host_type": str(body.get("host_type") or (existing or {}).get("host_type") or "unknown"),
        "app_version": str(body.get("app_version") or (existing or {}).get("app_version") or "0.0.1-dev"),
        "created_at": (existing or {}).get("created_at") or now,
        "updated_at": now,
        "last_seen_at": now,
        "last_seen_epoch": now_epoch,
        "capabilities_json": json.dumps(capabilities, separators=(",", ":")),
        "provider_status_json": json.dumps(provider_status, separators=(",", ":"))
    }

    home_connectors_table.put_item(Item=item)

    return response(200, {
        "state": "online",
        "connector": public_connector_item(item),
        "playback": {
            "enabled": bool(PLAYBACK_RELAY_PUBLIC_URL),
            "relay_websocket_url": PLAYBACK_RELAY_PUBLIC_URL.replace("https://", "wss://", 1)
                if PLAYBACK_RELAY_PUBLIC_URL.startswith("https://") else ""
        }
    })


def get_home_connector_status(event):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id query parameter is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    result = home_connectors_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    connectors = [public_connector_item(item) for item in result.get("Items", [])]
    online_connectors = [item for item in connectors if item.get("online")]

    return response(200, {
        "profile_id": profile_id,
        "state": "online" if online_connectors else ("offline" if connectors else "not_installed"),
        "online": bool(online_connectors),
        "online_count": len(online_connectors),
        "connectors": connectors
    })


def get_remote_routes(event):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id query parameter is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    result = home_connectors_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    connectors = [public_connector_item(item) for item in result.get("Items", [])]
    online_connectors = [item for item in connectors if item.get("online")]
    active_connector = online_connectors[0] if online_connectors else None

    providers = [
        "jellyfin", "playback_tunnel", "seerr", "sonarr", "radarr",
        "lidarr", "readarr", "prowlarr", "bazarr", "tdarr", "downloaders"
    ]
    routes = []

    provider_status = active_connector.get("provider_status", {}) if active_connector else {}

    for provider in providers:
        status = provider_status.get(provider, {}) if isinstance(provider_status, dict) else {}
        provider_ok = (
            bool_value(status.get("ok"), False)
            if isinstance(status, dict)
            else str(status).lower() == "available"
        )

        if active_connector and provider_ok:
            route = "kaevoCloud"
            route_state = "jellyfin_plugin_online"
            remote_ready = True
            reason = "The Kaevo Jellyfin Plugin is online and the requested capability is available."
        elif active_connector:
            route = "unavailable"
            route_state = "provider_not_reachable_from_connector"
            remote_ready = False
            reason = "The Kaevo Jellyfin Plugin is online, but this capability is disabled or unavailable."
        else:
            route = "unavailable"
            route_state = "connector_offline_or_not_installed"
            remote_ready = False
            reason = "No online Kaevo Jellyfin Plugin connector is available."

        routes.append({
            "provider": provider,
            "route": route,
            "route_state": route_state,
            "remote_ready": remote_ready,
            "provider_ok": provider_ok,
            "reason": reason
        })

    return response(200, {
        "profile_id": profile_id,
        "remote_access_stage": "secure_relay_beta",
        "connector_online": active_connector is not None,
        "connector": active_connector,
        "routes": routes,
        "note": "Metadata and playback use the Kaevo Jellyfin Plugin. Playback prefers a direct connection and uses the secure relay only when needed."
    })



REMOTE_REQUEST_TTL_SECONDS = 24 * 60 * 60
REMOTE_COMMAND_ID_NAMESPACE = uuid.UUID("dd84f037-4c25-4b21-a393-6971989adddf")
SAFE_JELLYFIN_ITEM_ID = re.compile(r"^[0-9a-fA-F]{32}$")
SAFE_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
SAFE_APPROVAL_TOKEN = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
SUPPORTED_LOCAL_PROVIDERS = {
    "sonarr", "radarr", "seerr", "lidarr", "readarr", "prowlarr", "bazarr", "tdarr"
}


def positive_int(value, maximum=2_147_483_647):
    if isinstance(value, bool):
        return None

    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None

    return parsed if 1 <= parsed <= maximum else None


def non_negative_int(value, maximum=10_000):
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= maximum else None


def normalize_remote_command(operation, parameters):
    operation = str(operation or "").strip()
    parameters = parameters if isinstance(parameters, dict) else {}

    if operation == "provider.health":
        provider = str(parameters.get("provider") or "").strip().lower()
        if provider not in SUPPORTED_LOCAL_PROVIDERS:
            return None, "provider is not supported"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/provider.health",
            "query": {},
            "body": {"provider": provider}
        }, ""

    if operation in {
        "jellyfin.mark_played",
        "jellyfin.mark_unplayed",
        "jellyfin.favorite",
        "jellyfin.unfavorite",
        "jellyfin.delete_item"
    }:
        item_id = str(parameters.get("item_id") or "").strip()
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return None, "item_id must be a 32-character Jellyfin id"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": f"/commands/{operation}",
            "query": {},
            "body": {"item_id": item_id.lower()}
        }, ""

    if operation == "optimizer.plan_remux":
        item_id = str(parameters.get("item_id") or "").strip()
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return None, "item_id must be a 32-character Jellyfin id"
        strategy = str(parameters.get("strategy") or "automatic").strip()
        if strategy not in {"automatic", "full_video_conversion"}:
            return None, "optimizer strategy is invalid"
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.plan_remux", "query": {},
            "body": {"item_id": item_id.lower(), "strategy": strategy}
        }, ""

    if operation == "jellyfin.prepare_playback":
        item_id = str(parameters.get("item_id") or "").strip()
        device_id = str(parameters.get("device_id") or "").strip()
        max_bitrate = positive_int(parameters.get("max_bitrate") or 40_000_000, maximum=100_000_000)
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return None, "item_id must be a 32-character Jellyfin id"
        if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id):
            return None, "device_id is invalid"
        if max_bitrate is None:
            return None, "max_bitrate is invalid"
        audio_stream_index = None
        subtitle_stream_index = None
        if "audio_stream_index" in parameters:
            audio_stream_index = non_negative_int(parameters.get("audio_stream_index"))
            if audio_stream_index is None:
                return None, "audio_stream_index is invalid"
        if "subtitle_stream_index" in parameters:
            subtitle_stream_index = non_negative_int(parameters.get("subtitle_stream_index"))
            if subtitle_stream_index is None:
                return None, "subtitle_stream_index is invalid"
        compatibility_player = parameters.get("compatibility_player", False)
        if not isinstance(compatibility_player, bool):
            return None, "compatibility_player is invalid"
        playback_body = {
            "item_id": item_id.lower(),
            "device_id": device_id,
            "max_bitrate": max_bitrate,
        }
        if compatibility_player:
            playback_body["compatibility_player"] = True
        if audio_stream_index is not None:
            playback_body["audio_stream_index"] = audio_stream_index
        if subtitle_stream_index is not None:
            playback_body["subtitle_stream_index"] = subtitle_stream_index
        return {
            "provider": "home_server", "method": "COMMAND", "path": "/commands/jellyfin.prepare_playback",
            "query": {}, "body": playback_body
        }, ""

    if operation in {
        "jellyfin.playback_started",
        "jellyfin.playback_progress",
        "jellyfin.playback_stopped"
    }:
        item_id = str(parameters.get("item_id") or "").strip()
        media_source_id = str(parameters.get("media_source_id") or "").strip()
        play_session_id = str(parameters.get("play_session_id") or "").strip()
        try:
            position_ticks = int(parameters.get("position_ticks") or 0)
        except (TypeError, ValueError):
            return None, "position_ticks is invalid"
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return None, "item_id must be a 32-character Jellyfin id"
        if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(media_source_id):
            return None, "media_source_id is invalid"
        if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(play_session_id):
            return None, "play_session_id is invalid"
        if position_ticks < 0 or position_ticks > 100_000_000_000_000:
            return None, "position_ticks is invalid"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": f"/commands/{operation}",
            "query": {},
            "body": {
                "item_id": item_id.lower(),
                "media_source_id": media_source_id,
                "play_session_id": play_session_id,
                "position_ticks": position_ticks,
                "is_paused": bool(parameters.get("is_paused", False))
            }
        }, ""

    if operation == "optimizer.scan":
        limit = positive_int(parameters.get("limit") or 50, maximum=100)
        if limit is None:
            return None, "optimizer scan limit must be between 1 and 100"
        start_index = non_negative_int(parameters.get("start_index") or 0, maximum=1_000_000)
        if start_index is None:
            return None, "optimizer scan start_index must be between 0 and 1000000"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/optimizer.scan",
            "query": {},
            "body": {"limit": limit, "start_index": start_index}
        }, ""

    if operation == "optimizer.execute_remux":
        plan_id = str(parameters.get("plan_id") or "").strip()
        approval_token = str(parameters.get("approval_token") or "").strip()
        confirmation = str(parameters.get("confirmation") or "")
        try:
            normalized_plan_id = str(uuid.UUID(plan_id))
        except (ValueError, TypeError, AttributeError):
            return None, "plan_id must be a UUID"
        if not SAFE_APPROVAL_TOKEN.fullmatch(approval_token):
            return None, "approval_token is invalid"
        if confirmation != "YES_REMUX_ONE_FILE":
            return None, "explicit one-file remux confirmation is required"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/optimizer.execute_remux",
            "query": {},
            "body": {
                "plan_id": normalized_plan_id,
                "approval_token": approval_token,
                "confirmation": confirmation
            }
        }, ""

    if operation == "optimizer.job_status":
        job_id = str(parameters.get("job_id") or "").strip()
        try:
            normalized_job_id = str(uuid.UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            return None, "job_id must be a UUID"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/optimizer.job_status",
            "query": {},
            "body": {"job_id": normalized_job_id}
        }, ""

    if operation == "optimizer.jobs":
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.jobs", "query": {}, "body": {}
        }, ""

    if operation == "optimizer.reorder_job":
        job_id = str(parameters.get("job_id") or "").strip()
        try:
            normalized_job_id = str(uuid.UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            return None, "job_id must be a UUID"
        priority_index = non_negative_int(parameters.get("priority_index"), maximum=10_000)
        if priority_index is None:
            return None, "priority_index must be between 0 and 10000"
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.reorder_job", "query": {},
            "body": {"job_id": normalized_job_id, "priority_index": priority_index}
        }, ""

    if operation == "optimizer.cancel_job":
        job_id = str(parameters.get("job_id") or "").strip()
        try:
            normalized_job_id = str(uuid.UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            return None, "job_id must be a UUID"
        confirmation = str(parameters.get("confirmation") or "")
        if confirmation != "YES_CANCEL_OPTIMIZATION":
            return None, "explicit optimization cancellation confirmation is required"
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.cancel_job", "query": {},
            "body": {"job_id": normalized_job_id, "confirmation": confirmation}
        }, ""

    if operation == "optimizer.cleanup_interrupted":
        item_id = str(parameters.get("item_id") or "").strip()
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return None, "item_id must be a 32-character Jellyfin id"
        confirmation = str(parameters.get("confirmation") or "")
        if confirmation != "YES_REMOVE_KAEVO_PARTIAL":
            return None, "explicit interrupted-output cleanup confirmation is required"
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.cleanup_interrupted", "query": {},
            "body": {"item_id": item_id.lower(), "confirmation": confirmation}
        }, ""

    if operation == "optimizer.pause_job":
        job_id = str(parameters.get("job_id") or "").strip()
        try:
            normalized_job_id = str(uuid.UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            return None, "job_id must be a UUID"
        duration_minutes = non_negative_int(parameters.get("duration_minutes"), maximum=720)
        if duration_minutes not in {0, 60, 360, 720}:
            return None, "duration_minutes must be 0, 60, 360, or 720"
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.pause_job", "query": {},
            "body": {"job_id": normalized_job_id, "duration_minutes": duration_minutes}
        }, ""

    if operation == "optimizer.resume_job":
        job_id = str(parameters.get("job_id") or "").strip()
        try:
            normalized_job_id = str(uuid.UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            return None, "job_id must be a UUID"
        return {
            "provider": "home_server", "method": "COMMAND",
            "path": "/commands/optimizer.resume_job", "query": {},
            "body": {"job_id": normalized_job_id}
        }, ""

    if operation == "seerr.create_request":
        media_type = str(parameters.get("media_type") or "").strip().lower()
        media_id = positive_int(parameters.get("media_id"))
        if media_type not in {"movie", "tv"}:
            return None, "media_type must be movie or tv"
        if media_id is None:
            return None, "media_id must be a positive integer"
        seasons = parameters.get("seasons") or []
        if not isinstance(seasons, list) or len(seasons) > 50:
            return None, "seasons must be a list with at most 50 entries"
        normalized_seasons = []
        for season in seasons:
            parsed = positive_int(season, maximum=100)
            if parsed is None:
                return None, "season values must be between 1 and 100"
            normalized_seasons.append(parsed)
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/seerr.create_request",
            "query": {},
            "body": {
                "media_type": media_type,
                "media_id": media_id,
                "seasons": sorted(set(normalized_seasons)),
                "is_4k": bool(parameters.get("is_4k", False))
            }
        }, ""

    if operation == "seerr.cancel_request":
        request_id = positive_int(parameters.get("request_id"))
        if request_id is None:
            return None, "request_id must be a positive integer"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/seerr.cancel_request",
            "query": {},
            "body": {"request_id": request_id}
        }, ""

    if operation == "sonarr.episode_inventory":
        tvdb_id = positive_int(parameters.get("tvdb_id"))
        if tvdb_id is None:
            return None, "tvdb_id must be a positive integer"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/sonarr.episode_inventory",
            "query": {},
            "body": {"tvdb_id": tvdb_id}
        }, ""

    if operation in {"sonarr.search_episodes", "sonarr.cancel_episodes", "sonarr.remove_episode_files"}:
        raw_ids = parameters.get("episode_ids") or []
        if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 500:
            return None, "episode_ids must contain between 1 and 500 entries"
        episode_ids = []
        for raw_id in raw_ids:
            episode_id = positive_int(raw_id)
            if episode_id is None:
                return None, "episode_ids must contain positive integers"
            episode_ids.append(episode_id)
        payload = {"episode_ids": sorted(set(episode_ids))}
        if operation != "sonarr.search_episodes":
            series_id = positive_int(parameters.get("series_id"))
            if series_id is None:
                return None, "series_id must be a positive integer"
            payload["series_id"] = series_id
        if operation == "sonarr.cancel_episodes":
            raw_command_ids = parameters.get("command_ids") or []
            if not isinstance(raw_command_ids, list) or len(raw_command_ids) > 500:
                return None, "command_ids must contain no more than 500 entries"
            command_ids = []
            for raw_id in raw_command_ids:
                command_id = positive_int(raw_id)
                if command_id is None:
                    return None, "command_ids must contain positive integers"
                command_ids.append(command_id)
            if command_ids:
                payload["command_ids"] = sorted(set(command_ids))
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": f"/commands/{operation}",
            "query": {},
            "body": payload
        }, ""

    return None, "unsupported remote command"


def is_safe_remote_path(provider, path, query):
    if not path or not path.startswith("/") or "://" in path or ".." in path:
        return False, "invalid path"

    blocked_query_keys = {"apikey", "api_key", "token", "password", "pass", "key", "auth"}

    for key in (query or {}).keys():
        if str(key).lower() in blocked_query_keys:
            return False, "query cannot include secrets"

    provider = str(provider or "").lower()

    allowed_prefixes = {
        "jellyfin": [
            "/kaevo/internal/main-snapshot",
            "/System/Info",
            "/Users/",
            "/Items/",
            "/Shows/"
        ],
        "sonarr": [
            "/api/v3/system/status",
            "/api/v3/series",
            "/api/v3/queue",
            "/api/v3/history",
            "/api/v3/wanted/missing"
        ],
        "radarr": [
            "/api/v3/system/status",
            "/api/v3/movie",
            "/api/v3/queue",
            "/api/v3/history",
            "/api/v3/wanted/missing"
        ],
        "seerr": [
            "/api/v1/status",
            "/api/v1/search",
            "/api/v1/discover/trending",
            "/api/v1/discover/movies",
            "/api/v1/discover/tv",
            "/api/v1/request",
            "/api/v1/media/",
            "/api/v1/movie/",
            "/api/v1/tv/"
        ],
        "lidarr": [
            "/api/v1/system/status",
            "/api/v1/artist",
            "/api/v1/queue",
            "/api/v1/history",
            "/api/v1/wanted/missing"
        ],
        "readarr": [
            "/api/v1/system/status",
            "/api/v1/author",
            "/api/v1/book",
            "/api/v1/queue",
            "/api/v1/history",
            "/api/v1/wanted/missing"
        ],
        "qbittorrent": [
            "/api/v2/app/version",
            "/api/v2/transfer/info",
            "/api/v2/torrents/info"
        ],
        "bazarr": [
            "/api/system/status"
        ],
        "prowlarr": [
            "/api/v1/system/status",
            "/api/v1/indexerstatus",
            "/api/v1/indexer"
        ],
        "tdarr": [
            "/api/v2/status"
        ]
    }

    if provider in allowed_prefixes:
        for prefix in allowed_prefixes[provider]:
            if path == prefix or path.startswith(prefix):
                return True, ""

        return False, f"path not allowed for provider {provider}"

    if provider == "sabnzbd":
        if path != "/api":
            return False, "sabnzbd only supports /api in v0"

        mode = str((query or {}).get("mode") or "").lower()
        if mode not in {"version", "queue", "history", "fullstatus"}:
            return False, "sabnzbd v0 allows only version, queue, history, or fullstatus"

        return True, ""

    return False, f"unsupported provider {provider}"


def remote_request_path_id(path, suffix=""):
    prefix = "/v1/remote-requests/"

    if path.startswith(prefix):
        value = path[len(prefix):]
        if suffix and value.endswith(suffix):
            value = value[:-len(suffix)]
        return value.strip("/")

    return ""


def remote_request_priority(request_payload):
    method = str((request_payload or {}).get("method") or "").upper()
    path = str((request_payload or {}).get("path") or "")

    if method == "COMMAND" and path == "/commands/jellyfin.prepare_playback":
        return 0
    if method == "COMMAND" and path in {
        "/commands/jellyfin.playback_started",
        "/commands/jellyfin.playback_progress",
        "/commands/jellyfin.playback_stopped"
    }:
        return 1
    if re.fullmatch(r"/Users/[0-9a-fA-F]{32}/Items/[0-9a-fA-F]{32}", path):
        return 10
    if re.fullmatch(r"/Shows/[0-9a-fA-F]{32}/(Seasons|Episodes)", path):
        return 12
    if path == "/kaevo/internal/main-snapshot":
        return 30
    if path == "/kaevo/internal/image":
        return 90
    if method == "COMMAND":
        return 20
    return 20


def status_sort_key(status, timestamp, request_id, priority=None):
    if status == "pending":
        normalized_priority = 50 if priority is None else max(0, min(int(priority), 999))
        return f"{status}#{normalized_priority:03d}#{timestamp}#{request_id}"
    return f"{status}#{timestamp}#{request_id}"


def public_remote_request_item(item, include_payload=True):
    request_payload = parse_json_field(item.get("request_json"), {})
    response_payload = decode_remote_response_payload(item, None)
    error_payload = parse_json_field(item.get("error_json"), None)

    result = {
        "request_id": item.get("request_id"),
        "profile_id": item.get("profile_id"),
        "connector_id": item.get("connector_id"),
        "status": item.get("status"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "claimed_at": item.get("claimed_at", ""),
        "completed_at": item.get("completed_at", ""),
        "failed_at": item.get("failed_at", ""),
        "expires_at": item.get("expires_at"),
        "provider": request_payload.get("provider"),
        "method": request_payload.get("method"),
        "path": request_payload.get("path"),
        "query": request_payload.get("query", {}),
    }

    if request_payload.get("method") == "COMMAND":
        result["operation"] = str(request_payload.get("path") or "").removeprefix("/commands/")
        result["parameters"] = request_payload.get("body", {})

    if include_payload:
        if response_payload is not None:
            result["response"] = response_payload
        if error_payload is not None:
            result["error"] = error_payload

    return result


def decode_remote_response_payload(item, default=None):
    if item.get("response_json") is not None:
        return parse_json_field(item.get("response_json"), default)
    encoded = str(item.get("response_gzip_base64") or "")
    if not encoded:
        object_key = str(item.get("response_s3_key") or "")
        if not object_key or not REMOTE_PAYLOADS_BUCKET or s3_client is None:
            return default
        try:
            body = s3_client.get_object(Bucket=REMOTE_PAYLOADS_BUCKET, Key=object_key)["Body"].read()
            return json.loads(gzip.decompress(body).decode("utf-8"))
        except Exception:
            return default
    try:
        compressed = base64.b64decode(encoded, validate=True)
        decoded = gzip.decompress(compressed).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return default


def latest_online_connector_for_profile(profile_id):
    if home_connectors_table is None:
        return None

    result = home_connectors_table.query(
        IndexName="profile_id-updated_at-index",
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10
    )

    for item in result.get("Items", []):
        if connector_online_from_item(item):
            return item

    return None


def create_remote_request(event):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    profile_id = str(body.get("profile_id") or "").strip()
    provider = str(body.get("provider") or "").strip().lower()
    method = str(body.get("method") or "GET").strip().upper()
    path = str(body.get("path") or "").strip()
    query = body.get("query") if isinstance(body.get("query"), dict) else {}

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    if method != "GET":
        return response(400, {"state": "bad_request", "message": "only GET is supported in remote metadata v0"})

    allowed, reason = is_safe_remote_path(provider, path, query)
    if not allowed:
        return response(400, {"state": "bad_request", "message": reason})

    connector = latest_online_connector_for_profile(profile_id)

    if not connector:
        return response(409, {
            "state": "connector_unavailable",
            "message": "No online Kaevo Jellyfin Plugin is available for this profile."
        })

    now = utc_now_iso()
    request_id = str(uuid.uuid4())
    connector_id = connector.get("connector_id")

    request_payload = {
        "provider": provider,
        "method": method,
        "path": path,
        "query": query
    }

    priority = remote_request_priority(request_payload)
    item = {
        "request_id": request_id,
        "profile_id": profile_id,
        "connector_id": connector_id,
        "status": "pending",
        "status_created_at": status_sort_key("pending", now, request_id, priority),
        "priority": priority,
        "request_json": json.dumps(request_payload, separators=(",", ":")),
        "created_at": now,
        "updated_at": now,
        "expires_at": epoch_now() + REMOTE_REQUEST_TTL_SECONDS
    }

    remote_requests_table.put_item(Item=item)

    return response(202, {
        "state": "queued",
        "request": public_remote_request_item(item, include_payload=False)
    })


def create_remote_command(event):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    profile_id = str(body.get("profile_id") or "").strip()
    operation = str(body.get("operation") or "").strip()
    parameters = body.get("parameters") if isinstance(body.get("parameters"), dict) else {}
    idempotency_key = str(body.get("idempotency_key") or "").strip()

    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    profile_authorized_operations = {
        "jellyfin.prepare_playback",
        "jellyfin.playback_started",
        "jellyfin.playback_progress",
        "jellyfin.playback_stopped",
        "jellyfin.mark_played",
        "jellyfin.mark_unplayed",
        "jellyfin.favorite",
        "jellyfin.unfavorite",
        "jellyfin.delete_item",
        "provider.health",
        "optimizer.scan",
        "optimizer.plan_remux",
        "optimizer.execute_remux",
        "optimizer.job_status",
        "optimizer.jobs",
        "optimizer.reorder_job",
        "optimizer.cancel_job",
        "optimizer.cleanup_interrupted",
        "optimizer.pause_job",
        "optimizer.resume_job",
        "seerr.create_request",
        "seerr.cancel_request",
        "sonarr.episode_inventory",
        "sonarr.search_episodes",
        "sonarr.cancel_episodes",
        "sonarr.remove_episode_files"
    }
    if not require_dev_key(event):
        if operation not in profile_authorized_operations or not require_profile_auth(event, profile_id):
            return response(401, {"state": "unauthorized"})
    if not SAFE_IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        return response(400, {"state": "bad_request", "message": "idempotency_key must be 8-128 safe characters"})

    request_payload, error = normalize_remote_command(operation, parameters)
    if request_payload is None:
        return response(400, {"state": "bad_request", "message": error})

    connector = latest_online_connector_for_profile(profile_id)
    if not connector:
        return response(409, {
            "state": "connector_unavailable",
            "message": "No online Kaevo Jellyfin Plugin is available for this profile."
        })

    request_id = str(uuid.uuid5(REMOTE_COMMAND_ID_NAMESPACE, f"{profile_id}:{idempotency_key}"))
    encoded_request = json.dumps(request_payload, separators=(",", ":"), sort_keys=True)
    existing = remote_requests_table.get_item(Key={"request_id": request_id}).get("Item")
    if existing:
        if existing.get("request_json") != encoded_request:
            return response(409, {
                "state": "idempotency_conflict",
                "message": "idempotency_key was already used for a different command"
            })
        return response(200, {
            "state": "existing",
            "request": public_remote_request_item(existing, include_payload=True)
        })

    now = utc_now_iso()
    priority = remote_request_priority(request_payload)
    item = {
        "request_id": request_id,
        "profile_id": profile_id,
        "connector_id": connector.get("connector_id"),
        "status": "pending",
        "status_created_at": status_sort_key("pending", now, request_id, priority),
        "priority": priority,
        "request_json": encoded_request,
        "idempotency_key": idempotency_key,
        "created_at": now,
        "updated_at": now,
        "expires_at": epoch_now() + REMOTE_REQUEST_TTL_SECONDS
    }
    remote_requests_table.put_item(Item=item)

    return response(202, {
        "state": "queued",
        "request": public_remote_request_item(item, include_payload=False)
    })


def create_playback_grant(event):
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    profile_id = str(body.get("profile_id") or "").strip()
    device_id = str(body.get("device_id") or "").strip()
    item_id = str(body.get("item_id") or "").strip().lower()
    media_source_id = str(body.get("media_source_id") or "").strip()
    playback_session_id = str(body.get("playback_session_id") or "").strip()
    mode = str(body.get("mode") or "").strip().lower()
    if not profile_id or not SAFE_PLAYBACK_IDENTIFIER.fullmatch(profile_id):
        return response(400, {"state": "bad_request", "message": "invalid profile_id"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})
    if not device_id or not SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id):
        return response(400, {"state": "bad_request", "message": "invalid device_id"})
    if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
        return response(400, {"state": "bad_request", "message": "invalid item_id"})
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(media_source_id):
        return response(400, {"state": "bad_request", "message": "invalid media_source_id"})
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(playback_session_id):
        return response(400, {"state": "bad_request", "message": "invalid playback_session_id"})
    if mode not in {"direct_play", "remux", "transcode"}:
        return response(400, {"state": "bad_request", "message": "invalid playback mode"})
    if len(PLAYBACK_GRANT_SIGNING_KEY) < 32:
        return response(503, {"state": "playback_grants_not_configured"})
    entitlements, _ = load_entitlements_for_profile(profile_id)
    subscription_state = str(entitlements.get("subscription_state") or "").lower()
    if not (
        bool_value(entitlements.get("cloud_enabled"), False)
        and subscription_state in {"active", "trialing", "grace_period"}
    ):
        return response(403, {"state": "playback_not_entitled"})
    connector = latest_online_connector_for_profile(profile_id)
    if not connector or connector.get("auth_state") != "active" or not connector.get("playback_grant_key"):
        return response(409, {"state": "connector_unavailable"})
    max_bitrate = positive_int(body.get("max_bitrate") or 40_000_000, maximum=100_000_000)
    if max_bitrate is None:
        return response(400, {"state": "bad_request", "message": "invalid max_bitrate"})
    now = epoch_now()
    payload = {
        "v": 1,
        "grant_id": str(uuid.uuid4()),
        "nonce": secrets.token_urlsafe(24),
        "profile_id": profile_id,
        "device_id": device_id,
        "connector_id": str(connector.get("connector_id")),
        "item_id": item_id,
        "media_source_id": media_source_id,
        "playback_session_id": playback_session_id,
        "mode": mode,
        "max_bitrate": max_bitrate,
        "max_concurrent": 1,
        "iat": now,
        "nbf": now - 5,
        "exp": now + PLAYBACK_GRANT_TTL_SECONDS
    }
    payload = add_home_connector_signature(payload, connector["playback_grant_key"])
    token = sign_playback_grant(payload)
    return response(201, {
        "state": "issued",
        "grant": token,
        "grant_id": payload["grant_id"],
        "expires_at": payload["exp"],
        "connector_id": payload["connector_id"],
        "relay_base_url": (
            f"{PLAYBACK_RELAY_PUBLIC_URL}/v1/playback/{avfoundation_safe_grant_path(token)}"
            if PLAYBACK_RELAY_PUBLIC_URL else ""
        )
    })


def get_remote_request(event, path):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    request_id = remote_request_path_id(path)

    if not request_id or request_id == "claim":
        return response(404, {"state": "not_found"})

    item = remote_requests_table.get_item(Key={"request_id": request_id}).get("Item")

    if not item:
        return response(404, {"state": "not_found", "request_id": request_id})
    if not require_profile_auth(event, str(item.get("profile_id") or "")):
        return response(401, {"state": "unauthorized"})

    return response(200, public_remote_request_item(item, include_payload=True))


def claim_remote_request(event):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    connector_id = str(body.get("connector_id") or "").strip()

    if not connector_id:
        return response(400, {"state": "bad_request", "message": "connector_id is required"})

    if not require_connector_auth(event, connector_id):
        return response(401, {"state": "connector_unauthorized"})

    result = remote_requests_table.query(
        IndexName="connector_id-status_created_at-index",
        KeyConditionExpression=Key("connector_id").eq(connector_id) & Key("status_created_at").begins_with("pending#"),
        ScanIndexForward=True,
        Limit=8
    )

    items = result.get("Items", [])

    if not items:
        return response(200, {"state": "empty"})

    for candidate in items:
        now = utc_now_iso()
        try:
            claimed = remote_requests_table.update_item(
                Key={"request_id": candidate["request_id"]},
                ConditionExpression="#status = :pending",
                UpdateExpression=(
                    "SET #status = :in_progress, claimed_at = :now, updated_at = :now, "
                    "status_created_at = :status_created_at"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":pending": "pending",
                    ":in_progress": "in_progress",
                    ":now": now,
                    ":status_created_at": status_sort_key("in_progress", now, candidate["request_id"]),
                },
                ReturnValues="ALL_NEW",
            ).get("Attributes", {})
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                continue
            raise

        if claimed:
            return response(200, {
                "state": "claimed",
                "request": public_remote_request_item(claimed, include_payload=False)
            })

    return response(200, {"state": "empty"})


def complete_remote_request(event, path):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    request_id = remote_request_path_id(path, suffix="/complete")

    if not request_id:
        return response(400, {"state": "bad_request", "message": "request_id is required"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    item = remote_requests_table.get_item(Key={"request_id": request_id}).get("Item")

    if not item:
        return response(404, {"state": "not_found", "request_id": request_id})

    if not require_connector_auth(event, str(item.get("connector_id") or "")):
        return response(401, {"state": "connector_unauthorized"})

    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and body_connector_id != item.get("connector_id"):
        return response(403, {"state": "forbidden", "message": "connector_id mismatch"})

    now = utc_now_iso()
    item["status"] = "completed"
    item["completed_at"] = now
    item["updated_at"] = now
    item["status_created_at"] = status_sort_key("completed", now, request_id)
    item["http_status"] = int(body.get("http_status") or 200)
    item["truncated"] = bool_value(body.get("truncated"), False)

    response_payload = body.get("response")
    if response_payload is None:
        response_payload = {}

    encoded_response = json.dumps(response_payload, separators=(",", ":")).encode("utf-8")
    if len(encoded_response) >= REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES:
        compressed_response = gzip.compress(encoded_response, compresslevel=6)
        if REMOTE_PAYLOADS_BUCKET and s3_client is not None:
            object_key = f"remote-responses/{item.get('profile_id')}/{request_id}.json.gz"
            s3_client.put_object(
                Bucket=REMOTE_PAYLOADS_BUCKET,
                Key=object_key,
                Body=compressed_response,
                ContentType="application/json",
                ContentEncoding="gzip",
                ServerSideEncryption="AES256"
            )
            item.pop("response_json", None)
            item.pop("response_gzip_base64", None)
            item["response_s3_key"] = object_key
            item["response_encoding"] = "s3+gzip"
            item["response_stored_bytes"] = len(compressed_response)
        elif len(compressed_response) > REMOTE_RESPONSE_MAX_STORED_BYTES:
            return response(413, {
                "state": "response_too_large",
                "message": "Remote response exceeded the bounded Cloud metadata limit."
            })
        else:
            item.pop("response_json", None)
            item.pop("response_s3_key", None)
            item["response_gzip_base64"] = base64.b64encode(compressed_response).decode("ascii")
            item["response_encoding"] = "gzip+base64"
    else:
        item["response_json"] = encoded_response.decode("utf-8")
        item.pop("response_gzip_base64", None)
        item.pop("response_s3_key", None)
        item.pop("response_encoding", None)

    remote_requests_table.put_item(Item=item)

    return response(200, {
        "state": "completed",
        "request": public_remote_request_item(item, include_payload=False)
    })


def fail_remote_request(event, path):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    request_id = remote_request_path_id(path, suffix="/fail")

    if not request_id:
        return response(400, {"state": "bad_request", "message": "request_id is required"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    item = remote_requests_table.get_item(Key={"request_id": request_id}).get("Item")

    if not item:
        return response(404, {"state": "not_found", "request_id": request_id})

    if not require_connector_auth(event, str(item.get("connector_id") or "")):
        return response(401, {"state": "connector_unauthorized"})

    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and body_connector_id != item.get("connector_id"):
        return response(403, {"state": "forbidden", "message": "connector_id mismatch"})

    now = utc_now_iso()
    item["status"] = "failed"
    item["failed_at"] = now
    item["updated_at"] = now
    item["status_created_at"] = status_sort_key("failed", now, request_id)
    item["error_json"] = json.dumps({
        "message": str(body.get("message") or "remote request failed"),
        "details": body.get("details") if isinstance(body.get("details"), dict) else {}
    }, separators=(",", ":"))

    remote_requests_table.put_item(Item=item)

    return response(200, {
        "state": "failed",
        "request": public_remote_request_item(item, include_payload=False)
    })


REMOTE_IMAGE_MAX_BYTES = 3_500_000
REMOTE_IMAGE_MAX_DIMENSION = 2_160
REMOTE_IMAGE_POLL_TIMEOUT_SECONDS = 12
REMOTE_IMAGE_POLL_INTERVAL_SECONDS = 0.25
REMOTE_IMAGE_TYPES = {"primary", "backdrop", "logo", "thumb"}
REMOTE_IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}


def binary_response(status_code, content_type, data, headers=None):
    merged_headers = {
        "Content-Type": content_type,
        "Cache-Control": "private, max-age=86400"
    }
    if headers:
        merged_headers.update(headers)
    return {
        "statusCode": status_code,
        "headers": merged_headers,
        "isBase64Encoded": True,
        "body": base64.b64encode(data).decode("ascii")
    }


def remote_image_path_parts(path):
    prefix = "/v1/remote-images/"
    if not path.startswith(prefix):
        return None
    parts = path[len(prefix):].strip("/").split("/")
    if len(parts) != 3:
        return None
    provider, item_id, image_type = parts
    return provider.lower(), item_id.strip(), image_type.strip()


def bounded_int_param(params, key, default, maximum):
    raw = (params or {}).get(key)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    return max(1, min(value, maximum))


def create_remote_image_request_item(profile_id, connector_id, provider, item_id, image_type, params):
    now = utc_now_iso()
    request_id = str(uuid.uuid4())
    query = {
        "item_id": item_id,
        "image_type": image_type,
        "tag": str((params or {}).get("tag") or ""),
        "max_width": str(bounded_int_param(params, "max_width", 600, REMOTE_IMAGE_MAX_DIMENSION)),
        "max_height": str(bounded_int_param(params, "max_height", 900, REMOTE_IMAGE_MAX_DIMENSION)),
        "quality": str(bounded_int_param(params, "quality", 90, 95))
    }
    request_payload = {
        "provider": provider,
        "method": "GET",
        "path": "/kaevo/internal/image",
        "query": query
    }
    priority = remote_request_priority(request_payload)
    return {
        "request_id": request_id,
        "profile_id": profile_id,
        "connector_id": connector_id,
        "status": "pending",
        "status_created_at": status_sort_key("pending", now, request_id, priority),
        "priority": priority,
        "request_json": json.dumps(request_payload, separators=(",", ":")),
        "created_at": now,
        "updated_at": now,
        "expires_at": epoch_now() + REMOTE_REQUEST_TTL_SECONDS
    }


def get_remote_image(event, path):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    parts = remote_image_path_parts(path)
    if not parts:
        return response(404, {"state": "not_found"})

    provider, item_id, image_type = parts
    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()

    if provider != "jellyfin":
        return response(400, {"state": "bad_request", "message": "only jellyfin images are supported"})
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})
    if not item_id or "/" in item_id or ".." in item_id or ":" in item_id:
        return response(400, {"state": "bad_request", "message": "invalid item id"})
    if image_type.lower() not in REMOTE_IMAGE_TYPES:
        return response(400, {"state": "bad_request", "message": "unsupported image type"})

    connector = latest_online_connector_for_profile(profile_id)
    if not connector:
        return response(409, {"state": "connector_unavailable", "message": "No online Kaevo Jellyfin Plugin is available for this profile."})

    item = create_remote_image_request_item(profile_id, connector.get("connector_id"), provider, item_id, image_type, params)
    remote_requests_table.put_item(Item=item)

    deadline = time.time() + REMOTE_IMAGE_POLL_TIMEOUT_SECONDS
    while time.time() < deadline:
        time.sleep(REMOTE_IMAGE_POLL_INTERVAL_SECONDS)
        current = remote_requests_table.get_item(Key={"request_id": item["request_id"]}).get("Item")
        if not current:
            return response(404, {"state": "not_found", "request_id": item["request_id"]})
        status = current.get("status")
        if status == "failed":
            error_payload = parse_json_field(current.get("error_json"), {})
            return response(502, {"state": "failed", "message": error_payload.get("message") or "remote image failed"})
        if status == "completed":
            payload = decode_remote_response_payload(current, {})
            content_type = str(payload.get("content_type") or "").split(";")[0].lower()
            if content_type not in REMOTE_IMAGE_CONTENT_TYPES:
                return response(502, {"state": "failed", "message": "unsupported image content type"})
            raw = payload.get("body_base64") or ""
            try:
                data = base64.b64decode(raw, validate=True)
            except Exception:
                return response(502, {"state": "failed", "message": "invalid image payload"})
            if not data or len(data) > REMOTE_IMAGE_MAX_BYTES:
                return response(502, {"state": "failed", "message": "image payload size is invalid"})
            return binary_response(200, content_type, data, {
                "X-Kaevo-Image-Proxy": "home-connector",
                "X-Kaevo-Remote-Request-Id": item["request_id"]
            })

    return response(504, {"state": "timed_out", "message": "Remote image request timed out.", "request_id": item["request_id"]})

def lambda_handler(event, context):
    path = normalized_path(event)
    method = method_for(event)

    if method == "GET" and path == "/":
        return response(200, {
            "state": "ok",
            "service": SERVICE_NAME,
            "version": VERSION,
            "routes": [
                "/health",
                "/v1/provider-settings",
                "/v1/home/personalized",
                "/v1/events",
                "/v1/events/batch",
                "/v1/events/recent",
                "/v1/entitlements",
                "/v1/devices/register",
                "/v1/devices",
                "/v1/profiles/{profileId}/settings",
                "/v1/profiles/{profileId}/avatar",
                "/v1/trials/start",
                "/v1/trials/activate",
                "/v1/app-sessions/migrate",
                "/v1/app-sessions/refresh",
                "/v1/app-sessions/status",
                "/v1/app-sessions/revoke",
                "/v1/home-connectors/pairing/start",
                "/v1/home-connectors/pairing/exchange",
                "/v1/home-connectors/register",
                "/v1/home-connectors/{connectorId}/heartbeat",
                "/v1/home-connectors/{connectorId}/revoke",
                "/v1/home-connectors/{connectorId}/relay-ticket",
                "/v1/home-connectors/status",
                "/v1/remote-routes",
                "/v1/remote-requests",
                "/v1/remote-commands",
                "/v1/playback/grants",
                "/v1/remote-requests/claim",
                "/v1/remote-requests/{requestId}",
                "/v1/remote-requests/{requestId}/complete",
                "/v1/remote-requests/{requestId}/fail",
                "/v1/remote-images/{provider}/{itemId}/{imageType}"
            ]
        })

    if method == "GET" and path == "/health":
        return response(200, {
            "state": "ok",
            "service": SERVICE_NAME,
            "version": VERSION
        })

    if method == "POST" and path == "/v1/trials/start":
        return start_cloud_trial(event)

    if method == "POST" and path == "/v1/trials/activate":
        return activate_cloud_trial(event)

    if method == "POST" and path == "/v1/app-sessions/migrate":
        return migrate_existing_app_session(event)

    if method == "POST" and path == "/v1/app-sessions/refresh":
        return refresh_app_session(event)

    if method == "GET" and path == "/v1/app-sessions/status":
        return get_app_session_status(event)

    if method == "POST" and path == "/v1/app-sessions/revoke":
        return revoke_app_session(event)

    if method == "POST" and path == "/v1/events":
        return save_event(event)

    if method == "POST" and path == "/v1/events/batch":
        return save_event_batch(event)

    if method == "GET" and path == "/v1/events/recent":
        return recent_events(event)

    if method == "GET" and path == "/v1/entitlements":
        return get_entitlements(event)

    if method == "PUT" and path == "/v1/entitlements":
        return put_entitlements(event)

    if method == "POST" and path == "/v1/devices/register":
        return register_device(event)

    if method == "GET" and path == "/v1/devices":
        return list_devices(event)

    if path.startswith("/v1/profiles/") and path.endswith("/settings"):
        if method == "GET":
            return get_profile_settings(event, path)

        if method == "PUT":
            return put_profile_settings(event, path)

    if path.startswith("/v1/profiles/") and path.endswith("/avatar"):
        if method == "GET":
            return get_profile_avatar(event, path)
        if method == "PUT":
            return put_profile_avatar(event, path)
        if method == "DELETE":
            return delete_profile_avatar(event, path)

    if method == "GET" and path == "/v1/home/personalized":
        return get_personalized_home(event)

    if method == "GET" and path == "/v1/provider-settings":
        return get_provider_settings(event)

    if method == "PUT" and path == "/v1/provider-settings":
        return put_provider_settings(event)

    if method == "POST" and path == "/v1/home-connectors/pairing/start":
        return start_connector_pairing(event)

    if method == "POST" and path == "/v1/home-connectors/pairing/exchange":
        return exchange_connector_pairing(event)

    if method == "POST" and path.startswith("/v1/home-connectors/") and path.endswith("/revoke"):
        return revoke_home_connector(event, path)

    if method == "POST" and path.startswith("/v1/home-connectors/") and path.endswith("/relay-ticket"):
        return create_connector_relay_ticket(event, path)

    if method == "POST" and path == "/v1/home-connectors/register":
        return register_home_connector(event)

    if method == "POST" and path.startswith("/v1/home-connectors/") and path.endswith("/heartbeat"):
        return heartbeat_home_connector(event, path)

    if method == "GET" and path == "/v1/home-connectors/status":
        return get_home_connector_status(event)

    if method == "GET" and path == "/v1/remote-routes":
        return get_remote_routes(event)

    if method == "GET" and path.startswith("/v1/remote-images/"):
        return get_remote_image(event, path)

    if method == "POST" and path == "/v1/remote-requests":
        return create_remote_request(event)

    if method == "POST" and path == "/v1/remote-commands":
        return create_remote_command(event)

    if method == "POST" and path == "/v1/playback/grants":
        return create_playback_grant(event)

    if method == "POST" and path == "/v1/remote-requests/claim":
        return claim_remote_request(event)

    if method == "GET" and path.startswith("/v1/remote-requests/"):
        return get_remote_request(event, path)

    if method == "POST" and path.startswith("/v1/remote-requests/") and path.endswith("/complete"):
        return complete_remote_request(event, path)

    if method == "POST" and path.startswith("/v1/remote-requests/") and path.endswith("/fail"):
        return fail_remote_request(event, path)

    return response(404, {
        "state": "not_found",
        "path": path,
        "method": method
    })
