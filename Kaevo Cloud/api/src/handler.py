import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import time
import uuid
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

# SAM loads sibling modules normally. The explicit path also keeps local
# contract tests that import this file by spec aligned with Lambda packaging.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_identity import (
    IdentityContext,
    IdentityError,
    authorize,
    jwk_thumbprint,
    new_session_material,
    rotate_refresh_record,
    token_hash as production_token_hash,
    validate_public_jwk,
    verify_dpop,
)
from security_audit import (
    AuditReferenceError,
    fallback_audit_item,
    prepare_audit_item,
    write_audit_item,
)
from connector_lifecycle import (
    LifecycleError,
    activate_intent,
    activate_unpair_intent,
    binding_key,
    cancel_intent,
    create_pairing_intent,
    create_unpair_intent,
    create_update_intent,
    opaque_intent,
    random_pairing_code,
)
from identity_authority import AuthorityError, derive_authoritative_claims, validate_access_token_claims
from account_foundation import (
    ACCOUNT_SCHEMA_VERSION,
    AccountFoundationError,
    CanonicalRole,
    HouseholdAccessRole,
    assert_auth_identity_binding,
    canonical_role,
    capabilities_for,
    household_access_role,
    household_capabilities_for,
    plan_existing_account_backfill,
    public_auth_identity,
    provider_subject_key,
)
from household_membership import (
    account_household_guard_id,
    household_membership_id,
    household_owner_guard_id,
    plan_household_membership_normalization,
    public_membership_context,
    resolve_household_membership,
)
from profile_binding import (
    build_profile_binding,
    build_profile_creation,
    resolve_profile_access,
    validate_profile,
)
from profile_mapping import (
    build_confirmed_mapping,
    local_profile_source_id,
    public_mapping,
    validate_confirmed_mapping,
)
from guest_pass import (
    MAX_ACTIVE_PASSES,
    GuestPassValidationError,
    effective_state as guest_pass_effective_state,
    new_claim_secret,
    normalize_create_request as normalize_guest_pass_create_request,
    pin_matches as guest_pass_pin_matches,
    pin_record as guest_pass_pin_record,
    public_projection as public_guest_pass,
    scope_authorizes as guest_pass_scope_authorizes,
    secret_digest as guest_pass_secret_digest,
)
from pairing_v3 import (
    AUTHORIZATION_AUDIENCE,
    PROTOCOL as PAIRING_V3_PROTOCOL,
    PairingV3CryptoError,
    b64url_decode as pairing_v3_b64url_decode,
    b64url_encode as pairing_v3_b64url_encode,
    canonical_transcript as pairing_v3_canonical_transcript,
    canonical_json_digest as pairing_v3_canonical_json_digest,
    canonical_json_digest_preserving_number_lexemes as pairing_v3_canonical_json_digest_preserving_number_lexemes,
    canonical_uuid as pairing_v3_canonical_uuid,
    constant_time_equal as pairing_v3_constant_time_equal,
    ed25519_public_key_from_seed,
    plugin_fingerprint as pairing_v3_plugin_fingerprint,
    redemption_transcript as pairing_v3_redemption_transcript,
    sha256_b64url as pairing_v3_sha256_b64url,
    sign_ed25519 as pairing_v3_sign_ed25519,
    sign_authorization as pairing_v3_sign_authorization,
    verify_authorization as pairing_v3_verify_authorization,
    verify_ed25519 as pairing_v3_verify_ed25519,
)
from social_identity import (
    SocialIdentityError,
    authorization_url as social_authorization_url,
    canonical_provider as canonical_social_provider,
    decode_form_body as decode_social_form_body,
    exchange_code as exchange_social_code,
    identity_is_linked as social_identity_is_linked,
    link_provider_identity,
    new_attempt as new_social_link_attempt,
    parse_cognito_identities,
    provider_name as social_provider_name,
    resolve_cognito_username,
    resolve_signing_key as resolve_social_signing_key,
    state_key as social_state_key,
    validate_identity_token as validate_social_identity_token,
)


SERVICE_NAME = "kaevo-cloud"
VERSION = "0.0.30"
LOGGER = logging.getLogger(__name__)

EVENTS_TABLE = os.environ.get("PROFILE_EVENTS_TABLE")
PROFILE_SETTINGS_TABLE = os.environ.get("PROFILE_SETTINGS_TABLE")
DEVICES_TABLE = os.environ.get("DEVICES_TABLE")
ENTITLEMENTS_TABLE = os.environ.get("ENTITLEMENTS_TABLE")
HOME_CONNECTORS_TABLE = os.environ.get("HOME_CONNECTORS_TABLE")
REMOTE_REQUESTS_TABLE = os.environ.get("REMOTE_REQUESTS_TABLE")
REMOTE_PAYLOADS_BUCKET = os.environ.get("REMOTE_PAYLOADS_BUCKET")
PROFILE_AVATARS_BUCKET = os.environ.get("PROFILE_AVATARS_BUCKET")
APP_SESSIONS_TABLE = os.environ.get("APP_SESSIONS_TABLE")
PRINCIPALS_TABLE = os.environ.get("PRINCIPALS_TABLE")
INSTALLATIONS_TABLE = os.environ.get("INSTALLATIONS_TABLE")
SECURITY_AUDIT_TABLE = os.environ.get("SECURITY_AUDIT_TABLE")
IDENTITY_MEMBERSHIPS_TABLE = os.environ.get("IDENTITY_MEMBERSHIPS_TABLE")
IDENTITY_HOUSEHOLDS_TABLE = os.environ.get("IDENTITY_HOUSEHOLDS_TABLE")
IDENTITY_PROFILES_TABLE = os.environ.get("IDENTITY_PROFILES_TABLE")
HOUSEHOLD_INVITATIONS_TABLE = os.environ.get("HOUSEHOLD_INVITATIONS_TABLE")
GUEST_PASSES_TABLE = os.environ.get("GUEST_PASSES_TABLE")
HOUSEHOLD_JOIN_TRANSACTIONS_TABLE = os.environ.get("HOUSEHOLD_JOIN_TRANSACTIONS_TABLE")
ACCOUNTS_TABLE = os.environ.get("ACCOUNTS_TABLE")
AUTH_IDENTITIES_TABLE = os.environ.get("AUTH_IDENTITIES_TABLE")
HOUSEHOLD_MEMBERSHIPS_TABLE = os.environ.get("HOUSEHOLD_MEMBERSHIPS_TABLE")
PROFILES_TABLE = os.environ.get("PROFILES_TABLE")
PROFILE_BINDINGS_TABLE = os.environ.get("PROFILE_BINDINGS_TABLE")
PROFILE_MAPPINGS_TABLE = os.environ.get("PROFILE_MAPPINGS_TABLE")
BINDING_OPERATIONS_TABLE = os.environ.get("BINDING_OPERATIONS_TABLE")
PROFILE_BINDING_TOMBSTONES_TABLE = os.environ.get("PROFILE_BINDING_TOMBSTONES_TABLE")
DEV_API_KEY = os.environ.get("DEV_API_KEY")
PUBLIC_API_BASE_URL = os.environ.get("PUBLIC_API_BASE_URL", "").strip()
KAEVO_ENV = os.environ.get("KAEVO_ENV", "dev").strip().lower()
PLAYBACK_GRANT_SIGNING_KEY = os.environ.get("PLAYBACK_GRANT_SIGNING_KEY", "")
PLAYBACK_RELAY_PUBLIC_URL = os.environ.get("PLAYBACK_RELAY_PUBLIC_URL", "").rstrip("/")
PAIRING_V3_AUTHORIZATION_SIGNING_SEED = os.environ.get("PAIRING_V3_AUTHORIZATION_SIGNING_SEED", "")
PAIRING_V3_AUTHORIZATION_KEY_ID = os.environ.get("PAIRING_V3_AUTHORIZATION_KEY_ID", "v3-dev-1")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
GOOGLE_IDENTITY_PROVIDER_SECRET_ARN = os.environ.get("GOOGLE_IDENTITY_PROVIDER_SECRET_ARN", "")
APPLE_IDENTITY_PROVIDER_SECRET_ARN = os.environ.get("APPLE_IDENTITY_PROVIDER_SECRET_ARN", "")
SOCIAL_IDENTITY_LINK_CALLBACK_URL = os.environ.get("SOCIAL_IDENTITY_LINK_CALLBACK_URL", "")
NATIVE_OIDC_AUTHORIZATION_ENDPOINT = os.environ.get("NATIVE_OIDC_AUTHORIZATION_ENDPOINT", "")
EXPECTED_NATIVE_CALLBACK_URI = os.environ.get("EXPECTED_NATIVE_CALLBACK_URI", "")

MAX_BATCH_EVENTS = 50
CONNECTOR_ONLINE_WINDOW_SECONDS = 120
CONNECTOR_PAIRING_TTL_SECONDS = 10 * 60
TRIAL_ACTIVATION_TTL_SECONDS = 10 * 60
TRIAL_DURATION_SECONDS = 14 * 24 * 60 * 60
APP_SESSION_DURATION_SECONDS = 30 * 24 * 60 * 60
PLAYBACK_GRANT_TTL_SECONDS = 120
PAIRING_V3_PLAYBACK_GRANT_AUDIENCE = "kaevo-home-connectors-playback-v3"
PAIRING_V3_PLAYBACK_GRANT_TYPE = "kaevo-playback-grant+jwt"
REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES = 180_000
REMOTE_RESPONSE_MAX_STORED_BYTES = 330_000
SAFE_PLAYBACK_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_PAIRING_V3_OPAQUE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
SAFE_PAIRING_V3_FINGERPRINT = re.compile(r"^sha256:[A-Za-z0-9_-]{43}$")
SAFE_PAIRING_V3_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
PAIRING_V3_AUTHORIZATION_TTL_SECONDS = 60
PAIRING_V3_TERMINAL_RETENTION_SECONDS = 24 * 60 * 60
PAIRING_V3_AUDIT_RETENTION_SECONDS = 30 * 24 * 60 * 60
PAIRING_V3_PLUGIN_TIMESTAMP_SKEW_SECONDS = 60
HOUSEHOLD_INVITATION_CODE_TTL_SECONDS = 15 * 60
HOUSEHOLD_INVITATION_RETENTION_SECONDS = 30 * 24 * 60 * 60
HOUSEHOLD_JOIN_TRANSACTION_TTL_SECONDS = 15 * 60
HOUSEHOLD_JOIN_TRANSACTION_RETENTION_SECONDS = 24 * 60 * 60
HOUSEHOLD_JOIN_MAX_ATTEMPTS = 8
BINDING_OPERATION_RETENTION_SECONDS = 14 * 24 * 60 * 60
BINDING_SOURCE_TOMBSTONE_RETENTION_SECONDS = 30 * 24 * 60 * 60
BINDING_OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
BINDING_OPERATION_PHASE_RANK = {
    "created": 0,
    "authorized": 1,
    "dispatch_pending": 2,
    "dispatched": 3,
    "connector_claimed": 4,
    "inspection_completed": 5,
    "mutation_authorized": 6,
    "plugin_cas_committed": 7,
    "cloud_persisted": 8,
    "snapshot_pending": 9,
    "snapshot_published": 10,
    "completed": 11,
    "safely_refused": 12,
    "reconciliation_required": 12,
    "failed_retryable": 12,
    "failed_terminal": 12,
}

dynamodb = boto3.resource("dynamodb")
events_table = dynamodb.Table(EVENTS_TABLE) if EVENTS_TABLE else None
profile_settings_table = dynamodb.Table(PROFILE_SETTINGS_TABLE) if PROFILE_SETTINGS_TABLE else None
devices_table = dynamodb.Table(DEVICES_TABLE) if DEVICES_TABLE else None
entitlements_table = dynamodb.Table(ENTITLEMENTS_TABLE) if ENTITLEMENTS_TABLE else None
home_connectors_table = dynamodb.Table(HOME_CONNECTORS_TABLE) if HOME_CONNECTORS_TABLE else None
remote_requests_table = dynamodb.Table(REMOTE_REQUESTS_TABLE) if REMOTE_REQUESTS_TABLE else None
s3_client = boto3.client("s3") if REMOTE_PAYLOADS_BUCKET or PROFILE_AVATARS_BUCKET else None
app_sessions_table = dynamodb.Table(APP_SESSIONS_TABLE) if APP_SESSIONS_TABLE else None
principals_table = dynamodb.Table(PRINCIPALS_TABLE) if PRINCIPALS_TABLE else None
installations_table = dynamodb.Table(INSTALLATIONS_TABLE) if INSTALLATIONS_TABLE else None
security_audit_table = dynamodb.Table(SECURITY_AUDIT_TABLE) if SECURITY_AUDIT_TABLE else None
identity_memberships_table = dynamodb.Table(IDENTITY_MEMBERSHIPS_TABLE) if IDENTITY_MEMBERSHIPS_TABLE else None
identity_households_table = dynamodb.Table(IDENTITY_HOUSEHOLDS_TABLE) if IDENTITY_HOUSEHOLDS_TABLE else None
identity_profiles_table = dynamodb.Table(IDENTITY_PROFILES_TABLE) if IDENTITY_PROFILES_TABLE else None
household_invitations_table = dynamodb.Table(HOUSEHOLD_INVITATIONS_TABLE) if HOUSEHOLD_INVITATIONS_TABLE else None
guest_passes_table = dynamodb.Table(GUEST_PASSES_TABLE) if GUEST_PASSES_TABLE else None
household_join_transactions_table = dynamodb.Table(HOUSEHOLD_JOIN_TRANSACTIONS_TABLE) if HOUSEHOLD_JOIN_TRANSACTIONS_TABLE else None
accounts_table = dynamodb.Table(ACCOUNTS_TABLE) if ACCOUNTS_TABLE else None
auth_identities_table = dynamodb.Table(AUTH_IDENTITIES_TABLE) if AUTH_IDENTITIES_TABLE else None
household_memberships_table = dynamodb.Table(HOUSEHOLD_MEMBERSHIPS_TABLE) if HOUSEHOLD_MEMBERSHIPS_TABLE else None
profiles_table = dynamodb.Table(PROFILES_TABLE) if PROFILES_TABLE else None
profile_bindings_table = dynamodb.Table(PROFILE_BINDINGS_TABLE) if PROFILE_BINDINGS_TABLE else None
profile_mappings_table = dynamodb.Table(PROFILE_MAPPINGS_TABLE) if PROFILE_MAPPINGS_TABLE else None
binding_operations_table = dynamodb.Table(BINDING_OPERATIONS_TABLE) if BINDING_OPERATIONS_TABLE else None
profile_binding_tombstones_table = dynamodb.Table(PROFILE_BINDING_TOMBSTONES_TABLE) if PROFILE_BINDING_TOMBSTONES_TABLE else None
cognito_client = boto3.client("cognito-idp")
secrets_client = boto3.client("secretsmanager")
_social_provider_secret_cache = {}


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

# App sessions identify a profile, not an adult account owner. Security-sensitive
# profile policy must therefore remain immutable until the request carries an
# owner-scoped credential (the development key is the only such credential in
# the current pre-production contract).
OWNER_PROTECTED_PROFILE_SETTING_KEYS = {
    "profile_type",
    "parental_controls",
    "parental_controls_sync_enabled",
    "parental_controls_updated_at",
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


def profile_avatar_read_authorized(event, profile_id):
    """Authorize one exact avatar through the protected profile-access graph.

    Reads may target an active profile that the authenticated canonical
    profile may explicitly switch to or select for Who's Watching. An active
    household Owner or Admin may also read one exact active same-household
    profile that the manager is authorized to edit. This is the same
    immutable-ID boundary used by profile management; a display name, local
    roster, or cross-household lookup never grants access.
    """
    if require_dev_key(event):
        return True
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return False
    source_profile_id = str(session.get("profile_id") or "").strip()
    target_profile_id = str(profile_id or "").strip()
    household_id = str(session.get("household_id") or "").strip()
    if not source_profile_id or not target_profile_id or not household_id:
        return False
    if hmac.compare_digest(source_profile_id, target_profile_id):
        return True
    if identity_profiles_table is None:
        return False
    source_profile = identity_profiles_table.get_item(
        Key={"profile_id": source_profile_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(source_profile, dict)
        and source_profile.get("state") == "active"
        and hmac.compare_digest(
            str(source_profile.get("profile_id") or ""), source_profile_id,
        )
        and hmac.compare_digest(
            str(source_profile.get("household_id") or ""), household_id,
        )
    ):
        return False

    manager, manager_error = household_manager_bound_session(
        event,
        verified_session=session,
    )
    if not manager_error and manager:
        target_profile = identity_profiles_table.get_item(
            Key={"profile_id": target_profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            isinstance(target_profile, dict)
            and target_profile.get("state") == "active"
            and hmac.compare_digest(
                str(target_profile.get("profile_id") or ""), target_profile_id,
            )
            and hmac.compare_digest(
                str(target_profile.get("household_id") or ""), household_id,
            )
        ):
            return True

    access = _authorized_switch_target_access(
        source_profile=source_profile,
        household_id=household_id,
    )
    access.extend(_authorized_viewing_profile_access(
        source_profile=source_profile,
        household_id=household_id,
    ))
    if principals_table is not None:
        principal_id = str(session.get("principal_id") or "").strip()
        principal = principals_table.get_item(
            Key={"principal_id": principal_id}, ConsistentRead=True,
        ).get("Item") if principal_id else None
        access.extend(_authorized_parent_managed_profile_access(
            principal=principal,
            source_profile=source_profile,
            household_id=household_id,
            is_household_owner=(
                str(session.get("role") or "").strip().lower()
                == CanonicalRole.OWNER.value
            ),
        ))
    return any(
        hmac.compare_digest(str(item.get("profile_id") or ""), target_profile_id)
        for item in access if isinstance(item, dict)
    )


def profile_avatar_write_authority(event, profile_id):
    """Resolve an exact avatar writer without granting writes to viewers.

    A profile may always write its own photo. Household Owners and Admins may
    additionally manage an exact, active profile in their current household,
    which matches the native Manage Profiles surface and lets a manager seed
    legacy local photos for profiles without their own device. Profile Switch
    and Who's Watching grants remain read-only.
    """
    if require_dev_key(event):
        return "self"
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return ""
    source_profile_id = str(session.get("profile_id") or "").strip()
    target_profile_id = str(profile_id or "").strip()
    household_id = str(session.get("household_id") or "").strip()
    if not source_profile_id or not target_profile_id or not household_id:
        return ""
    if hmac.compare_digest(source_profile_id, target_profile_id):
        return "self"

    manager, manager_error = household_manager_bound_session(
        event,
        verified_session=session,
    )
    if manager_error or not manager or identity_profiles_table is None:
        return ""
    target = identity_profiles_table.get_item(
        Key={"profile_id": target_profile_id}, ConsistentRead=True,
    ).get("Item")
    return "household-manager" if (
        isinstance(target, dict)
        and target.get("state") == "active"
        and hmac.compare_digest(
            str(target.get("profile_id") or ""), target_profile_id,
        )
        and hmac.compare_digest(
            str(target.get("household_id") or ""), household_id,
        )
    ) else ""


def put_profile_avatar(event, path):
    profile_id = extract_profile_id_from_avatar_path(path)
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "invalid profile avatar path"})
    write_authority = profile_avatar_write_authority(event, profile_id)
    if not write_authority:
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
    put_arguments = dict(
        Bucket=PROFILE_AVATARS_BUCKET,
        Key=profile_avatar_key(profile_id),
        Body=image_data,
        ContentType="image/jpeg",
        CacheControl="private, max-age=300",
        Metadata={
            "profile-id-hash": hashlib.sha256(profile_id.encode("utf-8")).hexdigest(),
            "updated-at": updated_at,
            "uploader-authority": write_authority,
        },
    )
    if write_authority == "household-manager":
        try:
            existing = s3_client.head_object(
                Bucket=PROFILE_AVATARS_BUCKET,
                Key=profile_avatar_key(profile_id),
            )
        except ClientError as error:
            if str(error.response.get("Error", {}).get("Code")) in {"NoSuchKey", "NotFound", "404"}:
                put_arguments["IfNoneMatch"] = "*"
            else:
                raise
        else:
            existing_authority = str(
                (existing.get("Metadata") or {}).get("uploader-authority") or "self"
            ).strip().lower()
            if existing_authority != "household-manager":
                return response(409, {
                    "state": "profile_avatar_user_authoritative",
                    "message": "The profile user's photo is authoritative.",
                })
            existing_etag = str(existing.get("ETag") or "").strip()
            if not existing_etag:
                return response(409, {"state": "profile_avatar_changed"})
            put_arguments["IfMatch"] = existing_etag
    try:
        s3_client.put_object(**put_arguments)
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code")) in {
            "ConditionalRequestConflict", "PreconditionFailed", "409", "412",
        }:
            return response(409, {"state": "profile_avatar_changed"})
        raise
    return response(200, {"state": "saved", "profile_id": profile_id, "updated_at": updated_at})


def get_profile_avatar(event, path):
    profile_id = extract_profile_id_from_avatar_path(path)
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "invalid profile avatar path"})
    if not profile_avatar_read_authorized(event, profile_id):
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
    write_authority = profile_avatar_write_authority(event, profile_id)
    if not write_authority:
        return response(401, {"state": "unauthorized"})
    if not profile_avatar_cloud_allowed(event, profile_id):
        return response(403, {"state": "cloud_inactive", "message": "Cloud Access is required for profile photo sync"})
    if not PROFILE_AVATARS_BUCKET or s3_client is None:
        return response(503, {"state": "unavailable", "message": "profile avatar storage is not configured"})
    delete_arguments = {
        "Bucket": PROFILE_AVATARS_BUCKET,
        "Key": profile_avatar_key(profile_id),
    }
    if write_authority == "household-manager":
        try:
            existing = s3_client.head_object(**delete_arguments)
        except ClientError as error:
            if str(error.response.get("Error", {}).get("Code")) in {"NoSuchKey", "NotFound", "404"}:
                return response(200, {"state": "deleted", "profile_id": profile_id})
            raise
        existing_authority = str(
            (existing.get("Metadata") or {}).get("uploader-authority") or "self"
        ).strip().lower()
        if existing_authority != "household-manager":
            return response(409, {
                "state": "profile_avatar_user_authoritative",
                "message": "The profile user's photo is authoritative.",
            })
        existing_etag = str(existing.get("ETag") or "").strip()
        if not existing_etag:
            return response(409, {"state": "profile_avatar_changed"})
        delete_arguments["IfMatch"] = existing_etag
    try:
        s3_client.delete_object(**delete_arguments)
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code")) in {
            "ConditionalRequestConflict", "PreconditionFailed", "409", "412",
        }:
            return response(409, {"state": "profile_avatar_changed"})
        raise
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
    return KAEVO_ENV in {"dev", "development", "local", "test"} and bool(DEV_API_KEY) and hmac.compare_digest(
        str(header_value(event, "x-kaevo-dev-key") or ""),
        str(DEV_API_KEY)
    )


def legacy_app_sessions_allowed():
    return KAEVO_ENV in {"dev", "development", "local", "test"}


def secret_hash(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


PROTECTED_IDENTITY_DIAGNOSTIC_EVENT = "protected_identity_session_rejected"
PROTECTED_IDENTITY_DIAGNOSTIC_ROUTES = frozenset({
    "/v3/identity/me",
    "/v3/identity/profile-mappings",
    "/v3/identity/households/profiles",
})
PROTECTED_IDENTITY_REASON_FALLBACK = "PROTECTED_SESSION_REJECTED_UNCLASSIFIED"
PROTECTED_IDENTITY_REASON_CATEGORIES = frozenset({
    "AUTHORIZATION_HEADER_MISSING",
    "AUTHORIZATION_SCHEME_INVALID",
    "APP_SESSION_STORAGE_UNAVAILABLE",
    "APP_SESSION_NOT_FOUND",
    "APP_SESSION_RECORD_INVALID",
    "APP_SESSION_INACTIVE",
    "APP_SESSION_EXPIRED",
    "INSTALLATION_BINDING_UNAVAILABLE",
    "DPOP_PROOF_MALFORMED",
    "DPOP_HTM_MISMATCH",
    "DPOP_HTU_MISMATCH",
    "DPOP_IAT_INVALID",
    "DPOP_JTI_REPLAY",
    "DPOP_KEY_BINDING_MISMATCH",
    "DPOP_ACCESS_TOKEN_MISMATCH",
    "LEGACY_SESSION_NOT_FOUND",
    "LEGACY_SESSION_INACTIVE",
    "LEGACY_SESSION_EXPIRED",
    PROTECTED_IDENTITY_REASON_FALLBACK,
})


def _protected_identity_fingerprint(value):
    """Return a short, domain-separated digest suitable for diagnostic correlation."""
    return secret_hash(f"protected-identity-diagnostic-v1:{value}")[:24] if value else ""


def _protected_identity_dpop_category(error):
    return {
        "invalid_dpop": "DPOP_PROOF_MALFORMED",
        "installation_key_mismatch": "DPOP_KEY_BINDING_MISMATCH",
        "dpop_method_mismatch": "DPOP_HTM_MISMATCH",
        "dpop_url_mismatch": "DPOP_HTU_MISMATCH",
        "stale_dpop": "DPOP_IAT_INVALID",
        "dpop_replay": "DPOP_JTI_REPLAY",
        "dpop_access_token_mismatch": "DPOP_ACCESS_TOKEN_MISMATCH",
    }.get(str(getattr(error, "reason", "")), PROTECTED_IDENTITY_REASON_FALLBACK)


def _protected_identity_session_rejected(event, reason, *, item=None, installation=None):
    """Emit bounded, non-secret protected-session diagnosis without changing authorization."""
    if normalized_path(event) not in PROTECTED_IDENTITY_DIAGNOSTIC_ROUTES:
        return
    try:
        category = reason if reason in PROTECTED_IDENTITY_REASON_CATEGORIES else PROTECTED_IDENTITY_REASON_FALLBACK
        item = item if isinstance(item, dict) else {}
        installation = installation if isinstance(installation, dict) else {}
        LOGGER.warning(json.dumps({
            "event": PROTECTED_IDENTITY_DIAGNOSTIC_EVENT,
            "reason_category": category,
            "route": normalized_path(event),
            "method": method_for(event),
            "principal_fingerprint": _protected_identity_fingerprint(item.get("principal_id")),
            "installation_fingerprint": _protected_identity_fingerprint(item.get("installation_id")),
            "dpop_key_fingerprint": _protected_identity_fingerprint(item.get("key_thumbprint") or installation.get("key_thumbprint")),
            "lambda_request_fingerprint": str((event or {}).get("_kaevo_lambda_request_fingerprint") or ""),
            "timestamp": utc_now_iso(),
        }, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Diagnostic failure must never alter the existing fail-closed decision.
        pass


PAIRING_V3_CONNECTOR_AUTH_DIAGNOSTIC_EVENT = "pairing_v3_connector_auth_rejected"
PAIRING_V3_CONNECTOR_AUTH_NUMBER_COMPATIBILITY_EVENT = "pairing_v3_connector_auth_number_compatibility"
PAIRING_V3_CONNECTOR_AUTH_REASON_FALLBACK = "CONNECTOR_AUTH_REJECTED_UNCLASSIFIED"
PAIRING_V3_CONNECTOR_AUTH_REASON_CATEGORIES = frozenset({
    "AUTH_STORAGE_UNAVAILABLE",
    "CONNECTOR_ID_MISSING",
    "REQUEST_BODY_INVALID",
    "BODY_CONNECTOR_MISMATCH",
    "CONNECTOR_NOT_FOUND",
    "CONNECTOR_REVOKED",
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
    PAIRING_V3_CONNECTOR_AUTH_REASON_FALLBACK,
})


def _pairing_v3_connector_route_category(event):
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


def _pairing_v3_connector_auth_rejected(event, reason, connector_id=""):
    """Emit bounded connector-auth diagnosis while preserving a false result."""
    try:
        category = reason if reason in PAIRING_V3_CONNECTOR_AUTH_REASON_CATEGORIES else PAIRING_V3_CONNECTOR_AUTH_REASON_FALLBACK
        LOGGER.warning(json.dumps({
            "event": PAIRING_V3_CONNECTOR_AUTH_DIAGNOSTIC_EVENT,
            "reason_category": category,
            "route_category": _pairing_v3_connector_route_category(event),
            "method": method_for(event),
            "connector_fingerprint": secret_hash(f"pairing-v3-connector-auth-v1:{connector_id}")[:24] if connector_id else "",
            "lambda_request_fingerprint": str((event or {}).get("_kaevo_lambda_request_fingerprint") or ""),
            "timestamp": utc_now_iso(),
        }, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Diagnostic failure must never alter the existing fail-closed decision.
        pass
    return False


def _pairing_v3_raw_event_json_body(event):
    raw_body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")
    if not isinstance(raw_body, str):
        raise PairingV3CryptoError("JSON body must be text")
    return raw_body


def _pairing_v3_exact_json_body_bytes(event):
    """Return the exact strict JSON bytes used by connector signature v2."""
    raw_body = _pairing_v3_raw_event_json_body(event)

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


def _pairing_v3_connector_request_transcript(event, body_digest, timestamp, nonce, connector_id,
                                             plugin_instance_id, plugin_key_id, fingerprint):
    return pairing_v3_canonical_transcript("connector-request", (
        ("httpMethod", method_for(event).upper()),
        ("canonicalRoute", normalized_path(event)),
        ("bodyDigest", body_digest),
        ("timestamp", timestamp),
        ("nonce", nonce),
        ("connectorId", connector_id),
        ("pluginInstanceId", plugin_instance_id),
        ("pluginKeyId", plugin_key_id),
        ("pluginPublicKeyFingerprint", fingerprint),
    ))


def _pairing_v3_connector_auth_number_compatibility(event, connector_id):
    try:
        LOGGER.warning(json.dumps({
            "event": PAIRING_V3_CONNECTOR_AUTH_NUMBER_COMPATIBILITY_EVENT,
            "route_category": _pairing_v3_connector_route_category(event),
            "method": method_for(event),
            "connector_fingerprint": secret_hash(f"pairing-v3-connector-auth-v1:{connector_id}")[:24],
            "lambda_request_fingerprint": str((event or {}).get("_kaevo_lambda_request_fingerprint") or ""),
            "timestamp": utc_now_iso(),
        }, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Observability must not alter a successfully verified request.
        pass


def app_bearer_token(event):
    authorization = str(header_value(event, "authorization") or "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def authenticated_app_session(event):
    authorization = str(header_value(event, "authorization") or "")
    token = app_bearer_token(event)
    if not authorization:
        _protected_identity_session_rejected(event, "AUTHORIZATION_HEADER_MISSING")
        return None
    if not authorization.lower().startswith("bearer "):
        _protected_identity_session_rejected(event, "AUTHORIZATION_SCHEME_INVALID")
        return None
    if not token:
        _protected_identity_session_rejected(event, "AUTHORIZATION_HEADER_MISSING")
        return None
    if app_sessions_table is None:
        _protected_identity_session_rejected(event, "APP_SESSION_STORAGE_UNAVAILABLE")
        return None
    item = app_sessions_table.get_item(Key={"token_hash": f"access#{production_token_hash(token)}"}).get("Item")
    if item:
        if item.get("record_type") != "access":
            _protected_identity_session_rejected(event, "APP_SESSION_RECORD_INVALID", item=item)
            return None
        if item.get("state") != "active" or bool_value(item.get("revoked"), False):
            _protected_identity_session_rejected(event, "APP_SESSION_INACTIVE", item=item)
            return None
        if int(item.get("expires_at") or 0) < epoch_now():
            _protected_identity_session_rejected(event, "APP_SESSION_EXPIRED", item=item)
            return None
        installation = installations_table.get_item(Key={"installation_id": str(item.get("installation_id") or "")}).get("Item") if installations_table else None
        if not installation or installation.get("state") != "active" or bool_value(installation.get("revoked"), False):
            _protected_identity_session_rejected(event, "INSTALLATION_BINDING_UNAVAILABLE", item=item, installation=installation)
            return None
        try:
            verify_dpop(
                str(header_value(event, "dpop") or ""),
                method=method_for(event),
                url=request_absolute_url(event),
                expected_thumbprint=str(item.get("key_thumbprint") or ""),
                access_token=token,
                replay_guard=record_dpop_jti,
            )
        except IdentityError as error:
            _protected_identity_session_rejected(event, _protected_identity_dpop_category(error), item=item, installation=installation)
            return None
        return item
    if not legacy_app_sessions_allowed():
        _protected_identity_session_rejected(event, "APP_SESSION_NOT_FOUND")
        return None
    item = app_sessions_table.get_item(Key={"token_hash": secret_hash(token)}).get("Item")
    if not item or item.get("record_type") != "app_session":
        _protected_identity_session_rejected(event, "LEGACY_SESSION_NOT_FOUND")
        return None
    if item.get("state") != "active" or bool_value(item.get("revoked"), False):
        _protected_identity_session_rejected(event, "LEGACY_SESSION_INACTIVE", item=item)
        return None
    if int(item.get("expires_at") or 0) < epoch_now():
        _protected_identity_session_rejected(event, "LEGACY_SESSION_EXPIRED", item=item)
        return None
    return item


def identity_me_v3(event, *, verified_session=None):
    """Resolve the caller exclusively from a DPoP-bound protected session.

    This endpoint deliberately accepts no account, household, role, or profile
    request values.  The app-session record, installation binding, and current
    DynamoDB identity graph are the only sources of authority.
    """
    if any(table is None for table in (
        accounts_table,
        auth_identities_table,
        household_memberships_table,
        profiles_table,
        profile_bindings_table,
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})

    session = verified_session if verified_session is not None else authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})

    subject = str(session.get("principal_id") or "")
    account_id = str(session.get("account_id") or "")
    household_id = str(session.get("household_id") or "")
    profile_id = str(session.get("profile_id") or "")
    if not all((subject, account_id, household_id, profile_id)):
        return response(401, {"state": "identity_context_invalid"})

    try:
        principal = principals_table.get_item(
            Key={"principal_id": subject}, ConsistentRead=True,
        ).get("Item")
        membership = identity_memberships_table.get_item(
            Key={"principal_id": subject}, ConsistentRead=True,
        ).get("Item")
        household = identity_households_table.get_item(
            Key={"household_id": household_id}, ConsistentRead=True,
        ).get("Item")
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        claims = derive_authoritative_claims(subject, principal, membership, household, profile)
        if any(not hmac.compare_digest(str(session.get(key) or ""), expected) for key, expected in (
            ("account_id", claims.account_id),
            ("household_id", claims.household_id),
            ("profile_id", claims.profile_id),
            ("role", claims.role),
            ("authz_version", str(claims.authz_version)),
        )):
            return response(401, {"state": "stale_authorization"})

        account = accounts_table.get_item(Key={"account_id": claims.account_id}, ConsistentRead=True).get("Item")
        if (
            not isinstance(account, dict)
            or account.get("entity_type") != "Account"
            or account.get("status") != "active"
            or int(account.get("schema_version") or 0) != ACCOUNT_SCHEMA_VERSION
        ):
            return response(409, {"state": "account_migration_required"})

        cognito_key = provider_subject_key("cognito", subject)
        cognito_identity = auth_identities_table.get_item(
            Key={"auth_identity_key": cognito_key}, ConsistentRead=True,
        ).get("Item")
        assert_auth_identity_binding(
            cognito_identity,
            account_id=claims.account_id,
            provider="cognito",
            provider_subject=subject,
        )
        records = auth_identities_table.query(
            IndexName="account_id-created_at_epoch-index",
            KeyConditionExpression=Key("account_id").eq(claims.account_id),
            ConsistentRead=False,
        ).get("Items", [])
        if not any(str(record.get("auth_identity_key") or "") == cognito_key for record in records):
            # The account GSI is eventually consistent. The strongly-read
            # Cognito binding above is sufficient for the caller's own
            # identity while a just-created index entry propagates.
            records.append(cognito_identity)
        auth_identities = [
            public_auth_identity(record)
            for record in records
            if isinstance(record, dict)
            and record.get("entity_type") == "AuthIdentity"
            and str(record.get("account_id") or "") == claims.account_id
        ]
        if not auth_identities:
            raise AccountFoundationError("auth_identity_binding_required")

        normalized_membership = household_memberships_table.get_item(Key={
            "household_id": claims.household_id,
            "membership_id": household_membership_id(claims.account_id, claims.household_id),
        }, ConsistentRead=True).get("Item")
        normalized_membership = _repair_legacy_active_membership_profile_pointer(
            normalized_membership,
            expected_profile_id=claims.profile_id,
        )
        claims, resolved_role, normalized_membership = resolve_household_membership(
            subject=subject,
            principal=principal,
            legacy_membership=membership,
            household=household,
            profile=profile,
            normalized_membership=normalized_membership,
        )
        bindings = profile_bindings_table.query(
            KeyConditionExpression=Key("account_id").eq(claims.account_id),
            ConsistentRead=True,
        ).get("Items", [])
        profiles_by_id = {}
        for binding in bindings:
            if not isinstance(binding, dict) or binding.get("status") != "active":
                continue
            binding_profile_id = str(binding.get("profile_id") or "")
            if binding_profile_id:
                item = profiles_table.get_item(Key={"profile_id": binding_profile_id}, ConsistentRead=True).get("Item")
                if isinstance(item, dict):
                    profiles_by_id[binding_profile_id] = item
        profile_access = resolve_profile_access(
            account_id=claims.account_id,
            household_id=claims.household_id,
            bindings=bindings,
            profiles_by_id=profiles_by_id,
        )
        # A normalized household membership may carry the caller's exact
        # server-owned profile pointer.  It is an authority record in its own
        # right, not a legacy Profile/ProfileBinding projection.  Surface that
        # one profile only after every edge agrees; this lets a replacement
        # installation explicitly link to the retained profile without
        # creating a duplicate Cloud profile.
        canonical_profile_access = _normalized_self_profile_access(
            claims=claims,
            resolved_role=resolved_role,
            normalized_membership=normalized_membership,
            profile=profile,
        )
        profile_access_by_id = {
            str(item.get("profile_id") or ""): item
            for item in profile_access + canonical_profile_access
            if str(item.get("profile_id") or "")
        }
        # Profile switching is an explicit household grant retained on the
        # authenticated member's canonical profile. Merge only those exact
        # server-owned IDs; do not broaden access from a device-local profile
        # list or a display-name match.
        for item in _authorized_switch_target_access(
            source_profile=profile,
            household_id=claims.household_id,
        ):
            profile_access_by_id.setdefault(str(item["profile_id"]), item)
        # Parent-managed kids are attached to the Owner principal at creation
        # time and have no child credential of their own. Recover that exact,
        # canonical relationship for older records whose Owner profile did
        # not yet receive explicit switch/watch target lists.
        parent_managed_access = _authorized_parent_managed_profile_access(
            principal=principal,
            source_profile=profile,
            household_id=claims.household_id,
            is_household_owner=(
                str(getattr(resolved_role, "value", resolved_role)) == CanonicalRole.OWNER.value
            ),
        )
        for item in parent_managed_access:
            profile_access_by_id.setdefault(str(item["profile_id"]), item)
        # Viewer selection is intentionally narrower than profile switching.
        # It is only a presentation/playback audience grant and never lets a
        # member enter, edit, or otherwise assume another profile.
        viewing_access = _authorized_viewing_profile_access(
            source_profile=profile,
            household_id=claims.household_id,
        )
        viewing_access_by_id = {
            str(item.get("profile_id") or ""): item
            for item in viewing_access
            if str(item.get("profile_id") or "")
        }
        for item in parent_managed_access:
            viewing_access_by_id.setdefault(str(item["profile_id"]), {
                **item,
                "access_level": "view",
            })
        viewing_access = list(viewing_access_by_id.values())
        self_profile_id = str(profile.get("profile_id") or "").strip()
        viewing_profile_ids = [self_profile_id] if self_profile_id else []
        viewing_profile_ids.extend(
            item["profile_id"] for item in viewing_access
            if item["profile_id"] not in viewing_profile_ids
        )
        for item in profile_access_by_id.values():
            if item.get("is_self") is True:
                item["allowed_viewing_profile_ids"] = viewing_profile_ids
        # The member receives only the exact, pre-authorized viewer records.
        # A view entry deliberately remains non-switchable; it provides the
        # presentation metadata required for Who's Watching without exposing
        # an account-entry path or the broader household roster.
        for item in viewing_access:
            profile_access_by_id.setdefault(str(item["profile_id"]), item)
        profile_access = sorted(profile_access_by_id.values(), key=lambda item: item["profile_id"])
        profile_access = _decorate_profile_access_with_switch_protection(
            profile_access,
            household_id=claims.household_id,
        )
        if profile_access and security_audit_table is not None:
            try:
                commit_security_audit(_profile_binding_audit(
                    event, session, "profile_access_resolved", "success",
                    target_id=claims.account_id, target_type="account",
                ))
            except AuditReferenceError:
                return audit_unavailable_response()

        return response(200, {
            "schema_version": 1,
            # This is server-derived from the same claims that were compared
            # against the protected session above.  Clients persist it with
            # their local authority snapshot so a later authorization change
            # invalidates that snapshot instead of silently retaining access.
            "account": {
                "account_id": claims.account_id,
                "status": "active",
                "authz_version": claims.authz_version,
            },
            "auth_identities": sorted(auth_identities, key=lambda item: item["provider"]),
            "household": public_membership_context(
                claims, resolved_role, normalized_membership, profile_access=profile_access,
            ),
            "profile_access": profile_access,
            "device": {
                "device_id": str(session.get("device_id") or ""),
                "installation_id": str(session.get("installation_id") or ""),
                "status": "active",
            },
            "migration_state": "already_normalized",
        })
    except AccountFoundationError as error:
        if error.reason in {
            "household_membership_migration_required",
            "legacy_role_unresolved",
            "household_authority_ambiguous",
            "membership_migration_not_required",
        }:
            return response(409, {"state": error.reason})
        return response(401, {"state": "identity_context_invalid"})
    except (AuthorityError, TypeError, ValueError):
        return response(401, {"state": "identity_context_invalid"})


def _normalized_self_profile_access(*, claims, resolved_role, normalized_membership, profile):
    """Return the caller's exact normalized profile, never a household-wide guess.

    This bridge intentionally relies on GetItem-resolved records already used
    by ``identity_me_v3``.  It does not enumerate profiles, inspect legacy
    invitation data, or grant access to a different account's profile.
    """
    if not isinstance(normalized_membership, dict) or not isinstance(profile, dict):
        return []
    profile_id = str(normalized_membership.get("profile_id") or "")
    if not profile_id or profile_id != str(claims.profile_id or ""):
        return []
    if any(str(normalized_membership.get(key) or "") != expected for key, expected in (
        ("household_id", str(claims.household_id or "")),
        ("account_id", str(claims.account_id or "")),
    )):
        return []
    if any(str(profile.get(key) or "") != expected for key, expected in (
        ("profile_id", profile_id),
        ("household_id", str(claims.household_id or "")),
        ("account_id", str(claims.account_id or "")),
    )):
        return []
    display_name = str(profile.get("display_name") or "").strip()
    profile_type = str(profile.get("profile_type") or "").strip().lower()
    if profile.get("state") != "active" or not display_name or profile_type not in {"adult", "teen", "child", "kid"}:
        return []
    access_role = str(normalized_membership.get("household_access_role") or "").strip().lower()
    is_household_owner = (
        str(getattr(resolved_role, "value", resolved_role)) == CanonicalRole.OWNER.value
        or access_role == HouseholdAccessRole.OWNER.value
    )
    access_level = "manage" if is_household_owner or access_role == "admin" else "switch"
    self_access = {
        "profile_id": profile_id,
        "profile_type": profile_type,
        "display_name": display_name,
        "access_level": access_level,
        "status": "active",
        "is_self": True,
        # Household Owners always retain video-request access. This governs
        # Kaevo policy only; an exact Seerr identity still requires the paired
        # plugin's canonical provisioning flow.
        # Request access is a profile-scoped policy.  The normalized
        # membership establishes the caller's household authority and exact
        # profile pointer, but can be an older projection after an Owner edits
        # a member's request grant.  Prefer the strongly-read canonical
        # profile whenever it carries an explicit value; retain the membership
        # field only for legacy profiles that have not yet stored the policy.
        # This does not broaden access: both records were read by exact key
        # and already proved the same active account, household, and profile.
        "request_access_enabled": is_household_owner or bool_value(
            profile.get(
                "request_access_enabled",
                normalized_membership.get("request_access_enabled"),
            ),
            False,
        ),
        "cloud_access_enabled": _profile_cloud_access_enabled(profile),
        "parental_controls": normalized_membership.get(
            "parental_controls",
            profile.get("parental_controls"),
        ),
        # Self is always a valid viewer. Explicit household audience grants
        # are added later after exact, same-household records are read back.
        "allowed_viewing_profile_ids": [profile_id],
        # Provider identifiers stay server-private.  The authenticated user
        # still needs an authoritative answer about whether their own Kaevo
        # profile has complete immutable provider edges before choosing an
        # account-deletion scope on a different device.
        "jellyfin_binding_status": _public_provider_binding_status(
            profile, provider="jellyfin",
        ),
        "seerr_binding_status": _public_provider_binding_status(
            profile, provider="seerr",
        ),
        # This is a fail-closed projection of the authenticated connector's
        # most recent signed heartbeat. It deliberately reveals no connector
        # or provider identifier and never grants deletion authority; the
        # destructive operation re-checks the plugin policy at execution.
        "provider_deletion_status": _public_profile_deletion_status(profile),
    }
    # Return the exact Seerr provider edge only for the authenticated self
    # profile. Other accessible household profiles never expose their Seerr
    # identity here. This lets clients attribute a provider request without
    # comparing mutable names or avatars.
    if str(profile.get("seerr_binding_state") or "") == "active":
        seerr_user_id = _normalized_seerr_user_id(profile.get("seerr_user_id"))
        if seerr_user_id:
            self_access["seerr_user_id"] = seerr_user_id
    return [self_access]


def _public_provider_binding_status(profile, *, provider):
    """Project binding completeness without exposing an immutable provider ID."""
    profile = profile if isinstance(profile, dict) else {}
    jellyfin_user_id = _normalized_jellyfin_user_id(profile.get("jellyfin_user_id"))
    jellyfin_connector_id = str(profile.get("jellyfin_connector_id") or "").strip()
    if provider == "jellyfin":
        state = str(profile.get("jellyfin_binding_state") or "").strip().lower()
        evidence = any((state, jellyfin_user_id, jellyfin_connector_id))
        if not evidence:
            return "not_linked"
        return (
            "linked"
            if state == "active" and jellyfin_user_id and jellyfin_connector_id
            else "needs_review"
        )

    if provider != "seerr":
        raise AccountFoundationError("provider_binding_projection_invalid")
    state = str(profile.get("seerr_binding_state") or "").strip().lower()
    seerr_user_id = _normalized_seerr_user_id(profile.get("seerr_user_id"))
    seerr_jellyfin_user_id = _normalized_jellyfin_user_id(
        profile.get("seerr_jellyfin_user_id")
    )
    seerr_connector_id = str(profile.get("seerr_connector_id") or "").strip()
    evidence = any((state, seerr_user_id, seerr_jellyfin_user_id, seerr_connector_id))
    if not evidence:
        return "not_linked"
    complete = (
        state == "active"
        and seerr_user_id
        and jellyfin_user_id
        and seerr_jellyfin_user_id
        and hmac.compare_digest(seerr_jellyfin_user_id, jellyfin_user_id)
        and seerr_connector_id
        and jellyfin_connector_id
        and hmac.compare_digest(seerr_connector_id, jellyfin_connector_id)
    )
    return "linked" if complete else "needs_review"


def _public_profile_deletion_status(profile):
    """Return enabled, disabled, or unavailable for the exact bound connector.

    Missing, stale, malformed, retired, or pre-capability heartbeats are all
    unavailable. This prevents a client from offering provider deletion based
    on a local cache, mutable display name, or an older plugin version.
    """
    profile = profile if isinstance(profile, dict) else {}
    connector_id = str(profile.get("jellyfin_connector_id") or "").strip()
    if not connector_id or home_connectors_table is None:
        return "unavailable"
    try:
        connector = home_connectors_table.get_item(
            Key={"connector_id": connector_id}, ConsistentRead=True,
        ).get("Item")
    except ClientError:
        return "unavailable"
    if not isinstance(connector, dict):
        return "unavailable"
    if not hmac.compare_digest(str(connector.get("connector_id") or ""), connector_id):
        return "unavailable"
    if not (
        connector.get("protocol_version") == PAIRING_V3_PROTOCOL
        and connector.get("auth_state") == "v3_active"
        and connector.get("state") == "active"
        and not bool_value(connector.get("revoked"), False)
        and connector_online_from_item(connector)
    ):
        return "unavailable"
    provider_status = parse_json_field(connector.get("provider_status_json"), {})
    deletion = provider_status.get("profile_deletion") if isinstance(provider_status, dict) else None
    if not isinstance(deletion, dict) or deletion.get("configured") is not True:
        return "unavailable"
    if deletion.get("ok") is True and deletion.get("reason") in {None, ""}:
        return "enabled"
    if deletion.get("ok") is False and deletion.get("reason") == "disabled":
        return "disabled"
    return "unavailable"


def _profile_switch_pin_configured(profile):
    """Return only the non-secret presence of a profile-switch PIN."""
    pin = profile.get("profile_switch_pin") if isinstance(profile, dict) else None
    return (
        isinstance(pin, dict)
        and int(pin.get("version") or 0) == 1
        and isinstance(pin.get("salt"), str)
        and isinstance(pin.get("hash"), str)
    )


def _profile_switch_protection(profile):
    """Describe entry protection without exposing a credential or policy secret."""
    if str((profile or {}).get("household_access_role") or "").lower() == HouseholdAccessRole.OWNER.value:
        return "owner_direct"
    return "pin_required" if _profile_switch_pin_configured(profile) else "not_configured"


def _profile_cloud_access_enabled(profile):
    """Preserve no-seat parent-managed children, including legacy records."""
    if not isinstance(profile, dict):
        return True
    return bool_value(
        profile.get("cloud_access_enabled"),
        not bool_value(profile.get("managed_by_owner"), False),
    )


def _authorized_switch_target_access(*, source_profile, household_id):
    """Resolve only explicit, active, same-household profile-switch grants.

    The source profile is the authenticated member's exact canonical profile.
    This deliberately uses its retained immutable IDs and strongly consistent
    reads; display names, a local cache, and broad table scans never grant
    entry to another household profile.
    """
    if not isinstance(source_profile, dict):
        return []
    candidates = source_profile.get("switch_profile_ids") or []
    if not isinstance(candidates, list) or len(candidates) > 64:
        return []
    resolved = []
    seen = set()
    for value in candidates:
        profile_id = str(value or "").strip()
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        target = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(target, dict)
            or target.get("state") != "active"
            or str(target.get("profile_id") or "") != profile_id
            or str(target.get("household_id") or "") != household_id
        ):
            continue
        display_name = str(target.get("display_name") or "").strip()
        profile_type = str(target.get("profile_type") or "").strip().lower()
        if not display_name or profile_type not in {"adult", "teen", "child", "kid"}:
            continue
        resolved.append({
            "profile_id": profile_id,
            "profile_type": profile_type,
            "display_name": display_name,
            "access_level": "switch",
            "status": "active",
            "switch_protection": _profile_switch_protection(target),
            "cloud_access_enabled": _profile_cloud_access_enabled(target),
            "parental_controls": target.get("parental_controls"),
        })
    return resolved


def _authorized_parent_managed_profile_access(
    *, principal, source_profile, household_id, is_household_owner,
):
    """Recover exact Owner-managed child profiles without widening access.

    Older parent-managed profiles were appended to the Owner principal but
    were not also appended to the Owner profile's switch/watch lists. The
    principal record is already the authenticated, strongly-read authority
    used by identity V3. Only canonical children whose owner pointer matches
    that exact principal are projected here.
    """
    if not is_household_owner or not isinstance(principal, dict) or not isinstance(source_profile, dict):
        return []
    principal_id = str(principal.get("principal_id") or "").strip()
    source_profile_id = str(source_profile.get("profile_id") or "").strip()
    candidates = principal.get("profile_ids") or []
    if not principal_id or not isinstance(candidates, list) or len(candidates) > 64:
        return []
    resolved = []
    seen = set()
    for value in candidates:
        profile_id = str(value or "").strip()
        if not profile_id or profile_id == source_profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        target = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if not (
            isinstance(target, dict)
            and target.get("state") == "active"
            and bool_value(target.get("managed_by_owner"), False)
            and str(target.get("owner_principal_id") or "") == principal_id
            and str(target.get("household_id") or "") == household_id
            and str(target.get("profile_type") or "").strip().lower() in {"child", "kid"}
        ):
            continue
        display_name = str(target.get("display_name") or "").strip()
        if not display_name:
            continue
        resolved.append({
            "profile_id": profile_id,
            "profile_type": str(target.get("profile_type") or "").strip().lower(),
            "display_name": display_name,
            "access_level": "switch",
            "status": "active",
            "switch_protection": _profile_switch_protection(target),
            # Parent-managed children intentionally have no device membership
            # or Cloud seat until an invitation is redeemed.
            "cloud_access_enabled": False,
            "parental_controls": target.get("parental_controls"),
        })
    return resolved


def _authorized_viewing_profile_access(*, source_profile, household_id):
    """Resolve the caller's exact, owner-configured Who's Watching audience.

    This returns minimal, exact target metadata rather than a household roster.
    ``access_level=view`` is presentation/playback-only and is never accepted
    by Profile Switching or profile-mapping routes.
    """
    if not isinstance(source_profile, dict):
        return []
    candidates = source_profile.get("watching_profile_ids") or []
    if not isinstance(candidates, list) or len(candidates) > 64:
        candidates = []
    resolved = []
    seen = set()
    for value in candidates:
        profile_id = str(value or "").strip()
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        target = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if not (
            isinstance(target, dict)
            and target.get("state") == "active"
            and str(target.get("profile_id") or "") == profile_id
            and str(target.get("household_id") or "") == household_id
        ):
            continue
        display_name = str(target.get("display_name") or "").strip()
        profile_type = str(target.get("profile_type") or "").strip().lower()
        if not display_name or profile_type not in {"adult", "teen", "child", "kid"}:
            continue
        resolved.append({
            "profile_id": profile_id,
            "profile_type": profile_type,
            "display_name": display_name,
            "access_level": "view",
            "status": "active",
            "cloud_access_enabled": _profile_cloud_access_enabled(target),
            "parental_controls": target.get("parental_controls"),
        })
    return resolved


def _decorate_profile_access_with_switch_protection(items, *, household_id):
    decorated = []
    for item in items:
        if not isinstance(item, dict):
            continue
        profile_id = str(item.get("profile_id") or "")
        target = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item") if profile_id else None
        result = dict(item)
        if (
            isinstance(target, dict)
            and target.get("state") == "active"
            and str(target.get("household_id") or "") == household_id
        ):
            result["switch_protection"] = _profile_switch_protection(target)
        else:
            # Legacy profile projections do not gain PIN protection by
            # absence. They remain direct only until their canonical identity
            # is available for a fresh server-authoritative decision.
            result["switch_protection"] = "not_configured"
        decorated.append(result)
    return decorated


def _identity_migration_audit(event, session, event_type, result, *, reason_code=""):
    return prepare_security_audit(
        event,
        str(session.get("household_id") or ""),
        event_type,
        str(session.get("principal_id") or ""),
        target_id=str(session.get("account_id") or ""),
        target_type="account",
        result=result,
        reason_code=reason_code,
    )


def _migration_response_with_identity(event, state, verified_session):
    resolved = identity_me_v3(event, verified_session=verified_session)
    if resolved.get("statusCode") != 200:
        # Account migration intentionally precedes membership migration. Its
        # successful write is still reportable even though /me correctly asks
        # for the next additive normalization step.
        if resolved.get("statusCode") == 409:
            body = json.loads(resolved["body"])
            if body.get("state") == "household_membership_migration_required":
                body["migration_state"] = state
                return response(200, body)
        return resolved
    body = json.loads(resolved["body"])
    body["migration_state"] = state
    return response(200, body)


HOME_CONNECTOR_BINDING_SCHEMA_VERSION = 1


def _home_connector_binding_candidates(profile_id):
    """Read connector provenance without accepting a client connector id.

    The connector profile index is the sole lookup path.  A profile binding
    must never enumerate unrelated household connectors merely to find an
    eligible record.  The caller subsequently checks the protected Identity
    context and V3 enrollment proof before a record is eligible.
    """
    if home_connectors_table is None:
        return None
    records = []
    options = {
        "IndexName": HOME_CONNECTORS_PROFILE_INDEX,
        "KeyConditionExpression": Key("profile_id").eq(str(profile_id)),
        "ProjectionExpression": (
            "connector_id, profile_id, protocol_version, auth_state, #state, revoked, "
            "account_binding, family_binding, plugin_instance_id, plugin_public_key_fingerprint, "
            "plugin_key_id, binding_status, account_id, household_id, last_seen_at, last_seen_epoch"
        ),
        "ExpressionAttributeNames": {"#state": "state"},
    }
    while True:
        page = home_connectors_table.query(**options)
        records.extend(page.get("Items", []))
        if not page.get("LastEvaluatedKey"):
            break
        options["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return [item for item in records if str(item.get("profile_id") or "") == str(profile_id)]


def _home_connector_binding_context(event):
    """Derive the sole eligible connector from the protected authority graph."""
    # Authenticate and consume the DPoP proof once, then reuse that verified
    # session for the authority resolver. A second authentication attempt
    # would correctly be rejected as a replay.
    session = authenticated_app_session(event)
    if not session:
        return None, None, response(401, {"state": "protected_session_required"})
    resolved = identity_me_v3(event, verified_session=session)
    if resolved.get("statusCode") != 200:
        return None, None, resolved
    try:
        identity = json.loads(str(resolved.get("body") or "{}"))
    except json.JSONDecodeError:
        return None, None, response(503, {"state": "manual_review_required"})
    account_id = str((identity.get("account") or {}).get("account_id") or "")
    household = identity.get("household") or {}
    household_id = str(household.get("household_id") or "")
    profile_id = str((session or {}).get("profile_id") or "")
    if not session or not all((account_id, household_id, profile_id)):
        return None, None, response(401, {"state": "protected_session_required"})
    if str((identity.get("account") or {}).get("status") or "") != "active":
        return None, None, response(409, {"state": "account_inactive"})
    if str(household.get("status") or "") != "active":
        return None, None, response(409, {"state": "household_membership_inactive"})
    if not isinstance(identity.get("profile_access"), list) or not identity["profile_access"]:
        return None, None, response(409, {"state": "manual_review_required"})
    candidates = _home_connector_binding_candidates(profile_id)
    if candidates is None:
        return None, None, response(503, {"state": "connector_binding_unavailable"})
    if not candidates:
        return None, None, response(404, {"state": "connector_not_found"})
    v3_candidates = [item for item in candidates if item.get("protocol_version") == PAIRING_V3_PROTOCOL]
    if not v3_candidates:
        return None, None, response(409, {"state": "connector_not_v3"})
    active_candidates = [
        item for item in v3_candidates
        if item.get("auth_state") == "v3_active"
        and item.get("state") == "active"
        and not bool_value(item.get("revoked"), False)
    ]
    if not active_candidates:
        state = "connector_revoked" if any(bool_value(item.get("revoked"), False) for item in v3_candidates) else "connector_inactive"
        return None, None, response(409, {"state": state})
    account_hash = pairing_v3_sha256_b64url(account_id.encode("utf-8"))
    household_hash = pairing_v3_sha256_b64url(household_id.encode("utf-8"))
    candidates = [
        item for item in active_candidates
        if hmac.compare_digest(str(item.get("account_binding") or ""), account_hash)
        and hmac.compare_digest(str(item.get("family_binding") or ""), household_hash)
    ]
    if not candidates:
        return None, None, response(409, {"state": "connector_enrollment_mismatch"})
    if len(candidates) > 1:
        return None, None, response(409, {"state": "authority_ambiguous"})
    connector = candidates[0]
    if not all(str(connector.get(key) or "") for key in (
        "connector_id", "plugin_instance_id", "plugin_public_key_fingerprint", "plugin_key_id",
    )):
        return None, None, response(409, {"state": "connector_enrollment_unverified"})
    return session, {
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "membership_id": str(household.get("membership_id") or ""),
    }, connector


def _public_home_connector_binding(connector, context):
    bound = (
        connector.get("binding_status") == "bound"
        and hmac.compare_digest(str(connector.get("account_id") or ""), context["account_id"])
        and hmac.compare_digest(str(connector.get("household_id") or ""), context["household_id"])
    )
    return {
        "schema_version": HOME_CONNECTOR_BINDING_SCHEMA_VERSION,
        "state": "bound" if bound else "binding_required",
        "binding_status": "bound" if bound else "missing",
        "eligible": not bound,
        "connector": {
            "auth_state": "v3_active", "status": "active",
            "plugin_key_id_present": bool(connector.get("plugin_key_id")),
            "heartbeat_at": str(connector.get("last_seen_at") or ""),
        },
        "account": {"status": "active"},
        "household": {"status": "active", "membership_id": context["membership_id"]},
        "cloud_profile_available": True,
    }


def get_home_connector_binding_v3(event):
    _session, context, connector_or_failure = _home_connector_binding_context(event)
    if context is None:
        return connector_or_failure
    return response(200, _public_home_connector_binding(connector_or_failure, context))


def bind_home_connector_v3(event):
    """Explicit, idempotent account/household binding for one V3 connector."""
    body = parse_json_body(event)
    if body not in (None, {}):
        return response(400, {"state": "client_authority_input_forbidden" if isinstance(body, dict) else "bad_request"})
    session, context, connector_or_failure = _home_connector_binding_context(event)
    if context is None:
        return connector_or_failure
    connector = connector_or_failure
    is_bound = (
        connector.get("binding_status") == "bound"
        and hmac.compare_digest(str(connector.get("account_id") or ""), context["account_id"])
        and hmac.compare_digest(str(connector.get("household_id") or ""), context["household_id"])
    )
    if is_bound:
        try:
            commit_security_audit(_profile_binding_audit(
                event, session, "home_connector_binding_already_bound", "success",
                target_id=str(connector.get("connector_id") or ""), target_type="home_connector",
            ))
        except AuditReferenceError:
            return audit_unavailable_response()
        return response(200, {**_public_home_connector_binding(connector, context), "state": "already_bound"})
    if any(str(connector.get(key) or "") for key in ("binding_status", "account_id", "household_id")):
        return response(409, {"state": "existing_binding_conflict"})
    if security_audit_table is None or home_connectors_table is None:
        return response(503, {"state": "manual_review_required"})
    now = utc_now_iso()
    try:
        audit = _profile_binding_audit(
            event, session, "home_connector_binding_completed", "success",
            target_id=str(connector.get("connector_id") or ""), target_type="home_connector",
        )
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Update": {
                "TableName": HOME_CONNECTORS_TABLE,
                "Key": {"connector_id": str(connector.get("connector_id") or "")},
                "ConditionExpression": (
                    "attribute_exists(connector_id) AND protocol_version = :protocol AND auth_state = :auth "
                    "AND #state = :active AND (attribute_not_exists(revoked) OR revoked = :false) "
                    "AND profile_id = :profile AND account_binding = :account_hash "
                    "AND family_binding = :household_hash AND plugin_instance_id = :plugin_instance "
                    "AND plugin_public_key_fingerprint = :fingerprint AND plugin_key_id = :plugin_key "
                    "AND attribute_not_exists(binding_status) AND attribute_not_exists(account_id) "
                    "AND attribute_not_exists(household_id)"
                ),
                "UpdateExpression": (
                    "SET account_id = :account, household_id = :household, binding_status = :bound, "
                    "bound_at = :now, bound_by_account_id = :account, binding_method = :method, "
                    "binding_schema_version = :schema, binding_installation_id = :installation, binding_updated_at = :now"
                ),
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {
                    ":protocol": PAIRING_V3_PROTOCOL, ":auth": "v3_active", ":active": "active", ":false": False,
                    ":profile": context["profile_id"],
                    ":account_hash": pairing_v3_sha256_b64url(context["account_id"].encode("utf-8")),
                    ":household_hash": pairing_v3_sha256_b64url(context["household_id"].encode("utf-8")),
                    ":plugin_instance": str(connector.get("plugin_instance_id") or ""),
                    ":fingerprint": str(connector.get("plugin_public_key_fingerprint") or ""),
                    ":plugin_key": str(connector.get("plugin_key_id") or ""),
                    ":account": context["account_id"], ":household": context["household_id"],
                    ":bound": "bound", ":now": now,
                    ":method": "protected_session_verified_v3_enrollment_v1",
                    ":schema": HOME_CONNECTOR_BINDING_SCHEMA_VERSION,
                    ":installation": str(session.get("installation_id") or ""),
                },
            }},
            {"Put": {"TableName": SECURITY_AUDIT_TABLE, "Item": audit,
                      "ConditionExpression": "attribute_not_exists(event_id)"}},
        ])
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            return response(409, {"state": "existing_binding_conflict"})
        raise
    updated = dict(connector)
    updated.update({"account_id": context["account_id"], "household_id": context["household_id"], "binding_status": "bound"})
    return response(200, {**_public_home_connector_binding(updated, context), "state": "binding_completed"})


def migrate_existing_account_v3(event, *, verified_session=None, audit_attempt=True, retry_on_conflict=True):
    """Atomically add normalized records for one legacy protected session."""
    if any(table is None for table in (
        accounts_table,
        auth_identities_table,
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
        security_audit_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})

    session = verified_session if verified_session is not None else authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    subject = str(session.get("principal_id") or "")
    household_id = str(session.get("household_id") or "")
    profile_id = str(session.get("profile_id") or "")
    if not all((subject, household_id, profile_id)):
        return response(401, {"state": "migration_ineligible"})

    if audit_attempt:
        try:
            attempted = _identity_migration_audit(event, session, "identity_migration_attempted", "attempted")
            commit_security_audit(attempted)
        except AuditReferenceError:
            return audit_unavailable_response()

    principal = principals_table.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    membership = identity_memberships_table.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    household = identity_households_table.get_item(Key={"household_id": household_id}, ConsistentRead=True).get("Item")
    profile = identity_profiles_table.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item")
    now = epoch_now()
    now_iso = utc_now_iso()
    try:
        # Validate the graph before reading any normalized record by an
        # account id.  The protected session is not allowed to nominate it.
        preliminary = plan_existing_account_backfill(
            subject=subject, principal=principal, membership=membership,
            household=household, profile=profile,
            existing_account=None, existing_auth_identity=None,
            now_iso=now_iso, now_epoch=now,
        )
        claims = preliminary.claims
        if any(not hmac.compare_digest(str(session.get(key) or ""), expected) for key, expected in (
            ("account_id", claims.account_id),
            ("household_id", claims.household_id),
            ("profile_id", claims.profile_id),
            ("role", claims.role),
            ("authz_version", str(claims.authz_version)),
        )):
            outcome = _identity_migration_audit(event, session, "identity_migration_rejected", "denied", reason_code="stale_authorization")
            commit_security_audit(outcome)
            return response(401, {"state": "migration_ineligible"})

        existing_account = accounts_table.get_item(
            Key={"account_id": claims.account_id}, ConsistentRead=True,
        ).get("Item")
        auth_key = provider_subject_key("cognito", subject)
        existing_identity = auth_identities_table.get_item(
            Key={"auth_identity_key": auth_key}, ConsistentRead=True,
        ).get("Item")
        plan = plan_existing_account_backfill(
            subject=subject, principal=principal, membership=membership,
            household=household, profile=profile,
            existing_account=existing_account, existing_auth_identity=existing_identity,
            now_iso=now_iso, now_epoch=now,
        )
    except AccountFoundationError as error:
        state = error.reason
        event_type = "identity_migration_manual_review" if state == "manual_review_required" else "identity_migration_rejected"
        if state == "provider_identity_conflict":
            event_type = "identity_migration_conflict_detected"
        try:
            outcome = _identity_migration_audit(event, session, event_type, "denied", reason_code=state)
            commit_security_audit(outcome)
        except AuditReferenceError:
            return audit_unavailable_response()
        return response(409 if state in {"manual_review_required", "provider_identity_conflict"} else 401, {"state": state})

    if plan.is_already_migrated:
        try:
            outcome = _identity_migration_audit(event, session, "identity_migration_already_migrated", "success")
            commit_security_audit(outcome)
        except AuditReferenceError:
            return audit_unavailable_response()
        return _migration_response_with_identity(event, "already_migrated", session)

    try:
        completed = _identity_migration_audit(event, session, "identity_migration_completed", "success")
        writes = []
        if plan.account_record is not None:
            writes.append({"Put": {
                "TableName": ACCOUNTS_TABLE,
                "Item": plan.account_record,
                "ConditionExpression": "attribute_not_exists(account_id)",
            }})
        if plan.auth_identity_record is not None:
            writes.append({"Put": {
                "TableName": AUTH_IDENTITIES_TABLE,
                "Item": plan.auth_identity_record,
                "ConditionExpression": "attribute_not_exists(auth_identity_key)",
            }})
        writes.append({"Put": {
            "TableName": SECURITY_AUDIT_TABLE,
            "Item": completed,
            "ConditionExpression": "attribute_not_exists(event_id)",
        }})
        dynamodb.meta.client.transact_write_items(TransactItems=writes)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "TransactionCanceledException":
            raise
        # A competing request may have created precisely the same additive
        # records. Re-read through the same authority graph; never overwrite
        # and never re-check an already-consumed DPoP proof.
        if retry_on_conflict:
            return migrate_existing_account_v3(
                event,
                verified_session=session,
                audit_attempt=False,
                retry_on_conflict=False,
            )
        outcome = _identity_migration_audit(event, session, "identity_migration_conflict_detected", "denied", reason_code="migration_conflict")
        commit_security_audit(outcome)
        return response(409, {"state": "migration_conflict"})
    return _migration_response_with_identity(event, "migration_completed", session)


def _membership_migration_audit(event, session, event_type, result, *, membership_id="", reason_code=""):
    return prepare_security_audit(
        event,
        str(session.get("household_id") or ""),
        event_type,
        str(session.get("principal_id") or ""),
        target_id=membership_id or str(session.get("account_id") or ""),
        target_type="household_membership",
        result=result,
        reason_code=reason_code,
    )


def _membership_migration_failure(event, session, state):
    event_type = {
        "household_authority_ambiguous": "household_membership_migration_ambiguous_authority",
        "legacy_role_unresolved": "household_membership_migration_legacy_role_unresolved",
        "ownership_conflict": "household_membership_migration_ownership_conflict",
        "membership_conflict": "household_membership_migration_conflict",
    }.get(state, "household_membership_migration_manual_review")
    try:
        outcome = _membership_migration_audit(event, session, event_type, "denied", reason_code=state)
        commit_security_audit(outcome)
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(409, {"state": state})


def migrate_household_membership_v3(event, *, verified_session=None, audit_attempt=True, retry_on_conflict=True):
    """Atomically create one normalized membership from the legacy authority graph.

    The request body is intentionally ignored.  Account, household, role,
    capability, profile-access, and provider values are never client inputs to
    this migration; the DPoP-bound app session and authority graph decide all
    of them.
    """
    if any(table is None for table in (
        accounts_table,
        auth_identities_table,
        household_memberships_table,
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
        security_audit_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})

    session = verified_session if verified_session is not None else authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    subject = str(session.get("principal_id") or "")
    if not all((subject, str(session.get("account_id") or ""), str(session.get("household_id") or ""), str(session.get("profile_id") or ""))):
        return response(401, {"state": "migration_ineligible"})
    if audit_attempt:
        try:
            commit_security_audit(_membership_migration_audit(
                event, session, "household_membership_migration_attempted", "attempted",
            ))
        except AuditReferenceError:
            return audit_unavailable_response()

    principal = principals_table.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    legacy_membership = identity_memberships_table.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    household = identity_households_table.get_item(
        Key={"household_id": str(session.get("household_id") or "")}, ConsistentRead=True,
    ).get("Item")
    profile = identity_profiles_table.get_item(
        Key={"profile_id": str(session.get("profile_id") or "")}, ConsistentRead=True,
    ).get("Item")
    now = epoch_now()
    now_iso = utc_now_iso()
    try:
        # First resolve only the graph. The session cannot nominate an account
        # or membership key before server-side authority validation succeeds.
        preliminary = plan_household_membership_normalization(
            subject=subject, principal=principal, legacy_membership=legacy_membership,
            household=household, profile=profile, existing_membership=None,
            existing_account_guard=None, existing_owner_guard=None,
            now_iso=now_iso, now_epoch=now,
        )
        claims = preliminary.claims
        if any(not hmac.compare_digest(str(session.get(key) or ""), expected) for key, expected in (
            ("account_id", claims.account_id),
            ("household_id", claims.household_id),
            ("profile_id", claims.profile_id),
            ("role", claims.role),
            ("authz_version", str(claims.authz_version)),
        )):
            return _membership_migration_failure(event, session, "manual_review_required")

        account = accounts_table.get_item(Key={"account_id": claims.account_id}, ConsistentRead=True).get("Item")
        if (
            not isinstance(account, dict)
            or account.get("entity_type") != "Account"
            or account.get("status") != "active"
            or int(account.get("schema_version") or 0) != ACCOUNT_SCHEMA_VERSION
        ):
            return _membership_migration_failure(event, session, "account_migration_required")
        cognito_identity = auth_identities_table.get_item(
            Key={"auth_identity_key": provider_subject_key("cognito", subject)}, ConsistentRead=True,
        ).get("Item")
        assert_auth_identity_binding(
            cognito_identity, account_id=claims.account_id, provider="cognito", provider_subject=subject,
        )

        membership_id = household_membership_id(claims.account_id, claims.household_id)
        existing_membership = household_memberships_table.get_item(Key={
            "household_id": claims.household_id, "membership_id": membership_id,
        }, ConsistentRead=True).get("Item")
        existing_account_guard = household_memberships_table.get_item(Key={
            "household_id": claims.household_id,
            "membership_id": account_household_guard_id(claims.account_id, claims.household_id),
        }, ConsistentRead=True).get("Item")
        existing_owner_guard = household_memberships_table.get_item(Key={
            "household_id": claims.household_id,
            "membership_id": household_owner_guard_id(claims.household_id),
        }, ConsistentRead=True).get("Item")
        plan = plan_household_membership_normalization(
            subject=subject, principal=principal, legacy_membership=legacy_membership,
            household=household, profile=profile, existing_membership=existing_membership,
            existing_account_guard=existing_account_guard, existing_owner_guard=existing_owner_guard,
            now_iso=now_iso, now_epoch=now,
        )
    except AccountFoundationError as error:
        return _membership_migration_failure(event, session, error.reason)

    if plan.is_already_normalized:
        try:
            commit_security_audit(_membership_migration_audit(
                event, session, "household_membership_migration_already_normalized", "success",
                membership_id=plan.membership_id,
            ))
        except AuditReferenceError:
            return audit_unavailable_response()
        return _migration_response_with_identity(event, "already_normalized", session)

    try:
        completed = _membership_migration_audit(
            event, session, "household_membership_migration_completed", "success",
            membership_id=plan.membership_id,
        )
        writes = []
        for item in (plan.membership_record, plan.uniqueness_guard_record, plan.owner_guard_record):
            if item is not None:
                writes.append({"Put": {
                    "TableName": HOUSEHOLD_MEMBERSHIPS_TABLE,
                    "Item": item,
                    "ConditionExpression": "attribute_not_exists(household_id) AND attribute_not_exists(membership_id)",
                }})
        writes.append({"Put": {
            "TableName": SECURITY_AUDIT_TABLE,
            "Item": completed,
            "ConditionExpression": "attribute_not_exists(event_id)",
        }})
        dynamodb.meta.client.transact_write_items(TransactItems=writes)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "TransactionCanceledException":
            raise
        # A winner can only have written the same deterministic membership or
        # an owner/uniqueness guard. Re-read without consuming DPoP again.
        if retry_on_conflict:
            return migrate_household_membership_v3(
                event, verified_session=session, audit_attempt=False, retry_on_conflict=False,
            )
        return _membership_migration_failure(event, session, "membership_conflict")
    return _migration_response_with_identity(event, "membership_migration_completed", session)


def _profile_binding_audit(event, session, event_type, result, *, target_id="", target_type="profile", reason_code=""):
    return prepare_security_audit(
        event,
        str(session.get("household_id") or ""),
        event_type,
        str(session.get("principal_id") or ""),
        target_id=target_id or str(session.get("account_id") or ""),
        target_type=target_type,
        result=result,
        reason_code=reason_code,
    )


def _normalized_profile_context(event, session):
    """Use the existing centralized /me resolver without consuming DPoP twice."""
    resolved = identity_me_v3(event, verified_session=session)
    if resolved.get("statusCode") != 200:
        return None, resolved
    return json.loads(resolved["body"]), None


def _ownership_transfer_failure(event, session, state, *, target_id=""):
    try:
        commit_security_audit(_profile_binding_audit(
            event,
            session,
            "household_ownership_transfer_rejected",
            "denied",
            target_id=target_id or str(session.get("household_id") or ""),
            target_type="household_membership",
            reason_code=state,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    status_code = 403 if state == "ownership_transfer_not_authorized" else 409
    return response(status_code, {"state": state})


def _ownership_transfer_context(event):
    required = (
        household_memberships_table,
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
        security_audit_table,
    )
    if any(table is None for table in required):
        return None, None, response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return None, None, response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return None, None, failure
    capabilities = set((context.get("household") or {}).get("capabilities") or [])
    if "household.transfer_ownership" not in capabilities:
        return None, None, _ownership_transfer_failure(
            event, session, "ownership_transfer_not_authorized",
        )
    if (
        str((context.get("household") or {}).get("canonical_role") or "") != CanonicalRole.OWNER.value
        or str((context.get("household") or {}).get("household_access_role") or "")
        != HouseholdAccessRole.OWNER.value
    ):
        return None, None, _ownership_transfer_failure(
            event, session, "ownership_transfer_not_authorized",
        )
    return session, context, None


def _household_membership_records(household_id):
    records = []
    query = {
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ConsistentRead": True,
    }
    while True:
        page = household_memberships_table.query(**query)
        records.extend(page.get("Items", []))
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def _household_cloud_profile_records(household_id):
    """Read only the canonical Cloud Profile household partition.

    DynamoDB does not allow a strongly consistent GSI query.  Each index hit
    is consequently re-read by its exact primary key before it is returned.
    """
    records = []
    query = {
        "IndexName": "household_id-created_at_epoch-index",
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ConsistentRead": False,
    }
    while True:
        page = profiles_table.query(**query)
        records.extend(page.get("Items", []))
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def _repair_legacy_active_membership_profile_pointer(
    normalized_membership, *, expected_profile_id=None,
):
    """Repair one legacy normalized membership from its exact identity graph.

    Older normalized rows predate the canonical ``profile_id`` pointer.  A
    missing pointer may be filled only when the account's strongly-read active
    ProfileBinding resolves to exactly one active Cloud Profile and the
    principal, legacy membership, household, and canonical IdentityProfile all
    agree.  Ambiguity is never resolved by name, invitation history, or Scan.
    """
    required = (
        household_memberships_table,
        profile_bindings_table,
        profiles_table,
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
    )
    if not all(required) or not isinstance(normalized_membership, dict):
        return normalized_membership
    if (
        normalized_membership.get("entity_type") != "HouseholdMembership"
        or normalized_membership.get("status") != "active"
        or int(normalized_membership.get("schema_version") or 0) != 1
    ):
        return normalized_membership

    existing_profile_id = str(normalized_membership.get("profile_id") or "").strip()
    if existing_profile_id:
        return normalized_membership

    account_id = str(normalized_membership.get("account_id") or "").strip()
    household_id = str(normalized_membership.get("household_id") or "").strip()
    membership_id = str(normalized_membership.get("membership_id") or "").strip()
    try:
        expected_membership_id = household_membership_id(account_id, household_id)
        expected_role = canonical_role(normalized_membership.get("canonical_role"))
    except AccountFoundationError:
        return normalized_membership
    if not account_id or not household_id or membership_id != expected_membership_id:
        return normalized_membership

    requested_profile_id = str(expected_profile_id or "").strip()
    candidates = []
    bindings = profile_bindings_table.query(
        KeyConditionExpression=Key("account_id").eq(account_id),
        ConsistentRead=True,
    ).get("Items", [])
    for binding in bindings:
        if (
            not isinstance(binding, dict)
            or binding.get("entity_type") != "ProfileBinding"
            or binding.get("status") != "active"
            or str(binding.get("account_id") or "") != account_id
            or str(binding.get("household_id") or "") != household_id
        ):
            continue
        profile_id = str(binding.get("profile_id") or "").strip()
        if not profile_id or (requested_profile_id and profile_id != requested_profile_id):
            continue
        cloud_profile = profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        identity_profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(cloud_profile, dict)
            or cloud_profile.get("entity_type") != "Profile"
            or cloud_profile.get("status") != "active"
            or str(cloud_profile.get("profile_id") or "") != profile_id
            or str(cloud_profile.get("household_id") or "") != household_id
            or not isinstance(identity_profile, dict)
            or identity_profile.get("state") != "active"
            or bool_value(identity_profile.get("revoked"), False)
            or str(identity_profile.get("profile_id") or "") != profile_id
            or str(identity_profile.get("account_id") or "") != account_id
            or str(identity_profile.get("household_id") or "") != household_id
        ):
            continue

        owner_subject = str(identity_profile.get("owner_principal_id") or "").strip()
        member_subject = str(identity_profile.get("member_principal_id") or "").strip()
        subject = owner_subject if expected_role is CanonicalRole.OWNER else member_subject
        if not subject:
            continue
        principal = principals_table.get_item(
            Key={"principal_id": subject}, ConsistentRead=True,
        ).get("Item")
        legacy_membership = identity_memberships_table.get_item(
            Key={"principal_id": subject}, ConsistentRead=True,
        ).get("Item")
        household = identity_households_table.get_item(
            Key={"household_id": household_id}, ConsistentRead=True,
        ).get("Item")
        try:
            claims = derive_authoritative_claims(
                subject, principal, legacy_membership, household, identity_profile,
            )
            role = canonical_role(claims.role)
        except (AccountFoundationError, AuthorityError):
            continue
        if (
            claims.account_id != account_id
            or claims.household_id != household_id
            or claims.profile_id != profile_id
            or role is not expected_role
            or (role is CanonicalRole.OWNER and subject != owner_subject)
            or (role is not CanonicalRole.OWNER and subject != member_subject)
        ):
            continue
        candidates.append((profile_id, role))

    unique_candidates = {profile_id: role for profile_id, role in candidates}
    if len(unique_candidates) != 1:
        return normalized_membership
    profile_id, role = next(iter(unique_candidates.items()))
    access_role = household_access_role(
        normalized_membership.get("household_access_role"), canonical=role,
    ).value
    now_iso = utc_now_iso()
    now_epoch = epoch_now()
    try:
        household_memberships_table.update_item(
            Key={"household_id": household_id, "membership_id": membership_id},
            UpdateExpression=(
                "SET profile_id = :profile_id, "
                "household_access_role = if_not_exists(household_access_role, :access_role), "
                "updated_at = :updated_at, updated_at_epoch = :updated_at_epoch, "
                "migration_provenance = :provenance"
            ),
            ConditionExpression=(
                "entity_type = :entity_type AND #status = :active "
                "AND account_id = :account_id AND household_id = :household_id "
                "AND membership_id = :membership_id AND canonical_role = :canonical_role "
                "AND schema_version = :schema_version AND attribute_not_exists(profile_id)"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":profile_id": profile_id,
                ":access_role": access_role,
                ":updated_at": now_iso,
                ":updated_at_epoch": now_epoch,
                ":provenance": "exact-legacy-profile-pointer-reconciliation-v1",
                ":entity_type": "HouseholdMembership",
                ":active": "active",
                ":account_id": account_id,
                ":household_id": household_id,
                ":membership_id": membership_id,
                ":canonical_role": role.value,
                ":schema_version": 1,
            },
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        current = household_memberships_table.get_item(
            Key={"household_id": household_id, "membership_id": membership_id},
            ConsistentRead=True,
        ).get("Item")
        if not isinstance(current, dict) or str(current.get("profile_id") or "") != profile_id:
            return normalized_membership
        return current

    repaired = dict(normalized_membership)
    repaired.update({
        "profile_id": profile_id,
        "household_access_role": access_role,
        "updated_at": now_iso,
        "updated_at_epoch": now_epoch,
        "migration_provenance": "exact-legacy-profile-pointer-reconciliation-v1",
    })
    return repaired


def _public_household_profile_roster_item(profile, *, canonical_role, household_access_role):
    """Project only profile display and policy fields safe for a manager roster."""
    profile_id = str(profile.get("profile_id") or "")
    display_name = str(profile.get("display_name") or "").strip()
    profile_type = str(profile.get("profile_type") or "").strip().lower()
    if not profile_id or not display_name or profile_type not in {"adult", "teen", "child", "kid"}:
        raise AccountFoundationError("household_profile_roster_record_invalid")
    return {
        "profile_id": profile_id,
        "display_name": display_name,
        "profile_type": profile_type,
        "canonical_role": canonical_role,
        "household_access_role": household_access_role,
        # An Owner is never eligible for an accidental request-access denial.
        # Other roles retain the explicit stored value, including legacy false.
        "request_access_enabled": (
            str(household_access_role or "").lower() == HouseholdAccessRole.OWNER.value
            or str(canonical_role or "").lower() == CanonicalRole.OWNER.value
            or bool_value(profile.get("request_access_enabled"), False)
        ),
        "parental_controls": profile.get("parental_controls"),
        "cloud_access_enabled": bool_value(profile.get("cloud_access_enabled"), True),
        "allowed_profile_switch_targets": list(profile.get("switch_profile_ids") or []),
        "allowed_watching_targets": list(profile.get("watching_profile_ids") or []),
        "status": "active",
    }


def _parent_managed_household_profile_roster_items(*, session, context):
    """Project exact Owner-managed kids without inventing a Cloud seat.

    Parent-managed kids intentionally have no HouseholdMembership until they
    receive and redeem their own device invitation. The Owner principal's
    exact ``profile_ids`` edge remains the authority for showing those kids in
    profile editors; names, avatars, and broad table reads are never used.
    """
    household = (context or {}).get("household") or {}
    if str(household.get("canonical_role") or "") != CanonicalRole.OWNER.value:
        return []
    household_id = str(household.get("household_id") or "").strip()
    principal_id = str((session or {}).get("principal_id") or "").strip()
    source_profile_id = str((session or {}).get("profile_id") or "").strip()
    account_id = str((session or {}).get("account_id") or "").strip()
    if not all((household_id, principal_id, source_profile_id, account_id)):
        return []
    principal = principals_table.get_item(
        Key={"principal_id": principal_id}, ConsistentRead=True,
    ).get("Item")
    source_profile = identity_profiles_table.get_item(
        Key={"profile_id": source_profile_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(principal, dict)
        and principal.get("state") == "active"
        and str(principal.get("principal_id") or "") == principal_id
        and str(principal.get("account_id") or "") == account_id
        and str(principal.get("household_id") or "") == household_id
        and isinstance(source_profile, dict)
        and source_profile.get("state") == "active"
        and str(source_profile.get("profile_id") or "") == source_profile_id
        and str(source_profile.get("account_id") or "") == account_id
        and str(source_profile.get("household_id") or "") == household_id
        and str(source_profile.get("owner_principal_id") or "") == principal_id
    ):
        return []

    roster = []
    for access in _authorized_parent_managed_profile_access(
        principal=principal,
        source_profile=source_profile,
        household_id=household_id,
        is_household_owner=True,
    ):
        profile_id = str(access.get("profile_id") or "").strip()
        target = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if not (
            isinstance(target, dict)
            and target.get("state") == "active"
            and str(target.get("profile_id") or "") == profile_id
            and str(target.get("account_id") or "") == account_id
            and str(target.get("household_id") or "") == household_id
            and str(target.get("owner_principal_id") or "") == principal_id
            and bool_value(target.get("managed_by_owner"), False)
        ):
            continue
        try:
            # A roster projection must not turn a no-membership kid into an
            # apparent Cloud seat, including older records missing the field.
            roster_profile = {**target, "cloud_access_enabled": False}
            roster.append(_public_household_profile_roster_item(
                roster_profile,
                canonical_role=str(target.get("canonical_role") or CanonicalRole.CHILD.value),
                household_access_role=str(
                    target.get("household_access_role") or HouseholdAccessRole.MEMBER.value
                ),
            ))
        except AccountFoundationError:
            continue
    return roster


def list_household_profiles_v3(event):
    """Return the canonical active roster for a server-authorized manager.

    Invitations are deliberately not consulted: accepted, expired, and
    deleted invitations are workflow artifacts, never household profiles.
    """
    if any(table is None for table in (
        household_memberships_table,
        profile_bindings_table,
        profiles_table,
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    if "household.manage" not in set((context.get("household") or {}).get("capabilities") or []):
        return response(403, {"state": "household_profile_roster_not_authorized"})

    household_id = str((context.get("household") or {}).get("household_id") or "")
    if not household_id:
        return response(409, {"state": "household_profile_roster_unavailable"})

    # A 30-day deletion is revoked immediately and finalized on the first
    # authoritative Owner refresh at or after its execute time. An immediate
    # deletion can also be interrupted after its authority cutover, leaving an
    # exact ``deleting`` row. Continue that already-authorized cleanup on the
    # next Owner refresh rather than leaving an unusable terminal membership.
    # Every cleanup path remains exact-key/household-query based; no DynamoDB
    # Scan is used.
    if (
        str((context.get("household") or {}).get("canonical_role") or "")
        == CanonicalRole.OWNER.value
        and all((
            principals_table,
            identity_memberships_table,
            profiles_table,
            profile_bindings_table,
            profile_mappings_table,
            installations_table,
            app_sessions_table,
            household_invitations_table,
            household_join_transactions_table,
            events_table,
            profile_settings_table,
            entitlements_table,
            devices_table,
            security_audit_table,
        ))
    ):
        for membership in _household_membership_records(household_id):
            if (
                not isinstance(membership, dict)
                or membership.get("entity_type") != "HouseholdMembership"
                or membership.get("status") not in {"deletion_pending", "deleting"}
                or int(membership.get("deletion_execute_at_epoch") or 0) > epoch_now()
            ):
                continue
            profile_id = str(membership.get("profile_id") or "")
            if not profile_id:
                continue
            try:
                graph = _canonical_profile_deletion_context(
                    profile_id=profile_id,
                    household_id=household_id,
                    session=session,
                )
                if graph is not None:
                    _execute_canonical_profile_deletion(
                        event,
                        session,
                        context,
                        graph,
                        profile_id=profile_id,
                        household_id=household_id,
                        mode="immediate",
                    )
            except (AccountFoundationError, AuditReferenceError, ClientError):
                # The profile remains access-revoked and hidden. A later Owner
                # refresh retries the exact retained graph.
                LOGGER.warning("profile_retention_finalization_deferred")

    roster_by_profile_id = {}
    for membership in _household_membership_records(household_id):
        if (
            not isinstance(membership, dict)
            or membership.get("entity_type") != "HouseholdMembership"
            or membership.get("status") != "active"
            or str(membership.get("household_id") or "") != household_id
        ):
            continue
        membership = _repair_legacy_active_membership_profile_pointer(membership)
        profile_id = str(membership.get("profile_id") or "")
        if not profile_id:
            # A legacy normalized projection without an exact profile pointer
            # is intentionally not guessed or recovered by Scan.
            continue
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(profile, dict)
            or profile.get("state") != "active"
            or str(profile.get("profile_id") or "") != profile_id
            or str(profile.get("household_id") or "") != household_id
            or str(profile.get("account_id") or "") != str(membership.get("account_id") or "")
        ):
            continue
        try:
            item = _public_household_profile_roster_item(
                profile,
                canonical_role=str(membership.get("canonical_role") or ""),
                household_access_role=str(membership.get("household_access_role") or ""),
            )
        except AccountFoundationError:
            continue
        roster_by_profile_id[item["profile_id"]] = item

    # Parent-managed kids are canonical household profiles but deliberately
    # are not seat-bearing HouseholdMembership records. Include their exact
    # stored policy in Owner readback so editor saves remain visible without
    # changing invitation, credential, or Cloud-seat semantics.
    for item in _parent_managed_household_profile_roster_items(
        session=session, context=context,
    ):
        roster_by_profile_id[item["profile_id"]] = item

    profiles = sorted(roster_by_profile_id.values(), key=lambda item: (
        str(item["display_name"]).casefold(), item["profile_id"],
    ))
    return response(200, {
        "schema_version": 1,
        "state": "household_profiles_ready",
        "profiles": profiles,
    })


def _resolve_ownership_candidate(household, normalized_membership):
    if (
        not isinstance(normalized_membership, dict)
        or normalized_membership.get("entity_type") != "HouseholdMembership"
        or normalized_membership.get("status") != "active"
        or normalized_membership.get("canonical_role") != CanonicalRole.ADULT.value
        or normalized_membership.get("household_access_role")
        not in {HouseholdAccessRole.ADMIN.value, HouseholdAccessRole.MEMBER.value}
    ):
        raise AccountFoundationError("ownership_transfer_target_not_eligible")
    household_id = str(household.get("household_id") or "")
    account_id = str(normalized_membership.get("account_id") or "")
    profile_id = str(normalized_membership.get("profile_id") or "")
    if (
        not account_id
        or not profile_id
        or str(normalized_membership.get("household_id") or "") != household_id
        or str(normalized_membership.get("membership_id") or "")
        != household_membership_id(account_id, household_id)
    ):
        raise AccountFoundationError("ownership_transfer_target_not_eligible")
    profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    subject = str((profile or {}).get("member_principal_id") or "")
    if not subject:
        raise AccountFoundationError("ownership_transfer_target_not_eligible")
    principal = principals_table.get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    legacy_membership = identity_memberships_table.get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    try:
        claims, role, resolved_membership = resolve_household_membership(
            subject=subject,
            principal=principal,
            legacy_membership=legacy_membership,
            household=household,
            profile=profile,
            normalized_membership=normalized_membership,
        )
    except (AccountFoundationError, AuthorityError) as error:
        raise AccountFoundationError("ownership_transfer_target_not_eligible") from error
    if (
        role is not CanonicalRole.ADULT
        or claims.account_id != account_id
        or claims.household_id != household_id
        or claims.profile_id != profile_id
    ):
        raise AccountFoundationError("ownership_transfer_target_not_eligible")
    return {
        "account_id": account_id,
        "profile_id": profile_id,
        "subject": subject,
        "display_name": str(profile.get("display_name") or "").strip() or "Household member",
        "normalized_membership": resolved_membership,
        "principal": principal,
        "legacy_membership": legacy_membership,
        "profile": profile,
        "claims": claims,
    }


def list_ownership_transfer_candidates_v3(event):
    session, context, failure = _ownership_transfer_context(event)
    if failure:
        return failure
    household_id = str((context.get("household") or {}).get("household_id") or "")
    caller_account_id = str((context.get("account") or {}).get("account_id") or "")
    household = identity_households_table.get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(household, dict)
        or household.get("state") != "active"
        or str(household.get("owner_principal_id") or "")
        != str(session.get("principal_id") or "")
    ):
        return _ownership_transfer_failure(
            event, session, "ownership_transfer_authority_changed",
        )
    candidates = []
    for item in _household_membership_records(household_id):
        if (
            not isinstance(item, dict)
            or item.get("entity_type") != "HouseholdMembership"
            or str(item.get("account_id") or "") == caller_account_id
        ):
            continue
        try:
            candidate = _resolve_ownership_candidate(household, item)
        except AccountFoundationError:
            continue
        candidates.append({
            "account_id": candidate["account_id"],
            "profile_id": candidate["profile_id"],
            "display_name": candidate["display_name"],
            "canonical_role": CanonicalRole.ADULT.value,
            "household_access_role": str(item.get("household_access_role") or ""),
        })
    candidates.sort(key=lambda value: (
        str(value.get("display_name") or "").casefold(),
        str(value.get("profile_id") or ""),
    ))
    return response(200, {
        "state": "ownership_transfer_candidates_ready",
        "candidates": candidates,
    })


def transfer_household_ownership_v3(event):
    session, context, failure = _ownership_transfer_context(event)
    if failure:
        return failure
    body = parse_json_body(event)
    if not isinstance(body, dict) or body.get("explicit_confirmation") is not True:
        return _ownership_transfer_failure(
            event, session, "ownership_transfer_confirmation_required",
        )
    target_account_id = str(body.get("target_account_id") or "").strip()
    target_profile_id = str(body.get("target_profile_id") or "").strip()
    current_account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    current_subject = str(session.get("principal_id") or "")
    current_profile_id = str(session.get("profile_id") or "")
    if (
        not target_account_id
        or not target_profile_id
        or target_account_id == current_account_id
        or target_profile_id == current_profile_id
    ):
        return _ownership_transfer_failure(
            event, session, "ownership_transfer_target_not_eligible",
            target_id=target_profile_id,
        )

    household = identity_households_table.get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item")
    current_principal = principals_table.get_item(
        Key={"principal_id": current_subject}, ConsistentRead=True,
    ).get("Item")
    current_legacy_membership = identity_memberships_table.get_item(
        Key={"principal_id": current_subject}, ConsistentRead=True,
    ).get("Item")
    current_profile = identity_profiles_table.get_item(
        Key={"profile_id": current_profile_id}, ConsistentRead=True,
    ).get("Item")
    current_membership_id = household_membership_id(current_account_id, household_id)
    current_normalized_membership = household_memberships_table.get_item(Key={
        "household_id": household_id,
        "membership_id": current_membership_id,
    }, ConsistentRead=True).get("Item")
    owner_guard_id = household_owner_guard_id(household_id)
    owner_guard = household_memberships_table.get_item(Key={
        "household_id": household_id,
        "membership_id": owner_guard_id,
    }, ConsistentRead=True).get("Item")
    try:
        current_claims, current_role, _ = resolve_household_membership(
            subject=current_subject,
            principal=current_principal,
            legacy_membership=current_legacy_membership,
            household=household,
            profile=current_profile,
            normalized_membership=current_normalized_membership,
        )
        if (
            current_role is not CanonicalRole.OWNER
            or current_claims.account_id != current_account_id
            or current_claims.profile_id != current_profile_id
            or not isinstance(owner_guard, dict)
            or owner_guard.get("entity_type") != "HouseholdMembershipOwnerGuard"
            or owner_guard.get("status") != "active"
            or str(owner_guard.get("account_id") or "") != current_account_id
            or str(owner_guard.get("normalized_membership_id") or "") != current_membership_id
        ):
            raise AccountFoundationError("ownership_transfer_authority_changed")
        target_membership = household_memberships_table.get_item(Key={
            "household_id": household_id,
            "membership_id": household_membership_id(target_account_id, household_id),
        }, ConsistentRead=True).get("Item")
        candidate = _resolve_ownership_candidate(household, target_membership)
        if (
            candidate["account_id"] != target_account_id
            or candidate["profile_id"] != target_profile_id
        ):
            raise AccountFoundationError("ownership_transfer_target_not_eligible")
    except AccountFoundationError as error:
        return _ownership_transfer_failure(
            event, session, error.reason, target_id=target_profile_id,
        )

    now_iso = utc_now_iso()
    now_epoch = epoch_now()
    current_authz_version = int(current_claims.authz_version)
    target_authz_version = int(candidate["claims"].authz_version)
    target_subject = candidate["subject"]
    target_membership_id = household_membership_id(target_account_id, household_id)
    try:
        audit = _profile_binding_audit(
            event,
            session,
            "household_ownership_transferred",
            "success",
            target_id=target_profile_id,
            target_type="household_membership",
            reason_code="explicit_owner_transfer_v1",
        )
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Update": {
                "TableName": PRINCIPALS_TABLE,
                "Key": {"principal_id": current_subject},
                "ConditionExpression": (
                    "account_id = :account_id AND household_id = :household_id "
                    "AND #role = :owner AND authz_version = :current_version "
                    "AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET #role = :adult, canonical_role = :adult, "
                    "household_access_role = :admin, authz_version = :next_version, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#role": "role", "#state": "state"},
                "ExpressionAttributeValues": {
                    ":account_id": current_account_id,
                    ":household_id": household_id,
                    ":owner": CanonicalRole.OWNER.value,
                    ":adult": CanonicalRole.ADULT.value,
                    ":admin": HouseholdAccessRole.ADMIN.value,
                    ":current_version": current_authz_version,
                    ":next_version": current_authz_version + 1,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Update": {
                "TableName": PRINCIPALS_TABLE,
                "Key": {"principal_id": target_subject},
                "ConditionExpression": (
                    "account_id = :account_id AND household_id = :household_id "
                    "AND #role = :adult AND authz_version = :current_version "
                    "AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET #role = :owner, canonical_role = :owner, "
                    "household_access_role = :owner_access, authz_version = :next_version, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#role": "role", "#state": "state"},
                "ExpressionAttributeValues": {
                    ":account_id": target_account_id,
                    ":household_id": household_id,
                    ":adult": CanonicalRole.ADULT.value,
                    ":owner": CanonicalRole.OWNER.value,
                    ":owner_access": HouseholdAccessRole.OWNER.value,
                    ":current_version": target_authz_version,
                    ":next_version": target_authz_version + 1,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Update": {
                "TableName": IDENTITY_MEMBERSHIPS_TABLE,
                "Key": {"principal_id": current_subject},
                "ConditionExpression": (
                    "account_id = :account_id AND household_id = :household_id "
                    "AND profile_id = :profile_id AND #role = :owner "
                    "AND authz_version = :current_version AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET #role = :adult, canonical_role = :adult, "
                    "household_access_role = :admin, authz_version = :next_version, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#role": "role", "#state": "state"},
                "ExpressionAttributeValues": {
                    ":account_id": current_account_id,
                    ":household_id": household_id,
                    ":profile_id": current_profile_id,
                    ":owner": CanonicalRole.OWNER.value,
                    ":adult": CanonicalRole.ADULT.value,
                    ":admin": HouseholdAccessRole.ADMIN.value,
                    ":current_version": current_authz_version,
                    ":next_version": current_authz_version + 1,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Update": {
                "TableName": IDENTITY_MEMBERSHIPS_TABLE,
                "Key": {"principal_id": target_subject},
                "ConditionExpression": (
                    "account_id = :account_id AND household_id = :household_id "
                    "AND profile_id = :profile_id AND #role = :adult "
                    "AND authz_version = :current_version AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET #role = :owner, canonical_role = :owner, "
                    "household_access_role = :owner_access, authz_version = :next_version, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#role": "role", "#state": "state"},
                "ExpressionAttributeValues": {
                    ":account_id": target_account_id,
                    ":household_id": household_id,
                    ":profile_id": target_profile_id,
                    ":adult": CanonicalRole.ADULT.value,
                    ":owner": CanonicalRole.OWNER.value,
                    ":owner_access": HouseholdAccessRole.OWNER.value,
                    ":current_version": target_authz_version,
                    ":next_version": target_authz_version + 1,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Update": {
                "TableName": HOUSEHOLD_MEMBERSHIPS_TABLE,
                "Key": {"household_id": household_id, "membership_id": current_membership_id},
                "ConditionExpression": (
                    "entity_type = :entity AND account_id = :account_id "
                    "AND canonical_role = :owner AND household_access_role = :owner_access "
                    "AND #status = :active"
                ),
                "UpdateExpression": (
                    "SET canonical_role = :adult, household_access_role = :admin, "
                    "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
                ),
                "ExpressionAttributeNames": {"#status": "status"},
                "ExpressionAttributeValues": {
                    ":entity": "HouseholdMembership",
                    ":account_id": current_account_id,
                    ":owner": CanonicalRole.OWNER.value,
                    ":owner_access": HouseholdAccessRole.OWNER.value,
                    ":adult": CanonicalRole.ADULT.value,
                    ":admin": HouseholdAccessRole.ADMIN.value,
                    ":active": "active",
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                },
            }},
            {"Update": {
                "TableName": HOUSEHOLD_MEMBERSHIPS_TABLE,
                "Key": {"household_id": household_id, "membership_id": target_membership_id},
                "ConditionExpression": (
                    "entity_type = :entity AND account_id = :account_id "
                    "AND canonical_role = :adult AND #status = :active"
                ),
                "UpdateExpression": (
                    "SET canonical_role = :owner, household_access_role = :owner_access, "
                    "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
                ),
                "ExpressionAttributeNames": {"#status": "status"},
                "ExpressionAttributeValues": {
                    ":entity": "HouseholdMembership",
                    ":account_id": target_account_id,
                    ":adult": CanonicalRole.ADULT.value,
                    ":owner": CanonicalRole.OWNER.value,
                    ":owner_access": HouseholdAccessRole.OWNER.value,
                    ":active": "active",
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                },
            }},
            {"Update": {
                "TableName": HOUSEHOLD_MEMBERSHIPS_TABLE,
                "Key": {"household_id": household_id, "membership_id": owner_guard_id},
                "ConditionExpression": (
                    "entity_type = :entity AND account_id = :current_account_id "
                    "AND normalized_membership_id = :current_membership_id "
                    "AND #status = :active"
                ),
                "UpdateExpression": (
                    "SET account_id = :target_account_id, "
                    "normalized_membership_id = :target_membership_id, "
                    "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
                ),
                "ExpressionAttributeNames": {"#status": "status"},
                "ExpressionAttributeValues": {
                    ":entity": "HouseholdMembershipOwnerGuard",
                    ":current_account_id": current_account_id,
                    ":current_membership_id": current_membership_id,
                    ":target_account_id": target_account_id,
                    ":target_membership_id": target_membership_id,
                    ":active": "active",
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                },
            }},
            {"Update": {
                "TableName": IDENTITY_HOUSEHOLDS_TABLE,
                "Key": {"household_id": household_id},
                "ConditionExpression": (
                    "account_id = :current_account_id AND owner_principal_id = :current_subject "
                    "AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET account_id = :target_account_id, owner_principal_id = :target_subject, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {
                    ":current_account_id": current_account_id,
                    ":current_subject": current_subject,
                    ":target_account_id": target_account_id,
                    ":target_subject": target_subject,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Update": {
                "TableName": IDENTITY_PROFILES_TABLE,
                "Key": {"profile_id": current_profile_id},
                "ConditionExpression": (
                    "account_id = :account_id AND household_id = :household_id "
                    "AND owner_principal_id = :current_subject AND #role = :owner "
                    "AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET owner_principal_id = :target_subject, #role = :adult, "
                    "canonical_role = :adult, household_access_role = :admin, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#role": "role", "#state": "state"},
                "ExpressionAttributeValues": {
                    ":account_id": current_account_id,
                    ":household_id": household_id,
                    ":current_subject": current_subject,
                    ":target_subject": target_subject,
                    ":owner": CanonicalRole.OWNER.value,
                    ":adult": CanonicalRole.ADULT.value,
                    ":admin": HouseholdAccessRole.ADMIN.value,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Update": {
                "TableName": IDENTITY_PROFILES_TABLE,
                "Key": {"profile_id": target_profile_id},
                "ConditionExpression": (
                    "account_id = :account_id AND household_id = :household_id "
                    "AND member_principal_id = :target_subject AND #role = :adult "
                    "AND #state = :active"
                ),
                "UpdateExpression": (
                    "SET owner_principal_id = :target_subject, #role = :owner, "
                    "canonical_role = :owner, household_access_role = :owner_access, "
                    "updated_at = :updated_at"
                ),
                "ExpressionAttributeNames": {"#role": "role", "#state": "state"},
                "ExpressionAttributeValues": {
                    ":account_id": target_account_id,
                    ":household_id": household_id,
                    ":target_subject": target_subject,
                    ":adult": CanonicalRole.ADULT.value,
                    ":owner": CanonicalRole.OWNER.value,
                    ":owner_access": HouseholdAccessRole.OWNER.value,
                    ":active": "active",
                    ":updated_at": now_iso,
                },
            }},
            {"Put": {
                "TableName": SECURITY_AUDIT_TABLE,
                "Item": audit,
                "ConditionExpression": "attribute_not_exists(event_id)",
            }},
        ])
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            return _ownership_transfer_failure(
                event, session, "ownership_transfer_conflict", target_id=target_profile_id,
            )
        raise
    return response(200, {
        "state": "household_ownership_transferred",
        "requires_reauthentication": True,
    })


def _profile_binding_failure(event, session, state, *, target_id="", target_type="profile"):
    event_type = {
        "cross_household_binding_rejected": "profile_binding_cross_household_rejected",
        "profile_binding_conflict": "profile_binding_conflict",
        "profile_binding_not_reactivated": "profile_binding_rejected",
        "profile_access_level_not_permitted": "profile_binding_unauthorized_access_level",
    }.get(state, "profile_binding_rejected")
    try:
        commit_security_audit(_profile_binding_audit(
            event, session, event_type, "denied", target_id=target_id,
            target_type=target_type, reason_code=state,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(409 if state not in {"profile_access_level_not_permitted"} else 403, {"state": state})


def create_profile_v3(event):
    """Create a Cloud profile and creator-only manage binding atomically."""
    if any(table is None for table in (profiles_table, profile_bindings_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    if "household.manage" not in set((context.get("household") or {}).get("capabilities") or []):
        return _profile_binding_failure(event, session, "profile_creation_not_authorized", target_type="profile")
    body = parse_json_body(event)
    if not isinstance(body, dict):
        return _profile_binding_failure(event, session, "invalid_profile_request", target_type="profile")
    account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    try:
        plan = build_profile_creation(
            household_id=household_id,
            account_id=account_id,
            display_name=body.get("display_name"),
            profile_type=body.get("profile_type"),
            age_classification=body.get("age_classification"),
            now_iso=utc_now_iso(), now_epoch=epoch_now(),
        )
        audit = _profile_binding_audit(
            event, session, "profile_created", "success", target_id=plan.profile["profile_id"],
        )
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Put": {
                "TableName": PROFILES_TABLE, "Item": plan.profile,
                "ConditionExpression": "attribute_not_exists(profile_id)",
            }},
            {"Put": {
                "TableName": PROFILE_BINDINGS_TABLE, "Item": plan.binding,
                "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(profile_id)",
            }},
            {"Put": {
                "TableName": SECURITY_AUDIT_TABLE, "Item": audit,
                "ConditionExpression": "attribute_not_exists(event_id)",
            }},
        ])
    except AccountFoundationError as error:
        return _profile_binding_failure(event, session, error.reason, target_type="profile")
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            return _profile_binding_failure(event, session, "profile_creation_conflict", target_type="profile")
        raise
    return _migration_response_with_identity(event, "profile_created", session)


def profile_binding_path_id(path):
    match = re.fullmatch(r"/v3/identity/profiles/([^/]+)/bindings", str(path or ""))
    return match.group(1) if match else ""


def profile_switch_pin_path_id(path):
    match = re.fullmatch(r"/v3/identity/profiles/([^/]+)/switch-pin", str(path or ""))
    return match.group(1) if match else ""


def profile_switch_pin_verification_path_id(path):
    match = re.fullmatch(r"/v3/identity/profiles/([^/]+)/switch-pin/verify", str(path or ""))
    return match.group(1) if match else ""


def profile_switch_targets_path_id(path):
    match = re.fullmatch(r"/v3/identity/profiles/([^/]+)/switch-targets", str(path or ""))
    return match.group(1) if match else ""


def profile_watching_targets_path_id(path):
    match = re.fullmatch(r"/v3/identity/profiles/([^/]+)/watching-targets", str(path or ""))
    return match.group(1) if match else ""


def profile_deletion_path_id(path):
    match = re.fullmatch(r"/v3/identity/profiles/([^/]+)/deletion", str(path or ""))
    return match.group(1) if match else ""


def profile_jellyfin_binding_path_id(path):
    match = re.fullmatch(
        r"/v3/identity/profiles/([^/]+)/jellyfin-binding", str(path or ""),
    )
    return match.group(1) if match else ""


def profile_seerr_binding_path_id(path):
    match = re.fullmatch(
        r"/v3/identity/profiles/([^/]+)/seerr-binding", str(path or ""),
    )
    return match.group(1) if match else ""


def profile_pending_provider_cleanup_path_id(path):
    match = re.fullmatch(
        r"/v3/identity/profiles/([^/]+)/pending-provider-cleanup", str(path or ""),
    )
    return match.group(1) if match else ""


def _normalized_jellyfin_user_id(value):
    compact = str(value or "").strip().replace("-", "")
    return compact.lower() if re.fullmatch(r"[0-9a-fA-F]{32}", compact) else ""


def _normalized_seerr_user_id(value):
    """Return a canonical positive Seerr user id without accepting aliases."""
    if isinstance(value, bool):
        return ""
    compact = str(value or "").strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", compact):
        return ""
    try:
        parsed = int(compact)
    except (TypeError, ValueError):
        return ""
    return str(parsed) if parsed <= 2147483647 else ""


def _profile_jellyfin_binding_for_connector(profile_id, connector_id):
    """Resolve one exact active Cloud-profile provider edge for its connector."""
    if identity_profiles_table is None or not profile_id or not connector_id:
        return None
    profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    user_id = _normalized_jellyfin_user_id((profile or {}).get("jellyfin_user_id"))
    if (
        not isinstance(profile, dict)
        or profile.get("state") != "active"
        or str(profile.get("profile_id") or "") != profile_id
        or str(profile.get("jellyfin_binding_state") or "") != "active"
        or not hmac.compare_digest(
            str(profile.get("jellyfin_connector_id") or ""), connector_id,
        )
        or not user_id
    ):
        return None
    return {
        "provider": "jellyfin",
        "connector_id": connector_id,
        "provider_user_id": user_id,
    }


def _household_identity_profile_records(household_id):
    """Enumerate canonical profiles by household membership Query + exact GetItem."""
    if household_memberships_table is None or identity_profiles_table is None:
        return []
    records = {}
    for membership in _household_membership_records(household_id):
        if (
            not isinstance(membership, dict)
            or membership.get("entity_type") != "HouseholdMembership"
            or str(membership.get("household_id") or "") != household_id
        ):
            continue
        membership = _repair_legacy_active_membership_profile_pointer(membership)
        profile_id = str(membership.get("profile_id") or "")
        if not profile_id:
            continue
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            isinstance(profile, dict)
            and str(profile.get("profile_id") or "") == profile_id
            and hmac.compare_digest(
                str(profile.get("household_id") or ""), household_id,
            )
        ):
            records[profile_id] = profile
    return list(records.values())


def _delete_profile_binding_recovery_request(request_id, profile_id, connector_id):
    """Remove the one-time provider identity response after exact validation."""
    if remote_requests_table is None:
        return
    try:
        remote_requests_table.delete_item(
            Key={"request_id": request_id},
            ConditionExpression="profile_id = :profile_id AND connector_id = :connector_id",
            ExpressionAttributeValues={
                ":profile_id": profile_id,
                ":connector_id": connector_id,
            },
        )
    except ClientError:
        # The canonical profile update remains authoritative. A failed cleanup
        # retains only the bounded TTL record; it never changes authorization.
        LOGGER.warning("profile Jellyfin recovery response cleanup was deferred")


def _recover_profile_jellyfin_binding_from_connector(
    profile_id,
    connectors,
    *,
    timeout_seconds=8.0,
):
    """Ask exactly one online household connector for one exact stored edge.

    The command carries only the canonical Cloud profile identifier. The plugin
    resolves its existing profile-to-Jellyfin registry, never an Owner fallback
    or display-name match. The temporary response is deleted after validation.
    """
    if remote_requests_table is None:
        return {"state": "profile_jellyfin_binding_recovery_unavailable"}
    online = [
        item for item in connectors
        if isinstance(item, dict)
        and str(item.get("connector_id") or "")
        and connector_online_from_item(item)
    ]
    if len(online) != 1:
        return {
            "state": (
                "profile_jellyfin_connector_missing"
                if not online
                else "profile_jellyfin_connector_ambiguous"
            ),
        }

    connector_id = str(online[0].get("connector_id") or "")
    request_id = str(uuid.uuid4())
    now = utc_now_iso()
    request_payload = {
        "provider": "home_server",
        "method": "COMMAND",
        "path": "/commands/jellyfin.recover_profile_binding",
        "query": {},
        "body": {},
    }
    priority = remote_request_priority(request_payload)
    item = {
        "request_id": request_id,
        "profile_id": profile_id,
        "connector_id": connector_id,
        "status": "pending",
        "status_created_at": status_sort_key(
            "pending", now, request_id, priority,
        ),
        "priority": priority,
        "request_json": json.dumps(
            request_payload, separators=(",", ":"), sort_keys=True,
        ),
        "created_at": now,
        "updated_at": now,
        # Recovery responses contain a provider identifier only briefly. They
        # are deleted on success and expire quickly if the plugin is offline.
        "expires_at": epoch_now() + 5 * 60,
    }
    remote_requests_table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(request_id)",
    )

    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while time.monotonic() < deadline:
        current = remote_requests_table.get_item(
            Key={"request_id": request_id}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(current, dict):
            return {"state": "profile_jellyfin_binding_recovery_missing"}
        if not (
            hmac.compare_digest(
                str(current.get("profile_id") or ""), profile_id,
            )
            and hmac.compare_digest(
                str(current.get("connector_id") or ""), connector_id,
            )
        ):
            return {"state": "profile_jellyfin_binding_recovery_mismatch"}

        status = str(current.get("status") or "")
        if status == "completed":
            payload = decode_remote_response_payload(current, None)
            result = payload.get("result") if isinstance(payload, dict) else None
            user_id = _normalized_jellyfin_user_id(
                (result or {}).get("provider_user_id")
                if isinstance(result, dict) else ""
            )
            valid = (
                200 <= int(current.get("http_status") or 0) < 300
                and isinstance(payload, dict)
                and str(payload.get("requestId") or "") == request_id
                and payload.get("state") == "complete"
                and payload.get("operation") == "jellyfin.recover_profile_binding"
                and isinstance(result, dict)
                and result.get("provider") == "jellyfin"
                and bool(user_id)
            )
            _delete_profile_binding_recovery_request(
                request_id, profile_id, connector_id,
            )
            if not valid:
                return {"state": "profile_jellyfin_binding_recovery_invalid"}
            return {
                "state": "recovered",
                "connector_id": connector_id,
                "jellyfin_user_id": user_id,
            }
        if status == "failed":
            return {"state": "profile_jellyfin_binding_source_missing"}
        if status not in {"pending", "in_progress", "completing"}:
            return {"state": "profile_jellyfin_binding_recovery_invalid"}
        time.sleep(0.25)

    return {"state": "profile_jellyfin_binding_recovery_pending"}


def _execute_profile_binding_connector_command(
    profile_id,
    connectors,
    operation,
    parameters,
    *,
    timeout_seconds=8.0,
    binding_operation_id="",
):
    """Execute one exact, short-lived binding command on one online connector."""
    allowed_operations = {
        "jellyfin.inspect_profile_binding_owner",
        "jellyfin.reassign_stale_profile_binding",
        "seerr.delete_exact_bound_user",
        "jellyfin.delete_exact_bound_user",
        "seerr.delete_orphaned_jellyfin_user",
        "jellyfin.delete_pending_exact_user",
    }
    if remote_requests_table is None or operation not in allowed_operations:
        return {"state": "profile_jellyfin_binding_command_unavailable"}
    online = [
        item for item in connectors
        if isinstance(item, dict)
        and str(item.get("connector_id") or "")
        and connector_online_from_item(item)
    ]
    if len(online) != 1:
        return {
            "state": (
                "profile_jellyfin_connector_missing"
                if not online
                else "profile_jellyfin_connector_ambiguous"
            ),
        }

    connector_id = str(online[0].get("connector_id") or "")
    request_id = str(uuid.uuid4())
    now = utc_now_iso()
    request_payload = {
        "provider": "home_server",
        "method": "COMMAND",
        "path": f"/commands/{operation}",
        "query": {},
        "body": dict(parameters or {}),
    }
    if binding_operation_id:
        request_payload["binding_operation_id"] = binding_operation_id
    priority = remote_request_priority(request_payload)
    remote_requests_table.put_item(
        Item={
            "request_id": request_id,
            "profile_id": profile_id,
            "connector_id": connector_id,
            "status": "pending",
            "status_created_at": status_sort_key(
                "pending", now, request_id, priority,
            ),
            "priority": priority,
            "request_json": json.dumps(
                request_payload, separators=(",", ":"), sort_keys=True,
            ),
            "created_at": now,
            "updated_at": now,
            "expires_at": epoch_now() + 5 * 60,
            **({"binding_operation_id": binding_operation_id} if binding_operation_id else {}),
        },
        ConditionExpression="attribute_not_exists(request_id)",
    )
    if binding_operation_id:
        _binding_operation_transition(
            binding_operation_id, "dispatched", connector_request_id=request_id,
        )

    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while time.monotonic() < deadline:
        current = remote_requests_table.get_item(
            Key={"request_id": request_id}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(current, dict):
            return {"state": "profile_jellyfin_binding_command_missing"}
        if not (
            hmac.compare_digest(str(current.get("profile_id") or ""), profile_id)
            and hmac.compare_digest(
                str(current.get("connector_id") or ""), connector_id,
            )
        ):
            return {"state": "profile_jellyfin_binding_command_mismatch"}

        status = str(current.get("status") or "")
        if status == "completed":
            payload = decode_remote_response_payload(current, None)
            result = payload.get("result") if isinstance(payload, dict) else None
            expected_provider = "seerr" if operation.startswith("seerr.") else "jellyfin"
            valid = (
                200 <= int(current.get("http_status") or 0) < 300
                and isinstance(payload, dict)
                and str(payload.get("requestId") or "") == request_id
                and payload.get("state") == "complete"
                and payload.get("operation") == operation
                and isinstance(result, dict)
                and result.get("provider") == expected_provider
            )
            _delete_profile_binding_recovery_request(
                request_id, profile_id, connector_id,
            )
            if not valid:
                return {"state": "profile_jellyfin_binding_command_invalid"}
            return {
                "state": "completed",
                "connector_id": connector_id,
                "result": result,
            }
        if status == "failed":
            _delete_profile_binding_recovery_request(
                request_id, profile_id, connector_id,
            )
            return {"state": "profile_jellyfin_binding_command_failed"}
        if status not in {"pending", "in_progress", "completing"}:
            return {"state": "profile_jellyfin_binding_command_invalid"}
        time.sleep(0.25)

    return {"state": "profile_jellyfin_binding_command_pending"}


def _publish_profile_jellyfin_snapshot(profile_id, connectors, *, binding_operation_id, timeout_seconds=8.0):
    """Read the member-scoped snapshot after canonical persistence.

    The snapshot is computed by the connector with the target Cloud profile,
    so it cannot borrow the initiating Owner's libraries. Its contents are
    deliberately never retained in the operation ledger.
    """
    if remote_requests_table is None or not binding_operation_id:
        return {"state": "snapshot_unavailable"}
    online = [
        item for item in connectors
        if isinstance(item, dict)
        and str(item.get("connector_id") or "")
        and connector_online_from_item(item)
    ]
    if len(online) != 1:
        return {"state": "snapshot_connector_missing" if not online else "snapshot_connector_ambiguous"}
    connector_id = str(online[0].get("connector_id") or "")
    request_id = str(uuid.uuid4())
    now = utc_now_iso()
    request_payload = {
        "provider": "jellyfin",
        "method": "GET",
        "path": "/kaevo/internal/main-snapshot",
        "query": {"moviesLimit": "1", "showsLimit": "1", "continueLimit": "1"},
        "binding_operation_id": binding_operation_id,
    }
    remote_requests_table.put_item(
        Item={
            "request_id": request_id, "profile_id": profile_id,
            "connector_id": connector_id, "status": "pending",
            "status_created_at": status_sort_key("pending", now, request_id, remote_request_priority(request_payload)),
            "priority": remote_request_priority(request_payload),
            "request_json": json.dumps(request_payload, separators=(",", ":"), sort_keys=True),
            "created_at": now, "updated_at": now,
            "expires_at": epoch_now() + 5 * 60,
            "binding_operation_id": binding_operation_id,
        },
        ConditionExpression="attribute_not_exists(request_id)",
    )
    _binding_operation_transition(binding_operation_id, "snapshot_pending", connector_request_id=request_id)
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while time.monotonic() < deadline:
        current = remote_requests_table.get_item(
            Key={"request_id": request_id}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(current, dict) or not (
            hmac.compare_digest(str(current.get("profile_id") or ""), profile_id)
            and hmac.compare_digest(str(current.get("connector_id") or ""), connector_id)
        ):
            return {"state": "snapshot_request_invalid"}
        status = str(current.get("status") or "")
        if status == "completed":
            valid = 200 <= int(current.get("http_status") or 0) < 300
            _delete_profile_binding_recovery_request(request_id, profile_id, connector_id)
            return {"state": "snapshot_published" if valid else "snapshot_invalid"}
        if status == "failed":
            _delete_profile_binding_recovery_request(request_id, profile_id, connector_id)
            return {"state": "snapshot_connector_failed"}
        if status not in {"pending", "in_progress", "completing"}:
            return {"state": "snapshot_request_invalid"}
        time.sleep(0.25)
    return {"state": "snapshot_pending"}


def _binding_operation_id(value):
    candidate = str(value or "").strip()
    return candidate if BINDING_OPERATION_ID_RE.fullmatch(candidate) else ""


def _binding_operation_fingerprint(value):
    """One-way correlation only; never emit the opaque operation identifier."""
    return "sha256:" + base64.urlsafe_b64encode(
        hashlib.sha256(str(value or "").encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")


def _binding_operation_public(item):
    """Return the caller-safe, identifier-free operation projection."""
    return {
        "schema_version": int((item or {}).get("schema_version") or 1),
        "operation_type": "profile_jellyfin_binding_v1",
        "phase": str((item or {}).get("phase") or "created"),
        "source_state": str((item or {}).get("source_state") or "unknown"),
        "inspection_result": str((item or {}).get("inspection_result") or "unknown"),
        "plugin_cas_result": str((item or {}).get("plugin_cas_result") or "not_started"),
        "cloud_persistence_result": str((item or {}).get("cloud_persistence_result") or "not_started"),
        "snapshot_result": str((item or {}).get("snapshot_result") or "not_started"),
        "terminal_result": str((item or {}).get("terminal_result") or "processing"),
        "reconciliation_required": bool((item or {}).get("reconciliation_required", False)),
    }


def _binding_operation_create_or_load(*, operation_id, session, profile_id, user_id):
    """Create one durable exact-key journal before a connector command exists.

    The record contains only one-way authority fingerprints. Exact source
    reads stay in the request path and are never copied into this journal.
    """
    if binding_operations_table is None:
        return None, "binding_operation_unavailable"
    household_id = str(session.get("household_id") or "")
    actor_profile_id = str(session.get("profile_id") or "")
    if not operation_id or not household_id or not actor_profile_id:
        return None, "binding_operation_invalid"
    now = utc_now_iso()
    item = {
        "operation_id": operation_id,
        "schema_version": 1,
        "operation_type": "profile_jellyfin_binding_v1",
        "phase": "created",
        "revision": 0,
        "created_at": now,
        "updated_at": now,
        "expires_at": epoch_now() + BINDING_OPERATION_RETENTION_SECONDS,
        "actor_profile_fingerprint": _binding_operation_fingerprint(actor_profile_id),
        "household_fingerprint": _binding_operation_fingerprint(household_id),
        "operation_trace": _binding_operation_fingerprint(operation_id),
        "target_fingerprint": _binding_operation_fingerprint(profile_id),
        "provider_user_fingerprint": _binding_operation_fingerprint(user_id),
        "source_state": "unknown",
        "inspection_result": "not_started",
        "plugin_cas_result": "not_started",
        "cloud_persistence_result": "not_started",
        "snapshot_result": "not_started",
        "terminal_result": "processing",
        "reconciliation_required": False,
    }
    try:
        binding_operations_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(operation_id)",
        )
        return item, None
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "ConditionalCheckFailedException":
            raise
    existing = binding_operations_table.get_item(
        Key={"operation_id": operation_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(existing, dict) or not (
        hmac.compare_digest(
            str(existing.get("actor_profile_fingerprint") or ""),
            _binding_operation_fingerprint(actor_profile_id),
        )
        and hmac.compare_digest(
            str(existing.get("household_fingerprint") or ""),
            _binding_operation_fingerprint(household_id),
        )
        and hmac.compare_digest(
            str(existing.get("target_fingerprint") or ""),
            _binding_operation_fingerprint(profile_id),
        )
        and hmac.compare_digest(
            str(existing.get("provider_user_fingerprint") or ""),
            _binding_operation_fingerprint(user_id),
        )
    ):
        return None, "binding_operation_conflict"
    return existing, None


def _binding_operation_transition(operation_id, phase, **categories):
    """Advance one exact journal monotonically; duplicate delivery is a read."""
    if binding_operations_table is None:
        return None
    current = binding_operations_table.get_item(
        Key={"operation_id": operation_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(current, dict):
        return None
    current_phase = str(current.get("phase") or "created")
    if BINDING_OPERATION_PHASE_RANK.get(phase, -1) < BINDING_OPERATION_PHASE_RANK.get(current_phase, -1):
        return current
    allowed = {
        "source_state", "inspection_result", "plugin_cas_result",
        "cloud_persistence_result", "snapshot_result", "terminal_result",
        "reconciliation_required",
    }
    values = {":phase": phase, ":updated_at": utc_now_iso(), ":revision": int(current.get("revision") or 0), ":next_revision": int(current.get("revision") or 0) + 1}
    set_parts = ["#phase = :phase", "updated_at = :updated_at", "revision = :next_revision"]
    for key, value in categories.items():
        if key not in allowed:
            continue
        placeholder = ":value_" + key
        values[placeholder] = value
        set_parts.append(f"{key} = {placeholder}")
    try:
        return binding_operations_table.update_item(
            Key={"operation_id": operation_id},
            ConditionExpression="revision = :revision",
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames={"#phase": "phase"},
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        ).get("Attributes")
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "ConditionalCheckFailedException":
            raise
        return binding_operations_table.get_item(
            Key={"operation_id": operation_id}, ConsistentRead=True,
        ).get("Item")


def _binding_operation_source_state(*, inspected, canonical, household_id, manager_profile_id):
    result = inspected.get("result") if isinstance(inspected, dict) else None
    owner_state = str((result or {}).get("owner_state") or "") if isinstance(result, dict) else ""
    source_profile_id = str((result or {}).get("source_profile_id") or "") if isinstance(result, dict) else ""
    if owner_state == "missing":
        # This is a new, explicitly-confirmed binding only when the target is
        # itself completely unbound.  The connector has proved that the exact
        # Jellyfin user has no existing owner, while the canonical record
        # proves the target is an active household profile.  Do not broaden
        # this to a partially populated or active target: those states need
        # durable lineage before any mutation can be authorized.
        target_is_completely_unbound = (
            isinstance(canonical, dict)
            and str(canonical.get("state") or "") == "active"
            and str(canonical.get("jellyfin_binding_state") or "") != "active"
            and not str(canonical.get("jellyfin_connector_id") or "")
            and not _normalized_jellyfin_user_id(canonical.get("jellyfin_user_id"))
        )
        return (
            ("unbound_target_explicit", "missing", "")
            if target_is_completely_unbound
            else ("absent_without_proof", "missing", "")
        )
    if owner_state != "found" or not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", source_profile_id):
        return "ambiguous", "invalid", ""
    target_profile_id = str((canonical or {}).get("profile_id") or "")
    if hmac.compare_digest(source_profile_id, target_profile_id):
        return "target_already_bound", "found", source_profile_id
    source = identity_profiles_table.get_item(
        Key={"profile_id": source_profile_id}, ConsistentRead=True,
    ).get("Item") if identity_profiles_table is not None else None
    if not isinstance(source, dict):
        tombstone = profile_binding_tombstones_table.get_item(
            Key={"profile_id": source_profile_id}, ConsistentRead=True,
        ).get("Item") if profile_binding_tombstones_table is not None else None
        if isinstance(tombstone, dict) and (
            tombstone.get("state") == "deleted"
            and hmac.compare_digest(str(tombstone.get("household_id") or ""), household_id)
        ):
            return "absent_with_valid_tombstone", "found", source_profile_id
        return "absent_without_proof", "found", source_profile_id
    if not hmac.compare_digest(str(source.get("household_id") or ""), household_id):
        return "active_unrelated", "found", source_profile_id
    if source.get("state") == "active":
        return (
            "active_owner" if hmac.compare_digest(source_profile_id, manager_profile_id)
            else "active_same_household_non_target",
            "found",
            source_profile_id,
        )
    return "inactive_or_deleted_with_lineage", "found", source_profile_id


def preflight_profile_jellyfin_binding_v3(event, path):
    """Create a durable, read-only operation before any reassignment mutation."""
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if any(table is None for table in (
        binding_operations_table, identity_profiles_table, home_connectors_table,
        remote_requests_table,
    )):
        return response(503, {"state": "binding_operation_unavailable"})
    profile_id = profile_jellyfin_binding_preflight_path_id(path)
    body = parse_json_body(event) or {}
    operation_id = _binding_operation_id(body.get("operation_id"))
    user_id = _normalized_jellyfin_user_id(body.get("jellyfin_user_id"))
    if not profile_id or not operation_id or not user_id or body.get("explicit_confirmation") is not True:
        return response(400, {"state": "binding_operation_invalid"})
    household_id = str(session.get("household_id") or "")
    manager_profile_id = str(session.get("profile_id") or "")
    canonical = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(canonical, dict)
        and canonical.get("state") == "active"
        and hmac.compare_digest(str(canonical.get("household_id") or ""), household_id)
    ):
        return response(404, {"state": "profile_jellyfin_binding_target_missing"})
    operation, error_state = _binding_operation_create_or_load(
        operation_id=operation_id, session=session, profile_id=profile_id, user_id=user_id,
    )
    if error_state:
        return response(409 if error_state == "binding_operation_conflict" else 503, {"state": error_state})
    if (
        str(operation.get("terminal_result") or "") != "processing"
        or str(operation.get("phase") or "created") != "created"
    ):
        return response(200, {"state": "binding_operation_recorded", "operation": _binding_operation_public(operation)})
    _binding_operation_transition(operation_id, "authorized")
    connectors = _home_connectors_for_profile_access(manager_profile_id)
    _binding_operation_transition(operation_id, "dispatch_pending")
    inspected = _execute_profile_binding_connector_command(
        profile_id, connectors, "jellyfin.inspect_profile_binding_owner",
        {"jellyfin_user_id": user_id, "binding_operation_id": operation_id},
        binding_operation_id=operation_id,
    )
    if inspected.get("state") != "completed":
        updated = _binding_operation_transition(
            operation_id, "failed_retryable",
            inspection_result=str(inspected.get("state") or "command_failed"),
            terminal_result="retryable_connector_failure",
        )
        return response(503, {"state": "binding_operation_recorded", "operation": _binding_operation_public(updated)})
    source_state, inspection_result, _source_id = _binding_operation_source_state(
        inspected=inspected, canonical=canonical, household_id=household_id,
        manager_profile_id=manager_profile_id,
    )
    eligible = source_state in {
        "unbound_target_explicit",
        "inactive_or_deleted_with_lineage",
        "absent_with_valid_tombstone",
        "target_already_bound",
    }
    phase = "mutation_authorized" if eligible else "safely_refused"
    terminal = "preflight_eligible" if eligible else "safely_refused"
    updated = _binding_operation_transition(
        operation_id, phase,
        source_state=source_state,
        inspection_result=inspection_result,
        terminal_result=terminal,
    )
    LOGGER.warning(
        "binding_operation_preflight trace=%s phase=%s source_state=%s",
        _binding_operation_fingerprint(operation_id), phase, source_state,
    )
    return response(200, {"state": "binding_operation_recorded", "operation": _binding_operation_public(updated)})


def profile_jellyfin_binding_preflight_path_id(path):
    match = re.fullmatch(
        r"/v3/identity/profiles/([^/]+)/jellyfin-binding-operations", str(path or ""),
    )
    return match.group(1) if match else ""


def get_profile_jellyfin_binding_operation_v3(event, path):
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    match = re.fullmatch(r"/v3/identity/jellyfin-binding-operations/([^/]+)", str(path or ""))
    operation_id = _binding_operation_id(match.group(1) if match else "")
    if not operation_id or binding_operations_table is None:
        return response(404, {"state": "binding_operation_missing"})
    item = binding_operations_table.get_item(
        Key={"operation_id": operation_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(item, dict) or not (
        hmac.compare_digest(
            str(item.get("actor_profile_fingerprint") or ""),
            _binding_operation_fingerprint(str(session.get("profile_id") or "")),
        )
        and hmac.compare_digest(
            str(item.get("household_fingerprint") or ""),
            _binding_operation_fingerprint(str(session.get("household_id") or "")),
        )
    ):
        return response(404, {"state": "binding_operation_missing"})
    return response(200, {"state": "binding_operation_recorded", "operation": _binding_operation_public(item)})


def save_profile_jellyfin_binding_v3(event, path):
    """Persist one exact household-scoped Cloud-profile/Jellyfin-user edge.

    The caller explicitly selected the provider identity. The server chooses
    the household connector, proves uniqueness with household Query + exact
    reads, and never derives an identity from a name or Owner fallback.
    """
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if any(table is None for table in (
        identity_profiles_table,
        household_memberships_table,
        household_invitations_table,
        home_connectors_table,
    )):
        return response(503, {"state": "profile_jellyfin_binding_unavailable"})
    profile_id = profile_jellyfin_binding_path_id(path)
    body = parse_json_body(event) or {}
    invitation_binding_handle = str(
        body.get("invitation_binding_handle") or ""
    ).strip().lower()
    repair_from_consumed = body.get("repair_from_consumed_invitation") is True
    allow_inactive_reassignment = body.get("allow_inactive_reassignment") is True
    supplied_user_id = body.get("jellyfin_user_id")
    user_id = _normalized_jellyfin_user_id(supplied_user_id)
    supplied_operation_id = body.get("operation_id")
    binding_operation_id = _binding_operation_id(supplied_operation_id)
    if (
        not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
        or body.get("explicit_confirmation") is not True
        or (repair_from_consumed and allow_inactive_reassignment)
        or (repair_from_consumed and supplied_user_id is not None)
        or (not repair_from_consumed and not user_id)
        or (supplied_operation_id is not None and not binding_operation_id)
    ):
        return response(400, {"state": "profile_jellyfin_binding_invalid"})

    household_id = str(session.get("household_id") or "")
    manager_profile_id = str(session.get("profile_id") or "")
    if binding_operation_id:
        if binding_operations_table is None:
            return response(503, {"state": "binding_operation_unavailable"})
        binding_operation = binding_operations_table.get_item(
            Key={"operation_id": binding_operation_id}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(binding_operation, dict) or not (
            hmac.compare_digest(
                str(binding_operation.get("actor_profile_fingerprint") or ""),
                _binding_operation_fingerprint(manager_profile_id),
            )
            and hmac.compare_digest(
                str(binding_operation.get("household_fingerprint") or ""),
                _binding_operation_fingerprint(household_id),
            )
            and hmac.compare_digest(
                str(binding_operation.get("target_fingerprint") or ""),
                _binding_operation_fingerprint(profile_id),
            )
            and hmac.compare_digest(
                str(binding_operation.get("provider_user_fingerprint") or ""),
                _binding_operation_fingerprint(user_id),
            )
        ):
            return response(409, {"state": "binding_operation_conflict"})
        if str(binding_operation.get("source_state") or "") not in {
            "unbound_target_explicit",
            "inactive_or_deleted_with_lineage",
            "absent_with_valid_tombstone",
            "target_already_bound",
        }:
            return response(409, {"state": "binding_operation_not_authorized"})
    connectors = _home_connectors_for_profile_access(manager_profile_id)
    canonical = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(canonical, dict)
        and canonical.get("state") == "active"
        and hmac.compare_digest(
            str(canonical.get("household_id") or ""), household_id,
        )
    ):
        canonical = None

    if repair_from_consumed:
        if canonical is None:
            return response(404, {"state": "profile_jellyfin_binding_target_missing"})
        retained_connector_id = str(canonical.get("jellyfin_connector_id") or "")
        retained_user_id = _normalized_jellyfin_user_id(
            canonical.get("jellyfin_user_id")
        )
        retained_is_active = (
            str(canonical.get("jellyfin_binding_state") or "") == "active"
            and retained_connector_id
            and retained_user_id
            and any(
                isinstance(item, dict)
                and hmac.compare_digest(
                    str(item.get("connector_id") or ""), retained_connector_id,
                )
                for item in connectors
            )
        )
        member_principal_id = str(canonical.get("member_principal_id") or "")
        candidates = []
        for invitation in _household_invitation_records(household_id):
            candidate_user_id = _normalized_jellyfin_user_id(
                (invitation or {}).get("jellyfin_user_id")
            )
            candidate_connector_id = str(
                (invitation or {}).get("jellyfin_connector_id") or ""
            )
            if (
                isinstance(invitation, dict)
                and invitation.get("state") == "consumed"
                and str(invitation.get("profile_id") or "") == profile_id
                and hmac.compare_digest(
                    str(invitation.get("household_id") or ""), household_id,
                )
                and member_principal_id
                and hmac.compare_digest(
                    str(invitation.get("member_principal_id") or ""),
                    member_principal_id,
                )
                and str(invitation.get("jellyfin_binding_state") or "") == "active"
                and candidate_user_id
                and candidate_connector_id
            ):
                candidates.append((invitation, candidate_connector_id, candidate_user_id))
        if len(candidates) > 1:
            return response(409, {
                "state": "profile_jellyfin_binding_source_ambiguous",
            })
        if candidates:
            # A consumed invitation is the stronger historical source. The
            # existing conflict checks below must compare it against any
            # retained canonical edge and refuse disagreement.
            _invitation, connector_id, user_id = candidates[0]
        elif retained_is_active:
            # Parent-managed kids have no consumed invitation or member
            # principal. Their canonical profile is nevertheless the durable
            # server-owned binding record written by provisioning. Accept that
            # exact active edge idempotently instead of asking the plugin to
            # rediscover an identity Cloud already knows.
            connector_id = retained_connector_id
            user_id = retained_user_id
        else:
            recovered = _recover_profile_jellyfin_binding_from_connector(
                profile_id, connectors,
            )
            if recovered.get("state") != "recovered":
                failure_state = str(
                    recovered.get("state")
                    or "profile_jellyfin_binding_source_missing"
                )
                return response(
                    503 if failure_state.endswith(("unavailable", "pending")) else 409,
                    {"state": failure_state},
                )
            connector_id = str(recovered.get("connector_id") or "")
            user_id = _normalized_jellyfin_user_id(
                recovered.get("jellyfin_user_id")
            )
        if not any(
            isinstance(item, dict)
            and hmac.compare_digest(str(item.get("connector_id") or ""), connector_id)
            for item in connectors
        ):
            return response(409, {"state": "profile_jellyfin_connector_missing"})
    elif not allow_inactive_reassignment:
        connector = next((item for item in connectors if isinstance(item, dict)), None)
        connector_id = str((connector or {}).get("connector_id") or "")
        if not connector_id:
            return response(409, {"state": "profile_jellyfin_connector_missing"})
    else:
        connector_id = ""

    matching_invitations = []
    if invitation_binding_handle:
        # A current client supplies the exact primary-key locator returned by
        # invitation creation. Never fall back to the eventually-consistent
        # household GSI when an explicit handle is present.
        if not re.fullmatch(r"[0-9a-f]{64}", invitation_binding_handle):
            return response(409, {
                "state": "profile_jellyfin_binding_invitation_invalid",
            })
        exact_invitation = household_invitations_table.get_item(
            Key={"code_hash": invitation_binding_handle},
            ConsistentRead=True,
        ).get("Item")
        if not (
            isinstance(exact_invitation, dict)
            and exact_invitation.get("state") == "pending"
            and hmac.compare_digest(
                str(exact_invitation.get("household_id") or ""), household_id,
            )
            and hmac.compare_digest(
                str(exact_invitation.get("profile_id") or ""), profile_id,
            )
            and household_invitation_code_expiration(exact_invitation) >= epoch_now()
        ):
            return response(409, {
                "state": "profile_jellyfin_binding_invitation_invalid",
            })
        matching_invitations = [exact_invitation]
    else:
        # Backward compatibility for clients issued before exact invitation
        # handles. This path can observe normal GSI propagation delay and is
        # intentionally not used by current invitation creation.
        matching_invitations = [
            item for item in _household_invitation_records(household_id)
            if isinstance(item, dict)
            and item.get("state") == "pending"
            and str(item.get("profile_id") or "") == profile_id
        ]
    if canonical is None and len(matching_invitations) != 1:
        return response(404 if not matching_invitations else 409, {
            "state": (
                "profile_jellyfin_binding_target_missing"
                if not matching_invitations
                else "profile_jellyfin_binding_target_ambiguous"
            ),
        })
    if canonical is not None and matching_invitations:
        return response(409, {"state": "profile_jellyfin_binding_target_ambiguous"})
    if allow_inactive_reassignment and canonical is None:
        return response(404, {"state": "profile_jellyfin_binding_target_missing"})
    if allow_inactive_reassignment and matching_invitations:
        return response(409, {"state": "profile_jellyfin_binding_target_ambiguous"})

    if canonical is not None and str(canonical.get("jellyfin_binding_state") or "") == "active":
        existing_connector_id = str(canonical.get("jellyfin_connector_id") or "")
        existing_user_id = _normalized_jellyfin_user_id(canonical.get("jellyfin_user_id"))
        if allow_inactive_reassignment and not hmac.compare_digest(existing_user_id, user_id):
            return response(409, {"state": "profile_jellyfin_binding_conflict"})
        if allow_inactive_reassignment:
            # The connector must still prove its exact current owner below.
            connector_id = existing_connector_id
        elif not (
            hmac.compare_digest(existing_connector_id, connector_id)
            and hmac.compare_digest(existing_user_id, user_id)
        ):
            return response(409, {"state": "profile_jellyfin_binding_conflict"})
        else:
            return response(200, {
                "state": (
                    "profile_jellyfin_binding_repaired"
                    if repair_from_consumed
                    else "profile_jellyfin_binding_saved"
                ),
            })

    household_profiles = _household_identity_profile_records(household_id)
    for other in household_profiles:
        other_profile_id = str(other.get("profile_id") or "")
        if other_profile_id == profile_id:
            continue
        if (
            str(other.get("jellyfin_binding_state") or "") == "active"
            and hmac.compare_digest(
                str(other.get("jellyfin_connector_id") or ""), connector_id,
            )
            and hmac.compare_digest(
                _normalized_jellyfin_user_id(other.get("jellyfin_user_id")), user_id,
            )
        ):
            return response(409, {"state": "jellyfin_identity_already_bound"})
    household_invitations = _household_invitation_records(household_id)
    for invitation in household_invitations:
        if (
            str(invitation.get("profile_id") or "") != profile_id
            and invitation.get("state") in (
                {"pending"}
                if allow_inactive_reassignment
                else {"pending", "consumed"}
            )
            and str(invitation.get("jellyfin_binding_state") or "") == "active"
            and hmac.compare_digest(
                str(invitation.get("jellyfin_connector_id") or ""), connector_id,
            )
            and hmac.compare_digest(
                _normalized_jellyfin_user_id(invitation.get("jellyfin_user_id")), user_id,
            )
        ):
            return response(409, {"state": "jellyfin_identity_already_bound"})

    if allow_inactive_reassignment:
        inspection_kwargs = (
            {"binding_operation_id": binding_operation_id}
            if binding_operation_id else {}
        )
        inspected = _execute_profile_binding_connector_command(
            profile_id,
            connectors,
            "jellyfin.inspect_profile_binding_owner",
            {"jellyfin_user_id": user_id, **({"binding_operation_id": binding_operation_id} if binding_operation_id else {})},
            **inspection_kwargs,
        )
        if inspected.get("state") != "completed":
            failure_state = str(
                inspected.get("state")
                or "profile_jellyfin_binding_command_failed"
            )
            return response(
                503 if failure_state.endswith(("unavailable", "pending", "missing")) else 409,
                {"state": failure_state},
            )
        connector_id = str(inspected.get("connector_id") or "")
        inspection_result = inspected.get("result")
        owner_state = str(
            (inspection_result or {}).get("owner_state")
            if isinstance(inspection_result, dict) else ""
        )
        source_profile_id = str(
            (inspection_result or {}).get("source_profile_id") or ""
            if isinstance(inspection_result, dict) else ""
        )
        if owner_state not in {"found", "missing"}:
            return response(409, {
                "state": "profile_jellyfin_binding_owner_invalid",
            })
        if owner_state == "found" and not re.fullmatch(
            r"profile_[A-Za-z0-9_-]{16,128}", source_profile_id,
        ):
            return response(409, {
                "state": "profile_jellyfin_binding_owner_invalid",
            })

        if source_profile_id and source_profile_id != profile_id:
            source_profile = identity_profiles_table.get_item(
                Key={"profile_id": source_profile_id}, ConsistentRead=True,
            ).get("Item")
            if not isinstance(source_profile, dict):
                if not (
                    binding_operation_id
                    and str(binding_operation.get("source_state") or "")
                    == "absent_with_valid_tombstone"
                ):
                    return response(409, {
                        "state": "profile_jellyfin_binding_owner_unverifiable",
                    })
            else:
                if source_profile.get("state") == "active":
                    return response(409, {
                        "state": "jellyfin_identity_already_bound",
                    })
                if not hmac.compare_digest(
                    str(source_profile.get("household_id") or ""),
                    household_id,
                ):
                    return response(409, {
                        "state": "profile_jellyfin_binding_owner_unrelated",
                    })

        reassignment_kwargs = (
            {"binding_operation_id": binding_operation_id}
            if binding_operation_id else {}
        )
        reassigned = _execute_profile_binding_connector_command(
            profile_id,
            connectors,
            "jellyfin.reassign_stale_profile_binding",
            {
                "jellyfin_user_id": user_id,
                "expected_source_profile_id": source_profile_id,
                "target_profile_id": profile_id,
                **({"binding_operation_id": binding_operation_id} if binding_operation_id else {}),
            },
            **reassignment_kwargs,
        )
        reassignment_result = reassigned.get("result")
        if not (
            reassigned.get("state") == "completed"
            and hmac.compare_digest(
                str(reassigned.get("connector_id") or ""), connector_id,
            )
            and isinstance(reassignment_result, dict)
            and reassignment_result.get("state") in {"reassigned", "already_bound"}
        ):
            failure_state = str(
                reassigned.get("state")
                or "profile_jellyfin_binding_reassignment_failed"
            )
            return response(
                503 if failure_state.endswith(("unavailable", "pending", "missing")) else 409,
                {"state": failure_state},
            )
        if binding_operation_id:
            _binding_operation_transition(
                binding_operation_id, "plugin_cas_committed",
                plugin_cas_result=str(reassignment_result.get("state") or "unknown"),
            )

    values = {
        ":household_id": household_id,
        ":connector_id": connector_id,
        ":user_id": user_id,
        ":binding_state": "active",
        ":updated_at": utc_now_iso(),
    }
    update = (
        "SET jellyfin_connector_id = :connector_id, "
        "jellyfin_user_id = :user_id, "
        "jellyfin_binding_state = :binding_state, "
        "jellyfin_binding_updated_at = :updated_at"
    )
    try:
        if canonical is not None:
            condition = "household_id = :household_id AND #state = :active"
            if repair_from_consumed:
                condition += " AND member_principal_id = :member_principal_id"
            identity_profiles_table.update_item(
                Key={"profile_id": profile_id},
                UpdateExpression=update,
                ConditionExpression=condition,
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    **values,
                    ":active": "active",
                    **(
                        {":member_principal_id": str(canonical.get("member_principal_id") or "")}
                        if repair_from_consumed else {}
                    ),
                },
            )
        else:
            invitation = matching_invitations[0]
            household_invitations_table.update_item(
                Key={"code_hash": str(invitation.get("code_hash") or "")},
                UpdateExpression=update,
                ConditionExpression=(
                    "household_id = :household_id AND profile_id = :profile_id "
                    "AND #state = :pending"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    **values, ":profile_id": profile_id, ":pending": "pending",
                },
            )
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "ConditionalCheckFailedException":
            return response(409, {"state": "profile_jellyfin_binding_conflict"})
        raise
    if binding_operation_id:
        _binding_operation_transition(
            binding_operation_id, "cloud_persisted",
            cloud_persistence_result="persisted",
            snapshot_result="pending",
            terminal_result="cloud_persisted",
        )
        snapshot = _publish_profile_jellyfin_snapshot(
            profile_id, connectors, binding_operation_id=binding_operation_id,
        )
        if snapshot.get("state") == "snapshot_published":
            _binding_operation_transition(
                binding_operation_id, "completed",
                snapshot_result="published", terminal_result="completed",
            )
        else:
            _binding_operation_transition(
                binding_operation_id, "reconciliation_required",
                snapshot_result=str(snapshot.get("state") or "snapshot_failed"),
                terminal_result="snapshot_reconciliation_required",
                reconciliation_required=True,
            )
            return response(202, {
                "state": "profile_jellyfin_binding_reconciliation_required",
                "operation": _binding_operation_public(
                    binding_operations_table.get_item(
                        Key={"operation_id": binding_operation_id}, ConsistentRead=True,
                    ).get("Item") or {}
                ),
            })
    return response(200, {
        "state": (
            "profile_jellyfin_binding_reassigned"
            if allow_inactive_reassignment
            else (
                "profile_jellyfin_binding_repaired"
                if repair_from_consumed
                else "profile_jellyfin_binding_saved"
            )
        ),
    })


def save_profile_seerr_binding_v3(event, path):
    """Persist a plugin-proven Seerr edge for an already-bound exact profile.

    Seerr discovery is deliberately not performed here. The Owner authorizes
    the write, the paired plugin returns one Seerr account for one immutable
    Jellyfin user, and this endpoint persists only that exact tuple.
    """
    if any(table is None for table in (identity_profiles_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    profile_id = profile_seerr_binding_path_id(path)
    body = parse_json_body(event)
    if not (
        re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
        and isinstance(body, dict)
        and body.get("explicit_confirmation") is True
    ):
        return _profile_switch_failure(event, session, "profile_seerr_binding_invalid", profile_id=profile_id)
    if str((context.get("household") or {}).get("role") or "").lower() != CanonicalRole.OWNER.value:
        return _profile_switch_failure(event, session, "profile_seerr_binding_owner_required", profile_id=profile_id)
    supplied_jellyfin_user_id = _normalized_jellyfin_user_id(body.get("jellyfin_user_id"))
    seerr_user_id = _normalized_seerr_user_id(body.get("seerr_user_id"))
    invitation_binding_handle = str(
        body.get("invitation_binding_handle") or ""
    ).strip().lower()
    if not supplied_jellyfin_user_id or not seerr_user_id:
        return _profile_switch_failure(event, session, "profile_seerr_binding_invalid", profile_id=profile_id)
    household_id = str((context.get("household") or {}).get("household_id") or "")
    try:
        canonical = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if not (
            isinstance(canonical, dict)
            and canonical.get("state") == "active"
            and hmac.compare_digest(
                str(canonical.get("household_id") or ""), household_id,
            )
        ):
            canonical = None

        pending_invitation = None
        if invitation_binding_handle:
            if (
                household_invitations_table is None
                or not re.fullmatch(r"[0-9a-f]{64}", invitation_binding_handle)
            ):
                raise AccountFoundationError("profile_seerr_binding_invitation_invalid")
            pending_invitation = household_invitations_table.get_item(
                Key={"code_hash": invitation_binding_handle}, ConsistentRead=True,
            ).get("Item")
            if not (
                isinstance(pending_invitation, dict)
                and pending_invitation.get("state") == "pending"
                and hmac.compare_digest(
                    str(pending_invitation.get("household_id") or ""), household_id,
                )
                and hmac.compare_digest(
                    str(pending_invitation.get("profile_id") or ""), profile_id,
                )
                and household_invitation_code_expiration(pending_invitation) >= epoch_now()
            ):
                raise AccountFoundationError("profile_seerr_binding_invitation_invalid")
            if canonical is not None:
                raise AccountFoundationError("profile_seerr_binding_conflict")
        elif canonical is None:
            raise AccountFoundationError("profile_switch_target_not_authorized")

        binding_target = pending_invitation or canonical
        bound_jellyfin_user_id = _normalized_jellyfin_user_id(
            binding_target.get("jellyfin_user_id")
        )
        connector_id = str(binding_target.get("jellyfin_connector_id") or "")
        if not (
            str(binding_target.get("jellyfin_binding_state") or "") == "active"
            and connector_id
            and hmac.compare_digest(bound_jellyfin_user_id, supplied_jellyfin_user_id)
        ):
            raise AccountFoundationError("profile_seerr_binding_jellyfin_mismatch")
        existing_state = str(binding_target.get("seerr_binding_state") or "")
        existing_connector_id = str(binding_target.get("seerr_connector_id") or "")
        existing_jellyfin_user_id = _normalized_jellyfin_user_id(
            binding_target.get("seerr_jellyfin_user_id")
        )
        existing_seerr_user_id = _normalized_seerr_user_id(
            binding_target.get("seerr_user_id")
        )
        if existing_state == "active" and not (
            hmac.compare_digest(existing_connector_id, connector_id)
            and hmac.compare_digest(existing_jellyfin_user_id, supplied_jellyfin_user_id)
            and hmac.compare_digest(existing_seerr_user_id, seerr_user_id)
        ):
            raise AccountFoundationError("profile_seerr_binding_conflict")
        if existing_state == "active":
            return response(200, {"state": "profile_seerr_binding_saved"})
        values = {
            ":household_id": household_id,
            ":connector_id": connector_id,
            ":jellyfin_user_id": supplied_jellyfin_user_id,
            ":seerr_user_id": seerr_user_id,
            ":binding_state": "active",
            ":updated_at": utc_now_iso(),
            ":request_access_enabled": True,
        }
        update = (
            "SET seerr_connector_id = :connector_id, "
            "seerr_jellyfin_user_id = :jellyfin_user_id, "
            "seerr_user_id = :seerr_user_id, "
            "seerr_binding_state = :binding_state, "
            "request_access_enabled = :request_access_enabled, "
            "seerr_binding_updated_at = :updated_at"
        )
        if pending_invitation is not None:
            household_invitations_table.update_item(
                Key={"code_hash": invitation_binding_handle},
                UpdateExpression=update,
                ConditionExpression=(
                    "#state = :pending AND household_id = :household_id "
                    "AND profile_id = :profile_id "
                    "AND code_expires_at >= :now "
                    "AND jellyfin_binding_state = :binding_state "
                    "AND jellyfin_connector_id = :connector_id "
                    "AND jellyfin_user_id = :jellyfin_user_id"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    **values, ":pending": "pending", ":profile_id": profile_id,
                    ":now": epoch_now(),
                },
            )
        else:
            identity_profiles_table.update_item(
                Key={"profile_id": profile_id},
                UpdateExpression=update,
                ConditionExpression=(
                    "#state = :active AND household_id = :household_id "
                    "AND jellyfin_binding_state = :binding_state "
                    "AND jellyfin_connector_id = :connector_id "
                    "AND jellyfin_user_id = :jellyfin_user_id"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={**values, ":active": "active"},
            )
        commit_security_audit(_profile_binding_audit(
            event, session, "profile_seerr_binding_saved", "success", target_id=profile_id,
        ))
    except AccountFoundationError as error:
        return _profile_switch_failure(event, session, error.reason, profile_id=profile_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError:
        return _profile_switch_failure(event, session, "profile_seerr_binding_conflict", profile_id=profile_id)
    return response(200, {"state": "profile_seerr_binding_saved"})


def _set_pending_provider_cleanup_state(
    binding_handle,
    *,
    profile_id,
    jellyfin_user_id,
    seerr_user_id,
    state,
    seerr_binding_state=None,
    jellyfin_binding_state=None,
):
    """CAS one exact pending cleanup receipt without discarding its IDs."""
    update = "SET provider_cleanup_state = :cleanup_state, provider_cleanup_updated_at = :updated_at"
    values = {
        ":cleanup_state": state,
        ":updated_at": utc_now_iso(),
        ":profile_id": profile_id,
        ":jellyfin_user_id": jellyfin_user_id,
        ":seerr_user_id": seerr_user_id,
    }
    if seerr_binding_state is not None:
        update += ", seerr_binding_state = :seerr_binding_state"
        values[":seerr_binding_state"] = seerr_binding_state
    if jellyfin_binding_state is not None:
        update += ", jellyfin_binding_state = :jellyfin_binding_state"
        values[":jellyfin_binding_state"] = jellyfin_binding_state
    household_invitations_table.update_item(
        Key={"code_hash": binding_handle},
        UpdateExpression=update,
        ConditionExpression=(
            "#state = :pending AND profile_id = :profile_id "
            "AND jellyfin_user_id = :jellyfin_user_id "
            "AND seerr_user_id = :seerr_user_id"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={**values, ":pending": "pending"},
    )


def cleanup_pending_profile_providers_v3(event, path):
    """Durably delete a failed invitation's exact Seerr then Jellyfin edge.

    The invitation is the transaction ledger.  IDs remain on it through every
    retry; no timeout, failed connector response, or expired invitation can
    silently turn a confirmed provider account into an orphan.
    """
    required = (
        household_invitations_table, identity_profiles_table,
        security_audit_table, remote_requests_table,
    )
    if any(table is None for table in required):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    profile_id = profile_pending_provider_cleanup_path_id(path)
    body = parse_json_body(event)
    if not (
        re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
        and isinstance(body, dict)
        and body.get("explicit_confirmation") is True
        and body.get("created_by_this_attempt") is True
    ):
        return _profile_switch_failure(
            event, session, "pending_provider_cleanup_invalid", profile_id=profile_id,
        )
    if str((context.get("household") or {}).get("role") or "").lower() != CanonicalRole.OWNER.value:
        return _profile_switch_failure(
            event, session, "pending_provider_cleanup_owner_required", profile_id=profile_id,
        )

    household_id = str((context.get("household") or {}).get("household_id") or "")
    owner_profile_id = str(session.get("profile_id") or "")
    binding_handle = str(body.get("invitation_binding_handle") or "").strip().lower()
    jellyfin_user_id = _normalized_jellyfin_user_id(body.get("jellyfin_user_id"))
    seerr_user_id = _normalized_seerr_user_id(body.get("seerr_user_id"))
    if not (
        re.fullmatch(r"[0-9a-f]{64}", binding_handle)
        and jellyfin_user_id
        and seerr_user_id
    ):
        return _profile_switch_failure(
            event, session, "pending_provider_cleanup_invalid", profile_id=profile_id,
        )

    try:
        invitation = household_invitations_table.get_item(
            Key={"code_hash": binding_handle}, ConsistentRead=True,
        ).get("Item")
        cleanup_state = str((invitation or {}).get("provider_cleanup_state") or "")
        retry_states = {
            "seerr_pending", "seerr_retryable", "jellyfin_pending",
            "jellyfin_retryable", "complete",
        }
        invitation_is_current = (
            isinstance(invitation, dict)
            and invitation.get("state") == "pending"
            and hmac.compare_digest(str(invitation.get("household_id") or ""), household_id)
            and hmac.compare_digest(str(invitation.get("profile_id") or ""), profile_id)
            and (
                household_invitation_code_expiration(invitation) >= epoch_now()
                or cleanup_state in retry_states
            )
        )
        if not invitation_is_current:
            raise AccountFoundationError("pending_provider_cleanup_invitation_invalid")

        receipt_matches = (
            hmac.compare_digest(
                _normalized_jellyfin_user_id(invitation.get("jellyfin_user_id")),
                jellyfin_user_id,
            )
            and hmac.compare_digest(
                _normalized_jellyfin_user_id(invitation.get("seerr_jellyfin_user_id")),
                jellyfin_user_id,
            )
            and hmac.compare_digest(
                _normalized_seerr_user_id(invitation.get("seerr_user_id")),
                seerr_user_id,
            )
            and str(invitation.get("jellyfin_connector_id") or "")
            and hmac.compare_digest(
                str(invitation.get("jellyfin_connector_id") or ""),
                str(invitation.get("seerr_connector_id") or ""),
            )
        )
        if not receipt_matches:
            raise AccountFoundationError("pending_provider_cleanup_identity_mismatch")

        if cleanup_state == "complete":
            return response(200, {
                "state": "pending_provider_cleanup_complete",
                "jellyfin_user_id": jellyfin_user_id,
                "seerr_user_id": int(seerr_user_id),
            })
        if not cleanup_state:
            if not (
                invitation.get("jellyfin_binding_state") == "active"
                and invitation.get("seerr_binding_state") == "active"
            ):
                raise AccountFoundationError("pending_provider_cleanup_binding_invalid")
            _set_pending_provider_cleanup_state(
                binding_handle,
                profile_id=profile_id,
                jellyfin_user_id=jellyfin_user_id,
                seerr_user_id=seerr_user_id,
                state="seerr_pending",
            )
            cleanup_state = "seerr_pending"

        connectors = _home_connectors_for_profile_access(owner_profile_id)
        connector_id = str(invitation.get("jellyfin_connector_id") or "")
        exact_connectors = [
            item for item in connectors
            if isinstance(item, dict)
            and hmac.compare_digest(str(item.get("connector_id") or ""), connector_id)
        ]
        if len(exact_connectors) != 1:
            _set_pending_provider_cleanup_state(
                binding_handle, profile_id=profile_id,
                jellyfin_user_id=jellyfin_user_id, seerr_user_id=seerr_user_id,
                state=("jellyfin_retryable" if cleanup_state.startswith("jellyfin") else "seerr_retryable"),
            )
            return response(202, {"state": "pending_provider_cleanup_retryable"})

        if cleanup_state in {"seerr_pending", "seerr_retryable"}:
            outcome = _execute_profile_binding_connector_command(
                profile_id,
                exact_connectors,
                "seerr.delete_exact_bound_user",
                {
                    "jellyfin_user_id": jellyfin_user_id,
                    "seerr_user_id": int(seerr_user_id),
                },
                timeout_seconds=8.0,
            )
            result = outcome.get("result") if isinstance(outcome, dict) else None
            confirmed = (
                outcome.get("state") == "completed"
                and isinstance(result, dict)
                and result.get("absence_confirmed") is True
                and str(result.get("state") or "") in {"deleted", "absent"}
                and hmac.compare_digest(
                    _normalized_jellyfin_user_id(result.get("jellyfin_user_id")), jellyfin_user_id,
                )
                and hmac.compare_digest(
                    _normalized_seerr_user_id(result.get("seerr_user_id")), seerr_user_id,
                )
            )
            if not confirmed:
                _set_pending_provider_cleanup_state(
                    binding_handle, profile_id=profile_id,
                    jellyfin_user_id=jellyfin_user_id, seerr_user_id=seerr_user_id,
                    state="seerr_retryable",
                )
                return response(202, {"state": "pending_provider_cleanup_retryable"})
            _set_pending_provider_cleanup_state(
                binding_handle, profile_id=profile_id,
                jellyfin_user_id=jellyfin_user_id, seerr_user_id=seerr_user_id,
                state="jellyfin_pending", seerr_binding_state="absent",
            )

        outcome = _execute_profile_binding_connector_command(
            profile_id,
            exact_connectors,
            "jellyfin.delete_pending_exact_user",
            {"jellyfin_user_id": jellyfin_user_id},
            timeout_seconds=8.0,
        )
        result = outcome.get("result") if isinstance(outcome, dict) else None
        confirmed = (
            outcome.get("state") == "completed"
            and isinstance(result, dict)
            and result.get("absence_confirmed") is True
            and str(result.get("state") or "") in {"deleted", "absent"}
            and hmac.compare_digest(
                _normalized_jellyfin_user_id(result.get("jellyfin_user_id")), jellyfin_user_id,
            )
        )
        if not confirmed:
            _set_pending_provider_cleanup_state(
                binding_handle, profile_id=profile_id,
                jellyfin_user_id=jellyfin_user_id, seerr_user_id=seerr_user_id,
                state="jellyfin_retryable",
            )
            return response(202, {"state": "pending_provider_cleanup_retryable"})
        _set_pending_provider_cleanup_state(
            binding_handle, profile_id=profile_id,
            jellyfin_user_id=jellyfin_user_id, seerr_user_id=seerr_user_id,
            state="complete", jellyfin_binding_state="absent",
        )
        commit_security_audit(_profile_binding_audit(
            event, session, "pending_provider_cleanup_complete", "success",
            target_id=profile_id,
        ))
        return response(200, {
            "state": "pending_provider_cleanup_complete",
            "jellyfin_user_id": jellyfin_user_id,
            "seerr_user_id": int(seerr_user_id),
        })
    except AccountFoundationError as error:
        return _profile_switch_failure(event, session, error.reason, profile_id=profile_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError:
        return _profile_switch_failure(
            event, session, "pending_provider_cleanup_conflict", profile_id=profile_id,
        )


def repair_exact_seerr_orphan_v3(event):
    """Owner-confirmed removal of one exact Seerr pair after Jellyfin absence."""
    if security_audit_table is None or remote_requests_table is None:
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    if str((context.get("household") or {}).get("role") or "").lower() != CanonicalRole.OWNER.value:
        return _profile_switch_failure(event, session, "seerr_orphan_repair_owner_required")
    body = parse_json_body(event)
    jellyfin_user_id = _normalized_jellyfin_user_id((body or {}).get("jellyfin_user_id"))
    seerr_user_id = _normalized_seerr_user_id((body or {}).get("seerr_user_id"))
    if not (
        isinstance(body, dict)
        and body.get("explicit_confirmation") is True
        and jellyfin_user_id
        and seerr_user_id
    ):
        return _profile_switch_failure(event, session, "seerr_orphan_repair_invalid")
    owner_profile_id = str(session.get("profile_id") or "")
    connectors = _home_connectors_for_profile_access(owner_profile_id)
    outcome = _execute_profile_binding_connector_command(
        owner_profile_id,
        connectors,
        "seerr.delete_orphaned_jellyfin_user",
        {
            "jellyfin_user_id": jellyfin_user_id,
            "seerr_user_id": int(seerr_user_id),
        },
        timeout_seconds=8.0,
    )
    result = outcome.get("result") if isinstance(outcome, dict) else None
    confirmed = (
        outcome.get("state") == "completed"
        and isinstance(result, dict)
        and result.get("absence_confirmed") is True
        and result.get("jellyfin_absence_confirmed") is True
        and str(result.get("state") or "") in {"deleted", "absent"}
        and hmac.compare_digest(
            _normalized_jellyfin_user_id(result.get("jellyfin_user_id")), jellyfin_user_id,
        )
        and hmac.compare_digest(
            _normalized_seerr_user_id(result.get("seerr_user_id")), seerr_user_id,
        )
    )
    if not confirmed:
        return _profile_switch_failure(event, session, "seerr_orphan_repair_unconfirmed")
    try:
        commit_security_audit(_profile_binding_audit(
            event, session, "seerr_orphan_repair_complete", "success",
            target_id=owner_profile_id,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(200, {
        "state": "seerr_orphan_repair_complete",
        "jellyfin_user_id": jellyfin_user_id,
        "seerr_user_id": int(seerr_user_id),
    })


def create_profile_binding_v3(event, path, *, verified_session=None, retry_on_conflict=True):
    """Grant one explicit view/switch binding to an active household member."""
    if any(table is None for table in (
        profiles_table, profile_bindings_table, accounts_table, household_memberships_table, security_audit_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = verified_session if verified_session is not None else authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    if "household.manage" not in set((context.get("household") or {}).get("capabilities") or []):
        return _profile_binding_failure(event, session, "profile_binding_not_authorized")
    profile_id = profile_binding_path_id(path)
    body = parse_json_body(event)
    if not profile_id or not isinstance(body, dict):
        return _profile_binding_failure(event, session, "invalid_profile_binding_request")
    caller_account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    target_account_id = str(body.get("target_account_id") or "").strip()
    requested_access = str(body.get("access_level") or "").strip().lower()
    if not target_account_id or target_account_id == caller_account_id:
        return _profile_binding_failure(event, session, "profile_binding_not_authorized", target_id=profile_id)
    if requested_access not in {"view", "switch"}:
        return _profile_binding_failure(event, session, "profile_access_level_not_permitted", target_id=profile_id)
    try:
        profile = profiles_table.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item")
        validate_profile(profile, household_id=household_id)
        target_account = accounts_table.get_item(Key={"account_id": target_account_id}, ConsistentRead=True).get("Item")
        target_membership = household_memberships_table.get_item(Key={
            "household_id": household_id,
            "membership_id": household_membership_id(target_account_id, household_id),
        }, ConsistentRead=True).get("Item")
        if (
            not isinstance(target_account, dict)
            or target_account.get("entity_type") != "Account"
            or target_account.get("status") != "active"
            or not isinstance(target_membership, dict)
            or target_membership.get("entity_type") != "HouseholdMembership"
            or target_membership.get("status") != "active"
            or str(target_membership.get("account_id") or "") != target_account_id
            or str(target_membership.get("household_id") or "") != household_id
        ):
            return _profile_binding_failure(event, session, "target_account_not_active_member", target_id=profile_id)
        try:
            canonical_role(target_membership.get("canonical_role"))
        except AccountFoundationError:
            return _profile_binding_failure(event, session, "manual_review_required", target_id=profile_id)
        existing = profile_bindings_table.get_item(
            Key={"account_id": target_account_id, "profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if isinstance(existing, dict):
            if existing.get("status") == "active":
                return response(200, {"state": "profile_binding_already_exists"})
            return _profile_binding_failure(event, session, "profile_binding_not_reactivated", target_id=profile_id)
        binding = build_profile_binding(
            account_id=target_account_id, profile=profile, access_level=requested_access,
            granted_by_account_id=caller_account_id, now_iso=utc_now_iso(), now_epoch=epoch_now(),
            provenance="explicit-household-manager-grant-v1",
        )
        audit = _profile_binding_audit(
            event, session, "profile_binding_created", "success", target_id=profile_id,
        )
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Put": {
                "TableName": PROFILE_BINDINGS_TABLE, "Item": binding,
                "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(profile_id)",
            }},
            {"Put": {
                "TableName": SECURITY_AUDIT_TABLE, "Item": audit,
                "ConditionExpression": "attribute_not_exists(event_id)",
            }},
        ])
    except AccountFoundationError as error:
        return _profile_binding_failure(event, session, error.reason, target_id=profile_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "TransactionCanceledException":
            raise
        if retry_on_conflict:
            return create_profile_binding_v3(event, path, verified_session=session, retry_on_conflict=False)
        return _profile_binding_failure(event, session, "profile_binding_conflict", target_id=profile_id)
    return response(200, {"state": "profile_binding_created"})


def _switch_pin_material(pin):
    """Create a versioned, salted verifier; the PIN itself never persists."""
    value = str(pin or "")
    if not (4 <= len(value) <= 8 and value.isascii() and value.isdigit()):
        raise AccountFoundationError("invalid_profile_switch_pin")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return {
        "version": 1,
        "algorithm": "scrypt-n16384-r8-p1-dk32",
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
        "updated_at": utc_now_iso(),
        "updated_at_epoch": epoch_now(),
    }


def _verify_switch_pin(material, pin):
    if not _profile_switch_pin_configured({"profile_switch_pin": material}):
        return False
    try:
        salt = base64.b64decode(str(material["salt"]), validate=True)
        expected = base64.b64decode(str(material["hash"]), validate=True)
        actual = hashlib.scrypt(
            str(pin or "").encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def _exact_identity_profile(profile_id, *, household_id):
    profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(profile, dict)
        or profile.get("state") != "active"
        or str(profile.get("profile_id") or "") != profile_id
        or str(profile.get("household_id") or "") != household_id
    ):
        raise AccountFoundationError("profile_switch_target_not_authorized")
    return profile


def _profile_switch_failure(event, session, state, *, profile_id=""):
    try:
        commit_security_audit(_profile_binding_audit(
            event, session, "profile_switch_security_rejected", "denied",
            target_id=profile_id, reason_code=state,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    status = 403 if state in {
        "profile_switch_not_authorized", "profile_switch_target_not_authorized",
        "profile_switch_pin_configuration_not_authorized",
        "watching_targets_owner_required",
    } else 409
    return response(status, {"state": state})


def set_profile_switch_pin_v3(event, path):
    """Let only a signed-in profile set or change its own profile PIN."""
    if any(table is None for table in (identity_profiles_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    profile_id = profile_switch_pin_path_id(path)
    body = parse_json_body(event)
    if not profile_id or not isinstance(body, dict):
        return _profile_switch_failure(event, session, "invalid_profile_switch_pin_request", profile_id=profile_id)
    account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    if profile_id != str(session.get("profile_id") or ""):
        return _profile_switch_failure(event, session, "profile_switch_pin_configuration_not_authorized", profile_id=profile_id)
    try:
        profile = _exact_identity_profile(profile_id, household_id=household_id)
        if str(profile.get("account_id") or "") != account_id:
            return _profile_switch_failure(event, session, "profile_switch_pin_configuration_not_authorized", profile_id=profile_id)
        material = _switch_pin_material(body.get("pin"))
        identity_profiles_table.update_item(
            Key={"profile_id": profile_id},
            UpdateExpression="SET profile_switch_pin = :pin, updated_at = :updated, updated_at_epoch = :epoch",
            ConditionExpression="#state = :active AND account_id = :account AND household_id = :household",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":pin": material, ":updated": material["updated_at"], ":epoch": material["updated_at_epoch"],
                ":active": "active", ":account": account_id, ":household": household_id,
            },
        )
        commit_security_audit(_profile_binding_audit(
            event, session, "profile_switch_pin_set", "success", target_id=profile_id,
        ))
    except AccountFoundationError as error:
        return _profile_switch_failure(event, session, error.reason, profile_id=profile_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError:
        return _profile_switch_failure(event, session, "profile_switch_pin_conflict", profile_id=profile_id)
    return response(200, {"state": "profile_switch_pin_configured", "pin_configured": True})


def verify_profile_switch_pin_v3(event, path):
    """Verify a target's PIN only after exact server-authorized switch access."""
    if any(table is None for table in (identity_profiles_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    profile_id = profile_switch_pin_verification_path_id(path)
    body = parse_json_body(event)
    if not profile_id or not isinstance(body, dict):
        return _profile_switch_failure(event, session, "invalid_profile_switch_pin_request", profile_id=profile_id)
    allowed = {
        str(item.get("profile_id") or "")
        for item in (context.get("profile_access") or [])
        if item.get("status") == "active" and item.get("access_level") in {"switch", "manage"}
    }
    if profile_id not in allowed:
        return _profile_switch_failure(event, session, "profile_switch_target_not_authorized", profile_id=profile_id)
    household_id = str((context.get("household") or {}).get("household_id") or "")
    try:
        profile = _exact_identity_profile(profile_id, household_id=household_id)
    except AccountFoundationError as error:
        return _profile_switch_failure(event, session, error.reason, profile_id=profile_id)
    if _profile_switch_protection(profile) == "owner_direct":
        return response(200, {"state": "profile_switch_owner_direct", "verified": True})
    if not _profile_switch_pin_configured(profile):
        # A missing PIN intentionally leaves an explicitly granted profile
        # accessible. The profile owner is invited to add protection later.
        return response(200, {"state": "profile_switch_pin_not_configured", "verified": True})
    if not _verify_switch_pin(profile.get("profile_switch_pin"), body.get("pin")):
        return _profile_switch_failure(event, session, "profile_switch_pin_invalid", profile_id=profile_id)
    try:
        commit_security_audit(_profile_binding_audit(
            event, session, "profile_switch_pin_verified", "success", target_id=profile_id,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(200, {"state": "profile_switch_pin_verified", "verified": True})


def update_profile_switch_targets_v3(event, path):
    """Update explicit switch grants without changing a profile's identity.

    Owners and household Admins may maintain member access. An Admin cannot
    alter the Owner's grants, preserving the Owner's final household authority.
    """
    if any(table is None for table in (identity_profiles_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    profile_id = profile_switch_targets_path_id(path)
    body = parse_json_body(event)
    if not profile_id or not isinstance(body, dict) or not isinstance(body.get("profile_ids"), list):
        return _profile_switch_failure(event, session, "invalid_profile_switch_targets_request", profile_id=profile_id)
    capabilities = set((context.get("household") or {}).get("capabilities") or [])
    if "profile.switch_grant" not in capabilities:
        return _profile_switch_failure(event, session, "profile_switch_not_authorized", profile_id=profile_id)
    household_id = str((context.get("household") or {}).get("household_id") or "")
    source_role = str((context.get("household") or {}).get("role") or "").lower()
    requested = body.get("profile_ids")
    if len(requested) > 32:
        return _profile_switch_failure(event, session, "invalid_profile_switch_targets_request", profile_id=profile_id)
    try:
        source = _exact_identity_profile(profile_id, household_id=household_id)
        if (
            source_role != CanonicalRole.OWNER.value
            and str(source.get("household_access_role") or "").lower() == HouseholdAccessRole.OWNER.value
        ):
            return _profile_switch_failure(event, session, "profile_switch_not_authorized", profile_id=profile_id)
        profile_ids = []
        for candidate in requested:
            target_id = str(candidate or "").strip()
            if not target_id or target_id == profile_id or target_id in profile_ids:
                raise AccountFoundationError("invalid_profile_switch_targets_request")
            _exact_identity_profile(target_id, household_id=household_id)
            profile_ids.append(target_id)
        now = utc_now_iso()
        identity_profiles_table.update_item(
            Key={"profile_id": profile_id},
            UpdateExpression="SET switch_profile_ids = :targets, updated_at = :updated, updated_at_epoch = :epoch",
            ConditionExpression="#state = :active AND household_id = :household",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":targets": profile_ids, ":updated": now, ":epoch": epoch_now(),
                ":active": "active", ":household": household_id,
            },
        )
        commit_security_audit(_profile_binding_audit(
            event, session, "profile_switch_grants_updated", "success", target_id=profile_id,
        ))
    except AccountFoundationError as error:
        return _profile_switch_failure(event, session, error.reason, profile_id=profile_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError:
        return _profile_switch_failure(event, session, "profile_switch_targets_conflict", profile_id=profile_id)
    return response(200, {"state": "profile_switch_targets_updated", "profile_ids": profile_ids})


def update_profile_watching_targets_v3(event, path):
    """Owner-only update for one profile's explicit Who's Watching audience."""
    if any(table is None for table in (identity_profiles_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    profile_id = profile_watching_targets_path_id(path)
    body = parse_json_body(event)
    if not profile_id or not isinstance(body, dict) or not isinstance(body.get("profile_ids"), list):
        return _profile_switch_failure(event, session, "invalid_watching_targets_request", profile_id=profile_id)
    if str((context.get("household") or {}).get("role") or "").lower() != CanonicalRole.OWNER.value:
        return _profile_switch_failure(event, session, "watching_targets_owner_required", profile_id=profile_id)
    household_id = str((context.get("household") or {}).get("household_id") or "")
    requested = body.get("profile_ids")
    if len(requested) > 32:
        return _profile_switch_failure(event, session, "invalid_watching_targets_request", profile_id=profile_id)
    try:
        _exact_identity_profile(profile_id, household_id=household_id)
        profile_ids = []
        for candidate in requested:
            target_id = str(candidate or "").strip()
            if not target_id or target_id == profile_id or target_id in profile_ids:
                raise AccountFoundationError("invalid_watching_targets_request")
            _exact_identity_profile(target_id, household_id=household_id)
            profile_ids.append(target_id)
        now = utc_now_iso()
        identity_profiles_table.update_item(
            Key={"profile_id": profile_id},
            UpdateExpression="SET watching_profile_ids = :targets, updated_at = :updated, updated_at_epoch = :epoch",
            ConditionExpression="#state = :active AND household_id = :household",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":targets": profile_ids, ":updated": now, ":epoch": epoch_now(),
                ":active": "active", ":household": household_id,
            },
        )
        commit_security_audit(_profile_binding_audit(
            event, session, "watching_targets_updated", "success", target_id=profile_id,
        ))
    except AccountFoundationError as error:
        return _profile_switch_failure(event, session, error.reason, profile_id=profile_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError:
        return _profile_switch_failure(event, session, "watching_targets_conflict", profile_id=profile_id)
    return response(200, {"state": "watching_targets_updated", "profile_ids": profile_ids})


def _mapping_context(event, *, verified_session=None):
    session = verified_session if verified_session is not None else authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return None, None, response(401, {"state": "protected_session_required"})
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return None, None, failure
    installation_id = str(session.get("installation_id") or "")
    if not installation_id:
        return None, None, response(401, {"state": "installation_context_required"})
    return session, context, None


def _mapping_failure(event, session, state, *, source_id=""):
    event_type = {
        "mapping_conflict": "profile_mapping_conflict_detected",
        "cross_household_mapping_rejected": "profile_mapping_cross_household_rejected",
        "mapping_not_authorized": "profile_mapping_unauthorized_rejected",
        "profile_deletion_not_authorized": "profile_deletion_unauthorized_rejected",
    }.get(state, "profile_mapping_manual_review_required")
    try:
        commit_security_audit(_profile_binding_audit(
            event, session, event_type, "denied", target_id=source_id,
            target_type="local_profile_mapping", reason_code=state,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    unauthorized_states = {"mapping_not_authorized", "profile_deletion_not_authorized"}
    return response(403 if state in unauthorized_states else 409, {"state": state})


def _mapping_eligible_profiles(context):
    # View-only bindings intentionally cannot activate a local profile mapping.
    return [
        item for item in (context.get("profile_access") or [])
        if item.get("access_level") in {"switch", "manage"} and item.get("status") == "active"
    ]


def _canonical_profile_deletion_context(*, profile_id, household_id, session):
    """Resolve one exact canonical profile graph without scanning DynamoDB."""
    canonical_profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(canonical_profile, dict):
        return None
    if (
        str(canonical_profile.get("profile_id") or "") != profile_id
        or str(canonical_profile.get("household_id") or "") != household_id
        or canonical_profile.get("state") not in {"active", "deletion_pending", "deleting"}
    ):
        raise AccountFoundationError("profile_deletion_not_authorized")
    if hmac.compare_digest(profile_id, str(session.get("profile_id") or "")):
        raise AccountFoundationError("owner_profile_deletion_forbidden")

    member_subject = str(canonical_profile.get("member_principal_id") or "").strip()
    if not member_subject and not bool_value(canonical_profile.get("managed_by_owner"), False):
        # An unbound adult/owner identity cannot be inferred from its display
        # fields. Fail closed rather than risk deleting the household Owner.
        raise AccountFoundationError("profile_deletion_ownership_ambiguous")

    memberships = _household_membership_records(household_id)
    target_memberships = [
        item for item in memberships
        if isinstance(item, dict)
        and item.get("entity_type") == "HouseholdMembership"
        and str(item.get("profile_id") or "") == profile_id
    ]
    if len(target_memberships) > 1:
        raise AccountFoundationError("profile_deletion_ownership_ambiguous")
    target_membership = target_memberships[0] if target_memberships else None
    if target_membership is not None:
        if (
            target_membership.get("canonical_role") == CanonicalRole.OWNER.value
            or target_membership.get("household_access_role") == HouseholdAccessRole.OWNER.value
            or str(target_membership.get("account_id") or "")
            != str(canonical_profile.get("account_id") or "")
        ):
            raise AccountFoundationError("owner_profile_deletion_forbidden")

    deletion_already_started = canonical_profile.get("state") in {
        "deletion_pending", "deleting",
    }
    if member_subject:
        principal = principals_table.get_item(
            Key={"principal_id": member_subject}, ConsistentRead=True,
        ).get("Item")
        legacy_membership = identity_memberships_table.get_item(
            Key={"principal_id": member_subject}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(principal, dict)
            or str(principal.get("household_id") or "") != household_id
            or (
                profile_id not in list(principal.get("profile_ids") or [])
                and not deletion_already_started
            )
            or (
                not isinstance(legacy_membership, dict)
                and not deletion_already_started
            )
            or (
                isinstance(legacy_membership, dict)
                and (
                    str(legacy_membership.get("household_id") or "") != household_id
                    or str(legacy_membership.get("profile_id") or "") != profile_id
                )
            )
        ):
            raise AccountFoundationError("profile_deletion_ownership_ambiguous")
    else:
        principal = None
        legacy_membership = None

    owner_subject = str(session.get("principal_id") or "")
    owner_principal = principals_table.get_item(
        Key={"principal_id": owner_subject}, ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(owner_principal, dict)
        or str(owner_principal.get("household_id") or "") != household_id
        or str(owner_principal.get("role") or "") != CanonicalRole.OWNER.value
    ):
        raise AccountFoundationError("profile_deletion_ownership_ambiguous")

    recorded_owner_subject = str(canonical_profile.get("owner_principal_id") or "")
    if recorded_owner_subject and not hmac.compare_digest(recorded_owner_subject, owner_subject):
        # A retained owner edge is authoritative. Never overwrite a different
        # owner during deletion, even when the active session is an Owner.
        raise AccountFoundationError("profile_deletion_ownership_ambiguous")
    if not recorded_owner_subject:
        # Some pre-canonical member profiles have a complete exact member and
        # household membership graph but predate the retained owner edge. The
        # active, exact Owner session above is the only authority permitted to
        # write that missing edge. A conditional write prevents this repair
        # from replacing a concurrently established owner relationship.
        try:
            identity_profiles_table.update_item(
                Key={"profile_id": profile_id},
                UpdateExpression="SET #owner_principal_id = :owner_principal_id, updated_at = :updated_at",
                ConditionExpression="attribute_not_exists(#owner_principal_id)",
                ExpressionAttributeNames={"#owner_principal_id": "owner_principal_id"},
                ExpressionAttributeValues={
                    ":owner_principal_id": owner_subject,
                    ":updated_at": utc_now_iso(),
                },
            )
        except ClientError as error:
            if str((error.response or {}).get("Error", {}).get("Code") or "") == "ConditionalCheckFailedException":
                raise AccountFoundationError("profile_deletion_ownership_ambiguous") from error
            raise
        canonical_profile = dict(canonical_profile)
        canonical_profile["owner_principal_id"] = owner_subject

    return {
        "profile": canonical_profile,
        "membership": target_membership,
        "member_principal": principal,
        "legacy_membership": legacy_membership,
        "owner_principal": owner_principal,
        "household_memberships": memberships,
        "member_subject": member_subject,
    }


def _household_installation_records(household_id):
    records = []
    query = {
        "IndexName": "household_id-created_at_epoch-index",
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ConsistentRead": False,
    }
    while True:
        page = installations_table.query(**query)
        for candidate in page.get("Items", []):
            installation_id = str(candidate.get("installation_id") or "")
            if not installation_id:
                continue
            exact = installations_table.get_item(
                Key={"installation_id": installation_id}, ConsistentRead=True,
            ).get("Item")
            if (
                isinstance(exact, dict)
                and str(exact.get("household_id") or "") == household_id
            ):
                records.append(exact)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def _account_deletion_pending_lookup_key(subject, installation_id):
    """Derive the exact Household Join recovery pointer used by the join API."""
    normalized_installation_id = str(installation_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,256}", normalized_installation_id):
        return ""
    installation_hash = hashlib.sha256(
        normalized_installation_id.encode("utf-8")
    ).hexdigest()
    pointer_material = f"{subject}:{installation_hash}"
    return "pending_" + hashlib.sha256(pointer_material.encode("utf-8")).hexdigest()


def _account_deletion_pending_lookup_keys(
    *, subject, account_id, household_id, profile_ids, installations,
):
    """Resolve and authorize exact pending join pointers before mutation."""
    keys = []
    allowed_profile_ids = set(profile_ids)
    for installation in installations:
        installation_id = str((installation or {}).get("installation_id") or "")
        lookup_key = _account_deletion_pending_lookup_key(subject, installation_id)
        if not lookup_key:
            continue
        exact = household_join_transactions_table.get_item(
            Key={"join_resume_hash": lookup_key}, ConsistentRead=True,
        ).get("Item")
        if exact is None:
            continue
        if not isinstance(exact, dict):
            raise AccountFoundationError("account_deletion_authority_conflict")
        expected_installation_hash = hashlib.sha256(
            installation_id.strip().encode("utf-8")
        ).hexdigest()
        pointer_profile_id = str(exact.get("profile_id") or "")
        if (
            exact.get("entity_type") != "HouseholdJoinPendingLookup"
            or not hmac.compare_digest(
                str(exact.get("join_resume_hash") or ""), lookup_key,
            )
            or not hmac.compare_digest(
                str(exact.get("member_principal_id") or ""), subject,
            )
            or not hmac.compare_digest(
                str(exact.get("account_id") or ""), account_id,
            )
            or not hmac.compare_digest(
                str(exact.get("household_id") or ""), household_id,
            )
            or not hmac.compare_digest(
                str(exact.get("device_binding_hash") or ""),
                expected_installation_hash,
            )
            or (pointer_profile_id and pointer_profile_id not in allowed_profile_ids)
        ):
            raise AccountFoundationError("account_deletion_authority_conflict")
        keys.append(lookup_key)
    return keys


def _profile_mapping_records_for_installations(installations, profile_id, household_id):
    records = []
    for installation in installations:
        installation_id = str(installation.get("installation_id") or "")
        query = {
            "KeyConditionExpression": Key("installation_id").eq(installation_id),
            "ConsistentRead": True,
        }
        while True:
            page = profile_mappings_table.query(**query)
            for item in page.get("Items", []):
                if (
                    str(item.get("installation_id") or "") == installation_id
                    and str(item.get("household_id") or "") == household_id
                    and str(item.get("cloud_profile_id") or "") == profile_id
                ):
                    records.append(item)
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                break
            query["ExclusiveStartKey"] = last_key
    return records


def _profile_binding_records_for_household(memberships, profile_id, household_id):
    records = []
    account_ids = {
        str(item.get("account_id") or "")
        for item in memberships
        if isinstance(item, dict)
        and item.get("entity_type") == "HouseholdMembership"
        and str(item.get("household_id") or "") == household_id
        and str(item.get("account_id") or "")
    }
    for account_id in account_ids:
        item = profile_bindings_table.get_item(
            Key={"account_id": account_id, "profile_id": profile_id},
            ConsistentRead=True,
        ).get("Item")
        if (
            isinstance(item, dict)
            and str(item.get("household_id") or "") == household_id
        ):
            records.append(item)
    return records


def _profile_invitation_records(profile_id, household_id):
    return [
        item for item in _household_invitation_records(household_id)
        if str(item.get("profile_id") or "") == profile_id
        and str(item.get("household_id") or "") == household_id
    ]


def _profile_join_transaction_records(invitations):
    records = []
    for invitation in invitations:
        invitation_id = str(invitation.get("invitation_id") or "")
        if not invitation_id:
            continue
        query = {
            "IndexName": "invitation_id-created_at_epoch-index",
            "KeyConditionExpression": Key("invitation_id").eq(invitation_id),
            "ConsistentRead": False,
        }
        while True:
            page = household_join_transactions_table.query(**query)
            for candidate in page.get("Items", []):
                resume_hash = str(candidate.get("join_resume_hash") or "")
                if not resume_hash:
                    continue
                exact = household_join_transactions_table.get_item(
                    Key={"join_resume_hash": resume_hash}, ConsistentRead=True,
                ).get("Item")
                if (
                    isinstance(exact, dict)
                    and str(exact.get("invitation_id") or "") == invitation_id
                ):
                    records.append(exact)
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                break
            query["ExclusiveStartKey"] = last_key
    return records


def _remove_profile_from_principal(principal, profile_id, *, now_iso, now_epoch):
    if not isinstance(principal, dict):
        return
    principal_id = str(principal.get("principal_id") or "")
    if profile_id not in list(principal.get("profile_ids") or []):
        return
    retained = [
        str(value) for value in list(principal.get("profile_ids") or [])
        if str(value) and str(value) != profile_id
    ]
    next_state = str(principal.get("state") or "active") if retained else "revoked"
    principals_table.update_item(
        Key={"principal_id": principal_id},
        ConditionExpression="contains(profile_ids, :profile_id)",
        UpdateExpression=(
            "SET profile_ids = :retained, #state = :next_state, revoked = :revoked, "
            "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":profile_id": profile_id,
            ":retained": retained,
            ":next_state": next_state,
            ":revoked": not bool(retained),
            ":updated_at": now_iso,
            ":updated_epoch": now_epoch,
        },
    )


def _revoke_profile_installation(installation, *, now_iso):
    installation_id = str(installation.get("installation_id") or "")
    installations_table.update_item(
        Key={"installation_id": installation_id},
        ConditionExpression="household_id = :household_id AND principal_id = :principal_id",
        UpdateExpression=(
            "SET #state = :revoked_state, revoked = :revoked, revoked_at = :revoked_at, "
            "revocation_reason = :reason"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":household_id": str(installation.get("household_id") or ""),
            ":principal_id": str(installation.get("principal_id") or ""),
            ":revoked_state": "revoked",
            ":revoked": True,
            ":revoked_at": now_iso,
            ":reason": "profile_deleted",
        },
    )
    sessions = app_sessions_table.query(
        IndexName="installation_id-created_at_epoch-index",
        KeyConditionExpression=Key("installation_id").eq(installation_id),
    ).get("Items", [])
    for family_id in {
        str(item.get("family_id") or "") for item in sessions
        if str(item.get("family_id") or "")
    }:
        revoke_session_family(family_id, "profile_deleted")


def _retain_deleted_profile_binding_tombstone(profile, *, household_id, now_epoch, now_iso):
    """Retain minimal, exact-key lineage before an immediate profile delete.

    This is not a binding and cannot be used to discover identities. It exists
    solely to let a future guarded reconciliation prove that a plugin-reported
    source belonged to this household after the canonical profile is gone.
    """
    if str((profile or {}).get("jellyfin_binding_state") or "") != "active":
        return
    if profile_binding_tombstones_table is None:
        raise AccountFoundationError("profile_binding_tombstone_unavailable")
    profile_id = str((profile or {}).get("profile_id") or "")
    user_id = _normalized_jellyfin_user_id((profile or {}).get("jellyfin_user_id"))
    if not profile_id or not user_id:
        raise AccountFoundationError("profile_binding_tombstone_invalid")
    item = {
        "profile_id": profile_id,
        "household_id": household_id,
        "state": "deleted",
        "deleted_at": now_iso,
        "expires_at": now_epoch + BINDING_SOURCE_TOMBSTONE_RETENTION_SECONDS,
        "provider_user_fingerprint": _binding_operation_fingerprint(user_id),
    }
    try:
        profile_binding_tombstones_table.put_item(
            Item=item, ConditionExpression="attribute_not_exists(profile_id)",
        )
        return
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "ConditionalCheckFailedException":
            raise
    existing = profile_binding_tombstones_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(existing, dict) or not (
        existing.get("state") == "deleted"
        and hmac.compare_digest(str(existing.get("household_id") or ""), household_id)
    ):
        raise AccountFoundationError("profile_binding_tombstone_conflict")


def _release_deleted_profile_cloud_seat(profile, *, household_id, now_iso):
    """Release a deleted device profile from the exact household seat ledger.

    A ledger may be absent on a household created before seat accounting. That
    is safe: the next reservation rebuilds it from exact active memberships.
    Cleanup never changes deletion success after the canonical profile is gone.
    """
    if not bool_value(profile.get("cloud_access_enabled"), True):
        return
    profile_id = str(profile.get("profile_id") or "")
    if not profile_id or not household_id or identity_households_table is None:
        return
    try:
        identity_households_table.update_item(
            Key={"household_id": household_id},
            ConditionExpression=(
                "#state = :active AND "
                "(attribute_not_exists(cloud_seat_profile_ids) "
                "OR contains(cloud_seat_profile_ids, :profile_id))"
            ),
            UpdateExpression=(
                "DELETE cloud_seat_profile_ids :profile_id_set "
                "SET updated_at = :updated_at"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":active": "active",
                ":profile_id": profile_id,
                ":profile_id_set": {profile_id},
                ":updated_at": now_iso,
            },
        )
    except ClientError:
        # This is a rebuildable accounting cache, never deletion authority.
        # Do not report a successful canonical deletion as a cleanup failure.
        LOGGER.warning(
            "household_cloud_seat_release_deferred profile=%s",
            _protected_identity_fingerprint(profile_id),
        )


def _execute_canonical_profile_deletion(
    event, session, context, graph, *, profile_id, household_id, mode,
):
    now_epoch = epoch_now()
    now_iso = utc_now_iso()
    execute_at = now_epoch if mode == "immediate" else now_epoch + (30 * 24 * 60 * 60)
    next_state = "deleting" if mode == "immediate" else "deletion_pending"
    member_subject = str(graph.get("member_subject") or "")

    exact_profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(exact_profile, dict) or not hmac.compare_digest(
        str(exact_profile.get("household_id") or ""), household_id,
    ):
        raise AccountFoundationError("profile_deletion_ownership_ambiguous")
    if mode == "immediate":
        _retain_deleted_profile_binding_tombstone(
            exact_profile, household_id=household_id, now_epoch=now_epoch, now_iso=now_iso,
        )

    # The authority cutover happens first. From this point onward the profile
    # cannot appear in the canonical roster or obtain a fresh protected
    # session, even if a provider cleanup step needs to be retried.
    identity_profiles_table.update_item(
        Key={"profile_id": profile_id},
        ConditionExpression=(
            "household_id = :household_id AND "
            "(#state = :active OR #state = :pending OR #state = :deleting)"
        ),
        UpdateExpression=(
            "SET #state = :next_state, deletion_mode = :mode, "
            "deletion_requested_at = :updated_at, deletion_execute_at_epoch = :execute_at, "
            "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":household_id": household_id,
            ":active": "active",
            ":pending": "deletion_pending",
            ":deleting": "deleting",
            ":next_state": next_state,
            ":mode": mode,
            ":updated_at": now_iso,
            ":updated_epoch": now_epoch,
            ":execute_at": execute_at,
        },
    )
    membership = graph.get("membership")
    if isinstance(membership, dict):
        household_memberships_table.update_item(
            Key={
                "household_id": household_id,
                "membership_id": str(membership.get("membership_id") or ""),
            },
            ConditionExpression=(
                "profile_id = :profile_id AND "
                "(#status = :active OR #status = :pending OR #status = :deleting)"
            ),
            UpdateExpression=(
                "SET #status = :next_status, updated_at = :updated_at, "
                "updated_at_epoch = :updated_epoch, deletion_execute_at_epoch = :execute_at"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":profile_id": profile_id,
                ":active": "active",
                ":pending": "deletion_pending",
                ":deleting": "deleting",
                ":next_status": next_state,
                ":updated_at": now_iso,
                ":updated_epoch": now_epoch,
                ":execute_at": execute_at,
            },
        )

    installations = _household_installation_records(household_id)
    profile_installations = [
        item for item in installations
        if member_subject
        and str(item.get("principal_id") or "") == member_subject
    ]
    mappings = _profile_mapping_records_for_installations(
        installations, profile_id, household_id,
    )
    bindings = _profile_binding_records_for_household(
        graph["household_memberships"], profile_id, household_id,
    )
    invitations = _profile_invitation_records(profile_id, household_id)
    join_transactions = _profile_join_transaction_records(invitations)

    for mapping in mappings:
        key = {
            "installation_id": str(mapping.get("installation_id") or ""),
            "local_profile_source_id": str(mapping.get("local_profile_source_id") or ""),
        }
        if mode == "immediate":
            profile_mappings_table.delete_item(Key=key)
        else:
            profile_mappings_table.update_item(
                Key=key,
                ConditionExpression="cloud_profile_id = :profile_id AND household_id = :household_id",
                UpdateExpression=(
                    "SET mapping_state = :revoked, revoked_at = :updated_at, "
                    "updated_at = :updated_at, updated_at_epoch = :updated_epoch, "
                    "revocation_reason = :reason"
                ),
                ExpressionAttributeValues={
                    ":profile_id": profile_id,
                    ":household_id": household_id,
                    ":revoked": "revoked",
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                    ":reason": "owner_profile_deletion_v2",
                },
            )
    for binding in bindings:
        key = {
            "account_id": str(binding.get("account_id") or ""),
            "profile_id": profile_id,
        }
        if mode == "immediate":
            profile_bindings_table.delete_item(Key=key)
        else:
            profile_bindings_table.update_item(
                Key=key,
                ConditionExpression="household_id = :household_id",
                UpdateExpression=(
                    "SET #status = :revoked, revoked_at = :updated_at, "
                    "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":household_id": household_id,
                    ":revoked": "revoked",
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                },
            )
    for installation in profile_installations:
        _revoke_profile_installation(installation, now_iso=now_iso)

    _remove_profile_from_principal(
        graph.get("owner_principal"), profile_id, now_iso=now_iso, now_epoch=now_epoch,
    )
    if graph.get("member_principal") is not graph.get("owner_principal"):
        _remove_profile_from_principal(
            graph.get("member_principal"), profile_id, now_iso=now_iso, now_epoch=now_epoch,
        )

    if isinstance(graph.get("legacy_membership"), dict):
        if mode == "immediate":
            identity_memberships_table.delete_item(Key={"principal_id": member_subject})
        else:
            identity_memberships_table.update_item(
                Key={"principal_id": member_subject},
                ConditionExpression="profile_id = :profile_id AND household_id = :household_id",
                UpdateExpression=(
                    "SET #state = :pending, revoked = :revoked, updated_at = :updated_at, "
                    "updated_at_epoch = :updated_epoch, deletion_execute_at_epoch = :execute_at"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":profile_id": profile_id,
                    ":household_id": household_id,
                    ":pending": "deletion_pending",
                    ":revoked": True,
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                    ":execute_at": execute_at,
                },
            )

    for invitation in invitations:
        key = {"code_hash": str(invitation.get("code_hash") or "")}
        if mode == "immediate":
            household_invitations_table.delete_item(Key=key)
        else:
            household_invitations_table.update_item(
                Key=key,
                ConditionExpression="profile_id = :profile_id AND household_id = :household_id",
                UpdateExpression=(
                    "SET #state = :pending, deletion_execute_at_epoch = :execute_at, "
                    "expires_at = :execute_at"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":profile_id": profile_id,
                    ":household_id": household_id,
                    ":pending": "deletion_pending",
                    ":execute_at": execute_at,
                },
            )
    for transaction in join_transactions:
        key = {"join_resume_hash": str(transaction.get("join_resume_hash") or "")}
        if mode == "immediate":
            household_join_transactions_table.delete_item(Key=key)
        else:
            household_join_transactions_table.update_item(
                Key=key,
                UpdateExpression=(
                    "SET #state = :pending, deletion_execute_at_epoch = :execute_at, "
                    "cleanup_at = :execute_at"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":pending": "deletion_pending",
                    ":execute_at": execute_at,
                },
            )

    legacy_profile = profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if isinstance(legacy_profile, dict):
        if str(legacy_profile.get("household_id") or "") != household_id:
            raise AccountFoundationError("profile_deletion_ownership_ambiguous")
        if mode == "immediate":
            profiles_table.delete_item(Key={"profile_id": profile_id})
        else:
            profiles_table.update_item(
                Key={"profile_id": profile_id},
                ConditionExpression="household_id = :household_id",
                UpdateExpression=(
                    "SET #status = :pending, deletion_execute_at_epoch = :execute_at, "
                    "updated_at = :updated_at, updated_at_epoch = :updated_epoch"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":household_id": household_id,
                    ":pending": "deletion_pending",
                    ":execute_at": execute_at,
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                },
            )

    if mode == "immediate":
        for item in events_table.query(
            KeyConditionExpression=Key("profile_id").eq(profile_id),
            ConsistentRead=True,
        ).get("Items", []):
            events_table.delete_item(Key={
                "profile_id": profile_id,
                "event_key": str(item.get("event_key") or ""),
            })
        for table in (profile_settings_table, entitlements_table):
            table.delete_item(Key={"profile_id": profile_id})
        for item in devices_table.query(
            IndexName="profile_id-updated_at-index",
            KeyConditionExpression=Key("profile_id").eq(profile_id),
            ConsistentRead=False,
        ).get("Items", []):
            device_id = str(item.get("device_id") or "")
            exact = devices_table.get_item(
                Key={"device_id": device_id}, ConsistentRead=True,
            ).get("Item")
            if isinstance(exact, dict) and str(exact.get("profile_id") or "") == profile_id:
                devices_table.delete_item(Key={"device_id": device_id})
        if PROFILE_AVATARS_BUCKET and s3_client is not None:
            avatar_key = profile_avatar_key(profile_id)
            # S3 delete operations are strongly consistent.  A successful
            # DeleteObject response therefore confirms this exact avatar key
            # is no longer readable, including when the key was already
            # absent.  Do not follow it with HeadObject: without ListBucket,
            # S3 deliberately returns 403 for an absent key, which used to
            # turn a completed provider cleanup into a false Cloud failure.
            # An avatar is not an identity or provider authority edge.  Once
            # the canonical profile graph has been revoked, its private
            # object cannot be requested through Kaevo.  Do not leave a
            # household member permanently in `deleting` because a later,
            # idempotent storage cleanup is temporarily unavailable.  Keep
            # the failure private and observable, without logging the raw
            # profile ID or broadening S3 permissions.
            try:
                s3_client.delete_object(Bucket=PROFILE_AVATARS_BUCKET, Key=avatar_key)
            except ClientError as error:
                LOGGER.warning(
                    "profile_avatar_cleanup_deferred profile=%s code=%s",
                    _protected_identity_fingerprint(profile_id),
                    str((error.response or {}).get("Error", {}).get("Code") or "unknown"),
                )

        if isinstance(membership, dict):
            household_memberships_table.delete_item(Key={
                "household_id": household_id,
                "membership_id": str(membership.get("membership_id") or ""),
            })
            account_id = str(membership.get("account_id") or "")
            household_memberships_table.delete_item(Key={
                "household_id": household_id,
                "membership_id": account_household_guard_id(account_id, household_id),
            })
        identity_profiles_table.delete_item(Key={"profile_id": profile_id})

    audit = _profile_binding_audit(
        event, session, "profile_deletion_completed", "success",
        target_id=profile_id, target_type="profile", reason_code=mode,
    )
    commit_security_audit(audit)

    exact_profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if mode == "immediate":
        if exact_profile is not None:
            raise AccountFoundationError("profile_deletion_absence_unconfirmed")
        _release_deleted_profile_cloud_seat(
            exact_profile if isinstance(exact_profile, dict) else graph["profile"],
            household_id=household_id,
            now_iso=now_iso,
        )
    elif (
        not isinstance(exact_profile, dict)
        or exact_profile.get("state") != "deletion_pending"
        or int(exact_profile.get("deletion_execute_at_epoch") or 0) != execute_at
    ):
        raise AccountFoundationError("profile_deletion_retention_unconfirmed")
    return response(200, {
        "state": "profile_deleted" if mode == "immediate" else "profile_deletion_scheduled",
        "mode": mode,
        "profile_status": "deleted" if mode == "immediate" else "deletion_pending",
        "deletion_execute_at_epoch": execute_at,
        "mapping_state": "revoked",
        "absence_verified": mode == "immediate",
        "cognito_identity_deleted": False,
    })


def _account_deletion_failure(event, session, state, *, status_code=409):
    """Return a privacy-safe, retryable account-deletion failure."""
    try:
        commit_security_audit(_profile_binding_audit(
            event, session, "account_deletion_rejected", "denied",
            target_id=str(session.get("account_id") or ""), target_type="account",
            reason_code=state,
        ))
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(status_code, {"state": state})


def _account_auth_identity_records(account_id):
    """Resolve one account's auth identities through its GSI and exact keys."""
    records = []
    query = {
        "IndexName": "account_id-created_at_epoch-index",
        "KeyConditionExpression": Key("account_id").eq(account_id),
        "ConsistentRead": False,
    }
    while True:
        page = auth_identities_table.query(**query)
        for candidate in page.get("Items", []):
            key = str(candidate.get("auth_identity_key") or "")
            if not key:
                continue
            exact = auth_identities_table.get_item(
                Key={"auth_identity_key": key}, ConsistentRead=True,
            ).get("Item")
            if isinstance(exact, dict) and hmac.compare_digest(
                str(exact.get("account_id") or ""), account_id,
            ):
                records.append(exact)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def _household_home_connector_records(household_id):
    """Resolve household connector bindings by GSI and exact primary key."""
    if home_connectors_table is None:
        return []
    records = []
    query = {
        "IndexName": "household_id-updated_at-index",
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ConsistentRead": False,
    }
    while True:
        page = home_connectors_table.query(**query)
        for candidate in page.get("Items", []):
            connector_id = str(candidate.get("connector_id") or "")
            if not connector_id:
                continue
            exact = home_connectors_table.get_item(
                Key={"connector_id": connector_id}, ConsistentRead=True,
            ).get("Item")
            if isinstance(exact, dict) and hmac.compare_digest(
                str(exact.get("household_id") or ""), household_id,
            ):
                records.append(exact)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def _account_deletion_profile_graph(
    *, profile_id, household_id, owner_principal, household_memberships,
):
    """Build one exact profile cleanup graph without display-field inference."""
    profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(profile, dict)
        or not hmac.compare_digest(str(profile.get("household_id") or ""), household_id)
        or profile.get("state") not in {"active", "deletion_pending", "deleting"}
    ):
        raise AccountFoundationError("account_deletion_authority_conflict")
    matches = [
        item for item in household_memberships
        if isinstance(item, dict)
        and item.get("entity_type") == "HouseholdMembership"
        and str(item.get("profile_id") or "") == profile_id
    ]
    if len(matches) > 1:
        raise AccountFoundationError("account_deletion_authority_conflict")
    membership = matches[0] if matches else None
    member_subject = str(profile.get("member_principal_id") or "").strip()
    if not member_subject and not bool_value(profile.get("managed_by_owner"), False):
        raise AccountFoundationError("account_deletion_authority_conflict")

    member_principal = None
    legacy_membership = None
    if member_subject:
        member_principal = principals_table.get_item(
            Key={"principal_id": member_subject}, ConsistentRead=True,
        ).get("Item")
        legacy_membership = identity_memberships_table.get_item(
            Key={"principal_id": member_subject}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(member_principal, dict)
            or str(member_principal.get("household_id") or "") != household_id
            or (
                isinstance(legacy_membership, dict)
                and (
                    str(legacy_membership.get("household_id") or "") != household_id
                    or str(legacy_membership.get("profile_id") or "") != profile_id
                )
            )
        ):
            raise AccountFoundationError("account_deletion_authority_conflict")

    recorded_owner = str(profile.get("owner_principal_id") or "")
    exact_owner = str((owner_principal or {}).get("principal_id") or "")
    if recorded_owner and not hmac.compare_digest(recorded_owner, exact_owner):
        raise AccountFoundationError("account_deletion_authority_conflict")
    return {
        "profile": profile,
        "membership": membership,
        "member_principal": member_principal,
        "legacy_membership": legacy_membership,
        "owner_principal": owner_principal,
        "household_memberships": household_memberships,
        "member_subject": member_subject,
    }


def _account_deletion_plan(session, context):
    """Create an exact, server-owned deletion plan before any mutation."""
    subject = str(session.get("principal_id") or "")
    account_id = str(session.get("account_id") or "")
    household_id = str(session.get("household_id") or "")
    profile_id = str(session.get("profile_id") or "")
    role = str((context.get("household") or {}).get("canonical_role") or "")
    if not all((subject, account_id, household_id, profile_id)):
        raise AccountFoundationError("account_deletion_authority_conflict")

    account = accounts_table.get_item(Key={"account_id": account_id}, ConsistentRead=True).get("Item")
    principal = principals_table.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    household = identity_households_table.get_item(Key={"household_id": household_id}, ConsistentRead=True).get("Item")
    current_profile = identity_profiles_table.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item")
    cognito_identity = auth_identities_table.get_item(
        Key={"auth_identity_key": provider_subject_key("cognito", subject)}, ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(account, dict) or account.get("status") != "active"
        or str(account.get("account_id") or "") != account_id
        or not isinstance(principal, dict) or str(principal.get("account_id") or "") != account_id
        or str(principal.get("household_id") or "") != household_id
        or not isinstance(household, dict) or str(household.get("household_id") or "") != household_id
        or not isinstance(current_profile, dict) or str(current_profile.get("account_id") or "") != account_id
        or str(current_profile.get("household_id") or "") != household_id
    ):
        raise AccountFoundationError("account_deletion_authority_conflict")
    assert_auth_identity_binding(
        cognito_identity, account_id=account_id, provider="cognito", provider_subject=subject,
    )

    memberships = _household_membership_records(household_id)
    is_owner = role == CanonicalRole.OWNER.value
    if is_owner:
        for membership in memberships:
            other_account_id = str((membership or {}).get("account_id") or "")
            if (
                not isinstance(membership, dict)
                or membership.get("entity_type") != "HouseholdMembership"
                or membership.get("status") != "active"
                or other_account_id in {"", account_id}
                or str(membership.get("canonical_role") or "") != CanonicalRole.ADULT.value
            ):
                continue
            other_account = accounts_table.get_item(Key={"account_id": other_account_id}, ConsistentRead=True).get("Item")
            if isinstance(other_account, dict) and other_account.get("status") == "active":
                raise AccountFoundationError("ownership_transfer_required")

    owner_subject = str(household.get("owner_principal_id") or "")
    owner_principal = principals_table.get_item(Key={"principal_id": owner_subject}, ConsistentRead=True).get("Item")
    if (
        not isinstance(owner_principal, dict)
        or str(owner_principal.get("household_id") or "") != household_id
        or str(owner_principal.get("role") or "") != CanonicalRole.OWNER.value
        or (is_owner and not hmac.compare_digest(owner_subject, subject))
    ):
        raise AccountFoundationError("account_deletion_authority_conflict")

    profile_ids = {profile_id}
    if is_owner:
        profile_ids.update(str(value) for value in list(owner_principal.get("profile_ids") or []) if str(value))
        profile_ids.update(
            str(item.get("profile_id") or "") for item in memberships
            if isinstance(item, dict) and str(item.get("profile_id") or "")
        )
    graphs = {
        target_id: _account_deletion_profile_graph(
            profile_id=target_id, household_id=household_id,
            owner_principal=owner_principal, household_memberships=memberships,
        )
        for target_id in profile_ids
    }
    ordered_profile_ids = sorted(target for target in profile_ids if target != profile_id)
    ordered_profile_ids.append(profile_id)
    installations = [
        item for item in (
            _household_installation_records(household_id)
            if installations_table is not None else []
        )
        if str(item.get("principal_id") or "") == subject
        and str(item.get("installation_id") or "")
    ]
    return {
        "subject": subject,
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "is_owner": is_owner,
        "graphs": graphs,
        "profile_ids": ordered_profile_ids,
        "auth_identities": _account_auth_identity_records(account_id),
        "installation_ids": [
            str(item.get("installation_id") or "") for item in installations
        ],
        "pending_lookup_keys": _account_deletion_pending_lookup_keys(
            subject=subject,
            account_id=account_id,
            household_id=household_id,
            profile_ids=ordered_profile_ids,
            installations=installations,
        ) if household_join_transactions_table is not None else [],
    }


def _account_deletion_provider_targets(plan):
    """Resolve only canonical immutable provider edges in deletion order."""
    targets = []
    connectors = _household_home_connector_records(plan["household_id"])
    for profile_id in plan["profile_ids"]:
        profile = plan["graphs"][profile_id]["profile"]
        jellyfin_state = str(profile.get("jellyfin_binding_state") or "")
        jellyfin_user_id = _normalized_jellyfin_user_id(profile.get("jellyfin_user_id"))
        connector_id = str(profile.get("jellyfin_connector_id") or "")
        if jellyfin_state != "active":
            if jellyfin_user_id or connector_id:
                raise AccountFoundationError("account_deletion_provider_binding_conflict")
            continue
        if not jellyfin_user_id or not connector_id:
            raise AccountFoundationError("account_deletion_provider_binding_conflict")

        exact_connectors = [
            item for item in connectors
            if isinstance(item, dict)
            and hmac.compare_digest(str(item.get("connector_id") or ""), connector_id)
        ]
        if len(exact_connectors) != 1:
            raise AccountFoundationError("account_deletion_provider_connector_unavailable")

        seerr_state = str(profile.get("seerr_binding_state") or "")
        seerr_user_id = _normalized_seerr_user_id(profile.get("seerr_user_id"))
        seerr_jellyfin_user_id = _normalized_jellyfin_user_id(
            profile.get("seerr_jellyfin_user_id")
        )
        seerr_connector_id = str(profile.get("seerr_connector_id") or "")
        if seerr_state == "active":
            if not (
                seerr_user_id
                and hmac.compare_digest(seerr_jellyfin_user_id, jellyfin_user_id)
                and hmac.compare_digest(seerr_connector_id, connector_id)
            ):
                raise AccountFoundationError("account_deletion_provider_binding_conflict")
        elif any((seerr_user_id, seerr_jellyfin_user_id, seerr_connector_id)):
            raise AccountFoundationError("account_deletion_provider_binding_conflict")

        targets.append({
            "profile_id": profile_id,
            "jellyfin_user_id": jellyfin_user_id,
            "seerr_user_id": seerr_user_id,
            "connectors": exact_connectors,
        })
    return targets


def _execute_account_deletion_provider_cleanup(plan):
    """Delete Seerr first and Jellyfin second, accepting verified absence only."""
    targets = _account_deletion_provider_targets(plan)
    for target in targets:
        if not target["seerr_user_id"]:
            continue
        outcome = _execute_profile_binding_connector_command(
            target["profile_id"],
            target["connectors"],
            "seerr.delete_exact_bound_user",
            {
                "jellyfin_user_id": target["jellyfin_user_id"],
                "seerr_user_id": int(target["seerr_user_id"]),
            },
            timeout_seconds=8.0,
        )
        result = outcome.get("result") if isinstance(outcome, dict) else None
        if not (
            outcome.get("state") == "completed"
            and isinstance(result, dict)
            and result.get("absence_confirmed") is True
            and str(result.get("state") or "") in {"deleted", "absent"}
            and hmac.compare_digest(
                _normalized_jellyfin_user_id(result.get("jellyfin_user_id")),
                target["jellyfin_user_id"],
            )
            and hmac.compare_digest(
                _normalized_seerr_user_id(result.get("seerr_user_id")),
                target["seerr_user_id"],
            )
        ):
            raise AccountFoundationError("account_deletion_seerr_absence_unconfirmed")

    for target in targets:
        outcome = _execute_profile_binding_connector_command(
            target["profile_id"],
            target["connectors"],
            "jellyfin.delete_exact_bound_user",
            {"jellyfin_user_id": target["jellyfin_user_id"]},
            timeout_seconds=8.0,
        )
        result = outcome.get("result") if isinstance(outcome, dict) else None
        if not (
            outcome.get("state") == "completed"
            and isinstance(result, dict)
            and result.get("absence_confirmed") is True
            and str(result.get("state") or "") in {"deleted", "absent"}
            and hmac.compare_digest(
                _normalized_jellyfin_user_id(result.get("jellyfin_user_id")),
                target["jellyfin_user_id"],
            )
        ):
            raise AccountFoundationError("account_deletion_jellyfin_absence_unconfirmed")
    return {
        "requested": True,
        "seerr_absence_confirmed": True,
        "jellyfin_absence_confirmed": True,
    }


def _delete_cognito_account(subject):
    """Delete the exact Cognito identity; already absent is idempotent success."""
    try:
        username = resolve_cognito_username(
            cognito_client, user_pool_id=COGNITO_USER_POOL_ID, subject=subject,
        )
        cognito_client.admin_delete_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)
        try:
            cognito_client.admin_get_user(
                UserPoolId=COGNITO_USER_POOL_ID, Username=username,
            )
        except ClientError as readback_error:
            readback_code = str(
                (readback_error.response or {}).get("Error", {}).get("Code") or ""
            )
            if readback_code in {"UserNotFoundException", "ResourceNotFoundException"}:
                return
            raise
        raise AccountFoundationError("account_deletion_cognito_absence_unconfirmed")
    except ClientError as error:
        code = str((error.response or {}).get("Error", {}).get("Code") or "")
        if code not in {"UserNotFoundException", "ResourceNotFoundException"}:
            raise
    except SocialIdentityError as error:
        if error.reason not in {
            "existing_account_not_found",
            "identity_not_found",
            "identity_provider_user_not_found",
        }:
            raise


def _account_deletion_attempt_id(value):
    attempt_id = str(value or "").strip()
    return attempt_id if re.fullmatch(r"del_[A-Za-z0-9_-]{32,128}", attempt_id) else ""


def _account_deletion_receipt_key(attempt_id):
    return f"account_deletion#{hashlib.sha256(attempt_id.encode('utf-8')).hexdigest()}"


def _account_deletion_receipt_payload(receipt):
    if not isinstance(receipt, dict) or receipt.get("state") != "completed":
        return None
    return {
        "state": "account_deleted",
        "deletion_scope": str(receipt.get("deletion_scope") or ""),
        "session_revoked": receipt.get("session_revoked") is True,
        "provider_accounts_preserved": receipt.get("provider_accounts_preserved") is True,
        "provider_deletion_requested": receipt.get("provider_deletion_requested") is True,
        "seerr_identity_absence_confirmed": receipt.get("seerr_identity_absence_confirmed") is True,
        "jellyfin_identity_absence_confirmed": receipt.get("jellyfin_identity_absence_confirmed") is True,
        "subscription_cancellation_required": receipt.get("subscription_cancellation_required") is True,
        "deletion_attempt_id": str(receipt.get("deletion_attempt_id") or ""),
    }


def _account_deletion_receipt_for_plan(attempt_id, plan, *, state, payload=None, reason=""):
    now = epoch_now()
    item = {
        "token_hash": _account_deletion_receipt_key(attempt_id),
        "record_type": "account_deletion_receipt",
        "deletion_attempt_id": attempt_id,
        "account_id": plan["account_id"],
        "principal_id": plan["subject"],
        "household_id": plan["household_id"],
        "profile_ids": list(plan["profile_ids"]),
        "auth_identity_keys": [
            str(identity.get("auth_identity_key") or "")
            for identity in plan["auth_identities"]
            if str(identity.get("auth_identity_key") or "")
        ],
        "state": state,
        "updated_at": utc_now_iso(),
        "updated_at_epoch": now,
        "expires_at": now + (30 * 24 * 60 * 60),
    }
    if reason:
        item["retry_reason"] = reason
    if isinstance(payload, dict):
        for key in (
            "deletion_scope", "session_revoked", "provider_accounts_preserved",
            "provider_deletion_requested", "seerr_identity_absence_confirmed",
            "jellyfin_identity_absence_confirmed", "subscription_cancellation_required",
        ):
            if key in payload:
                item[key] = payload[key]
    return item


def account_deletion_status_v3(event, path):
    """Read a bearer-safe terminal receipt after the exact session is gone."""
    attempt_id = _account_deletion_attempt_id(
        path.removeprefix("/v3/identity/account-deletions/")
    )
    if not attempt_id or app_sessions_table is None:
        return response(404, {"state": "account_deletion_receipt_not_found"})
    receipt = app_sessions_table.get_item(
        Key={"token_hash": _account_deletion_receipt_key(attempt_id)}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(receipt, dict) or not hmac.compare_digest(
        str(receipt.get("deletion_attempt_id") or ""), attempt_id,
    ):
        return response(404, {"state": "account_deletion_receipt_not_found"})
    terminal = _account_deletion_receipt_payload(receipt)
    if terminal is not None:
        return response(200, terminal)
    if receipt.get("state") == "retry_required":
        return response(409, {"state": "account_deletion_retry_required", "retryable": True})
    return response(202, {"state": "account_deletion_pending", "retryable": True})


def _delete_household_account_artifacts(plan):
    """Delete Kaevo-owned household bindings without touching providers/media."""
    household_id = plan["household_id"]
    invitations = _household_invitation_records(household_id)
    for transaction in _profile_join_transaction_records(invitations):
        household_join_transactions_table.delete_item(Key={"join_resume_hash": str(transaction.get("join_resume_hash") or "")})
    for invitation in invitations:
        household_invitations_table.delete_item(Key={"code_hash": str(invitation.get("code_hash") or "")})
    for guest_pass in _guest_pass_records(household_id):
        guest_passes_table.delete_item(Key={"pass_id": str(guest_pass.get("pass_id") or "")})
    for connector in _household_home_connector_records(household_id):
        home_connectors_table.delete_item(Key={"connector_id": str(connector.get("connector_id") or "")})
    for membership in _household_membership_records(household_id):
        household_memberships_table.delete_item(Key={
            "household_id": household_id, "membership_id": str(membership.get("membership_id") or ""),
        })
    identity_households_table.delete_item(Key={"household_id": household_id})


def _execute_account_deletion(event, session, context, plan):
    """Execute a preflighted plan with the caller profile/session last."""
    current_profile_id = plan["profile_id"]
    for profile_id in plan["profile_ids"]:
        if profile_id == current_profile_id:
            continue
        _execute_canonical_profile_deletion(
            event, session, context, plan["graphs"][profile_id],
            profile_id=profile_id, household_id=plan["household_id"], mode="immediate",
        )

    # Keep the caller's exact profile, installation, and session alive through
    # every external step so a retryable Cognito failure can be safely retried.
    _delete_cognito_account(plan["subject"])
    _execute_canonical_profile_deletion(
        event, session, context, plan["graphs"][current_profile_id],
        profile_id=current_profile_id, household_id=plan["household_id"], mode="immediate",
    )

    if plan["is_owner"]:
        _delete_household_account_artifacts(plan)
    else:
        for binding in profile_bindings_table.query(
            KeyConditionExpression=Key("account_id").eq(plan["account_id"]), ConsistentRead=True,
        ).get("Items", []):
            profile_bindings_table.delete_item(Key={
                "account_id": plan["account_id"], "profile_id": str(binding.get("profile_id") or ""),
            })

    for identity in plan["auth_identities"]:
        auth_identities_table.delete_item(Key={"auth_identity_key": str(identity.get("auth_identity_key") or "")})
    for lookup_key in plan.get("pending_lookup_keys") or []:
        household_join_transactions_table.delete_item(
            Key={"join_resume_hash": lookup_key},
        )
    identity_memberships_table.delete_item(Key={"principal_id": plan["subject"]})
    principals_table.delete_item(Key={"principal_id": plan["subject"]})
    accounts_table.delete_item(Key={"account_id": plan["account_id"]})

    retained = [
        accounts_table.get_item(
            Key={"account_id": plan["account_id"]}, ConsistentRead=True,
        ).get("Item"),
        principals_table.get_item(
            Key={"principal_id": plan["subject"]}, ConsistentRead=True,
        ).get("Item"),
        identity_memberships_table.get_item(
            Key={"principal_id": plan["subject"]}, ConsistentRead=True,
        ).get("Item"),
    ]
    retained.extend(
        identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        for profile_id in plan["profile_ids"]
    )
    retained.extend(
        auth_identities_table.get_item(
            Key={"auth_identity_key": str(identity.get("auth_identity_key") or "")},
            ConsistentRead=True,
        ).get("Item")
        for identity in plan["auth_identities"]
        if str(identity.get("auth_identity_key") or "")
    )
    retained.extend(
        household_join_transactions_table.get_item(
            Key={"join_resume_hash": lookup_key}, ConsistentRead=True,
        ).get("Item")
        for lookup_key in plan.get("pending_lookup_keys") or []
    )
    if plan["is_owner"]:
        retained.append(identity_households_table.get_item(
            Key={"household_id": plan["household_id"]}, ConsistentRead=True,
        ).get("Item"))
    if any(item is not None for item in retained):
        raise AccountFoundationError("account_deletion_absence_unconfirmed")

    for installation_id in plan.get("installation_ids") or []:
        installation = installations_table.get_item(
            Key={"installation_id": installation_id}, ConsistentRead=True,
        ).get("Item")
        if not (
            isinstance(installation, dict)
            and installation.get("state") == "revoked"
            and bool_value(installation.get("revoked"), False)
            and hmac.compare_digest(
                str(installation.get("principal_id") or ""), plan["subject"],
            )
        ):
            raise AccountFoundationError("account_deletion_absence_unconfirmed")
        sessions = app_sessions_table.query(
            IndexName="installation_id-created_at_epoch-index",
            KeyConditionExpression=Key("installation_id").eq(installation_id),
        ).get("Items", [])
        if any(
            item.get("record_type") in {"access", "refresh"}
            and item.get("state") == "active"
            and not bool_value(item.get("revoked"), False)
            for item in sessions
        ):
            raise AccountFoundationError("account_deletion_absence_unconfirmed")

    commit_security_audit(_profile_binding_audit(
        event, session, "account_deletion_completed", "success",
        target_id=plan["account_id"], target_type="account",
        reason_code="household_deleted" if plan["is_owner"] else "member_deleted",
    ))
    return response(200, {
        "state": "account_deleted",
        "deletion_scope": "household" if plan["is_owner"] else "member",
        "session_revoked": True,
        "provider_accounts_preserved": not bool(plan.get("provider_deletion_requested")),
        "provider_deletion_requested": bool(plan.get("provider_deletion_requested")),
        "seerr_identity_absence_confirmed": bool(plan.get("seerr_identity_absence_confirmed")),
        "jellyfin_identity_absence_confirmed": bool(plan.get("jellyfin_identity_absence_confirmed")),
        "subscription_cancellation_required": True,
    })


def delete_account_v3(event):
    """Delete only the account bound to the exact protected app session."""
    required = (
        accounts_table, auth_identities_table, household_memberships_table,
        profiles_table, profile_bindings_table, profile_mappings_table,
        principals_table, identity_memberships_table, identity_households_table,
        identity_profiles_table, installations_table, app_sessions_table,
        household_invitations_table, household_join_transactions_table,
        events_table, profile_settings_table, entitlements_table, devices_table,
        security_audit_table, guest_passes_table, home_connectors_table,
        profile_binding_tombstones_table,
    )
    if any(table is None for table in required) or not COGNITO_USER_POOL_ID:
        return response(503, {"state": "account_deletion_storage_unavailable"})
    session = authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return response(401, {"state": "protected_session_required"})
    body = parse_json_body(event)
    if (
        not isinstance(body, dict)
        or not set(body).issubset({
            "explicit_confirmation", "delete_linked_provider_accounts",
            "deletion_attempt_id",
        })
        or body.get("explicit_confirmation") is not True
        or not isinstance(body.get("delete_linked_provider_accounts", False), bool)
        or not _account_deletion_attempt_id(body.get("deletion_attempt_id"))
    ):
        return _account_deletion_failure(
            event, session, "account_deletion_confirmation_required", status_code=400,
        )
    attempt_id = _account_deletion_attempt_id(body.get("deletion_attempt_id"))
    receipt_key = _account_deletion_receipt_key(attempt_id)
    existing_receipt = app_sessions_table.get_item(
        Key={"token_hash": receipt_key}, ConsistentRead=True,
    ).get("Item")
    if isinstance(existing_receipt, dict):
        receipt_matches_session = (
            existing_receipt.get("record_type") == "account_deletion_receipt"
            and hmac.compare_digest(
                str(existing_receipt.get("deletion_attempt_id") or ""), attempt_id,
            )
            and hmac.compare_digest(
                str(existing_receipt.get("account_id") or ""),
                str(session.get("account_id") or ""),
            )
            and hmac.compare_digest(
                str(existing_receipt.get("principal_id") or ""),
                str(session.get("principal_id") or ""),
            )
        )
        if not receipt_matches_session:
            return _account_deletion_failure(
                event, session, "account_deletion_attempt_conflict", status_code=409,
            )
        terminal = _account_deletion_receipt_payload(existing_receipt)
        if terminal is not None:
            return response(200, terminal)
        if (
            existing_receipt.get("state") == "in_progress"
            and int(existing_receipt.get("updated_at_epoch") or 0) > epoch_now() - 60
        ):
            return response(202, {
                "state": "account_deletion_pending",
                "deletion_attempt_id": attempt_id,
                "retryable": True,
            })
    context, failure = _normalized_profile_context(event, session)
    if failure:
        return failure
    plan = None
    try:
        plan = _account_deletion_plan(session, context)
        in_progress_receipt = _account_deletion_receipt_for_plan(
            attempt_id, plan, state="in_progress",
        )
        if existing_receipt is None:
            try:
                app_sessions_table.put_item(
                    Item=in_progress_receipt,
                    ConditionExpression="attribute_not_exists(token_hash)",
                )
            except ClientError:
                winner = app_sessions_table.get_item(
                    Key={"token_hash": receipt_key}, ConsistentRead=True,
                ).get("Item")
                if not isinstance(winner, dict) or not all((
                    hmac.compare_digest(str(winner.get("account_id") or ""), plan["account_id"]),
                    hmac.compare_digest(str(winner.get("principal_id") or ""), plan["subject"]),
                    hmac.compare_digest(str(winner.get("deletion_attempt_id") or ""), attempt_id),
                )):
                    raise AccountFoundationError("account_deletion_attempt_conflict")
                terminal = _account_deletion_receipt_payload(winner)
                if terminal is not None:
                    return response(200, terminal)
                app_sessions_table.put_item(Item=in_progress_receipt)
        else:
            app_sessions_table.put_item(Item=in_progress_receipt)
        delete_linked_providers = body.get("delete_linked_provider_accounts", False) is True
        if delete_linked_providers:
            provider_result = _execute_account_deletion_provider_cleanup(plan)
            plan["provider_deletion_requested"] = True
            plan["seerr_identity_absence_confirmed"] = bool(
                provider_result.get("seerr_absence_confirmed")
            )
            plan["jellyfin_identity_absence_confirmed"] = bool(
                provider_result.get("jellyfin_absence_confirmed")
            )
        deletion_response = _execute_account_deletion(event, session, context, plan)
        deletion_payload = json.loads(deletion_response["body"])
        deletion_payload["deletion_attempt_id"] = attempt_id
        app_sessions_table.put_item(Item=_account_deletion_receipt_for_plan(
            attempt_id, plan, state="completed", payload=deletion_payload,
        ))
        return response(200, deletion_payload)
    except AccountFoundationError as error:
        if isinstance(plan, dict):
            app_sessions_table.put_item(Item=_account_deletion_receipt_for_plan(
                attempt_id, plan, state="retry_required", reason=error.reason,
            ))
        return _account_deletion_failure(event, session, error.reason, status_code=409)
    except SocialIdentityError:
        if isinstance(plan, dict):
            app_sessions_table.put_item(Item=_account_deletion_receipt_for_plan(
                attempt_id, plan, state="retry_required",
                reason="account_deletion_retry_required",
            ))
        return _account_deletion_failure(
            event, session, "account_deletion_retry_required", status_code=503,
        )
    except ClientError as error:
        code = str((error.response or {}).get("Error", {}).get("Code") or "")
        state = "account_deletion_conflict" if code in {
            "ConditionalCheckFailedException", "TransactionCanceledException",
        } else "account_deletion_retry_required"
        if isinstance(plan, dict):
            app_sessions_table.put_item(Item=_account_deletion_receipt_for_plan(
                attempt_id, plan, state="retry_required", reason=state,
            ))
        return _account_deletion_failure(
            event, session, state, status_code=409 if state == "account_deletion_conflict" else 503,
        )


def delete_profile_v3(event, path):
    """Schedule or permanently delete one exact household profile graph.

    Canonical household profiles are authorized from the server-owned
    HouseholdMembership and IdentityProfile graph. Legacy mapping-only Cloud
    profiles retain the installation-scoped receipt requirement. Neither path
    searches by display name or deletes a Cognito identity.
    """
    if any(table is None for table in (
        profiles_table,
        profile_mappings_table,
        security_audit_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session, context, failure = _mapping_context(event)
    if failure:
        return failure
    capabilities = set((context.get("household") or {}).get("capabilities") or [])
    if "profile.delete_household" not in capabilities:
        return _mapping_failure(event, session, "profile_deletion_not_authorized")
    profile_id = profile_deletion_path_id(path)
    body = parse_json_body(event)
    if (
        not profile_id
        or not isinstance(body, dict)
        or body.get("explicit_confirmation") is not True
    ):
        return _mapping_failure(event, session, "invalid_profile_deletion_request")
    mode = str(body.get("mode") or "").strip().lower()
    if mode not in {"immediate", "retained_30_days"}:
        return _mapping_failure(event, session, "invalid_profile_deletion_mode")
    household_id = str((context.get("household") or {}).get("household_id") or "")

    if any(table is None for table in (
        profile_bindings_table,
        household_memberships_table,
        identity_profiles_table,
        principals_table,
        identity_memberships_table,
    )):
        return response(503, {"state": "identity_context_storage_unavailable"})
    try:
        canonical_graph = _canonical_profile_deletion_context(
            profile_id=profile_id,
            household_id=household_id,
            session=session,
        )
    except AccountFoundationError as error:
        status = 403 if error.reason in {
            "owner_profile_deletion_forbidden",
            "profile_deletion_not_authorized",
        } else 409
        return response(status, {"state": error.reason})
    if canonical_graph is not None:
        if any(table is None for table in (
            installations_table,
            app_sessions_table,
            household_invitations_table,
            household_join_transactions_table,
            events_table,
            profile_settings_table,
            entitlements_table,
            devices_table,
        )):
            return response(503, {"state": "identity_context_storage_unavailable"})
        try:
            return _execute_canonical_profile_deletion(
                event,
                session,
                context,
                canonical_graph,
                profile_id=profile_id,
                household_id=household_id,
                mode=mode,
            )
        except AuditReferenceError:
            return audit_unavailable_response()
        except AccountFoundationError as error:
            return response(409, {"state": error.reason})
        except ClientError as error:
            if str((error.response or {}).get("Error", {}).get("Code") or "") in {
                "ConditionalCheckFailedException",
                "TransactionCanceledException",
            }:
                return response(409, {"state": "profile_deletion_conflict"})
            raise

    # Mapping-only Cloud profiles predate the canonical household roster and
    # remain deletable only with the exact installation receipt.
    try:
        source_id = local_profile_source_id(body.get("local_profile_source_id"))
    except AccountFoundationError as error:
        return _mapping_failure(event, session, error.reason)
    mapping_id_value = str(body.get("mapping_id") or "").strip()
    eligible = {str(item.get("profile_id") or "") for item in _mapping_eligible_profiles(context)}
    if profile_id not in eligible:
        return _mapping_failure(event, session, "profile_deletion_not_authorized", source_id=source_id)

    installation_id = str(session.get("installation_id") or "")
    account_id = str((context.get("account") or {}).get("account_id") or "")
    mapping = profile_mappings_table.get_item(Key={
        "installation_id": installation_id,
        "local_profile_source_id": source_id,
    }, ConsistentRead=True).get("Item")
    profile = profiles_table.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item")
    try:
        validate_confirmed_mapping(
            mapping, installation_id=installation_id, source_id=source_id,
            account_id=account_id, household_id=household_id,
        )
        validate_profile(profile, household_id=household_id)
    except AccountFoundationError as error:
        return _mapping_failure(event, session, error.reason, source_id=source_id)
    if (
        str(mapping.get("mapping_id") or "") != mapping_id_value
        or str(mapping.get("cloud_profile_id") or "") != profile_id
    ):
        return _mapping_failure(event, session, "mapping_conflict", source_id=source_id)

    now_epoch = epoch_now()
    now_iso = utc_now_iso()
    next_status = "deleted" if mode == "immediate" else "deletion_pending"
    execute_at = now_epoch if mode == "immediate" else now_epoch + (30 * 24 * 60 * 60)
    try:
        audit = _profile_binding_audit(
            event, session, "profile_deletion_requested", "success",
            target_id=profile_id, target_type="profile", reason_code=mode,
        )
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Update": {
                "TableName": PROFILES_TABLE,
                "Key": {"profile_id": profile_id},
                "ConditionExpression": (
                    "entity_type = :profile_entity AND household_id = :household_id "
                    "AND #status = :active_status"
                ),
                "UpdateExpression": (
                    "SET #status = :next_status, updated_at = :updated_at, "
                    "updated_at_epoch = :updated_epoch, deletion_mode = :mode, "
                    "deletion_requested_by_account_id = :account_id, "
                    "deletion_requested_at = :updated_at, "
                    "deletion_execute_at_epoch = :execute_at"
                ),
                "ExpressionAttributeNames": {"#status": "status"},
                "ExpressionAttributeValues": {
                    ":profile_entity": "Profile",
                    ":household_id": household_id,
                    ":active_status": "active",
                    ":next_status": next_status,
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                    ":mode": mode,
                    ":account_id": account_id,
                    ":execute_at": execute_at,
                },
            }},
            {"Update": {
                "TableName": PROFILE_MAPPINGS_TABLE,
                "Key": {
                    "installation_id": installation_id,
                    "local_profile_source_id": source_id,
                },
                "ConditionExpression": (
                    "mapping_id = :mapping_id AND account_id = :account_id "
                    "AND household_id = :household_id AND cloud_profile_id = :profile_id "
                    "AND mapping_state = :confirmed"
                ),
                "UpdateExpression": (
                    "SET mapping_state = :revoked, updated_at = :updated_at, "
                    "updated_at_epoch = :updated_epoch, revoked_at = :updated_at, "
                    "revocation_reason = :reason"
                ),
                "ExpressionAttributeValues": {
                    ":mapping_id": mapping_id_value,
                    ":account_id": account_id,
                    ":household_id": household_id,
                    ":profile_id": profile_id,
                    ":confirmed": "confirmed",
                    ":revoked": "revoked",
                    ":updated_at": now_iso,
                    ":updated_epoch": now_epoch,
                    ":reason": "owner_profile_deletion_v1",
                },
            }},
            {"Put": {
                "TableName": SECURITY_AUDIT_TABLE, "Item": audit,
                "ConditionExpression": "attribute_not_exists(event_id)",
            }},
        ])
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            return _mapping_failure(event, session, "profile_deletion_conflict", source_id=source_id)
        raise
    if mode == "immediate":
        mappings = [mapping]
        if installations_table is not None:
            mappings = _profile_mapping_records_for_installations(
                _household_installation_records(household_id),
                profile_id,
                household_id,
            ) or mappings
        for record in mappings:
            profile_mappings_table.delete_item(Key={
                "installation_id": str(record.get("installation_id") or ""),
                "local_profile_source_id": str(record.get("local_profile_source_id") or ""),
            })
        if profile_bindings_table is not None and household_memberships_table is not None:
            for record in _profile_binding_records_for_household(
                _household_membership_records(household_id),
                profile_id,
                household_id,
            ):
                profile_bindings_table.delete_item(Key={
                    "account_id": str(record.get("account_id") or ""),
                    "profile_id": profile_id,
                })
        profiles_table.delete_item(Key={"profile_id": profile_id})
        if profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item") is not None:
            return response(409, {"state": "profile_deletion_absence_unconfirmed"})
    return response(200, {
        "state": "profile_deleted" if mode == "immediate" else "profile_deletion_scheduled",
        "mode": mode,
        "profile_status": next_status,
        "deletion_execute_at_epoch": execute_at,
        "mapping_state": "revoked",
        "absence_verified": mode == "immediate",
        "cognito_identity_deleted": False,
    })


def preview_profile_mapping_v3(event):
    if profile_mappings_table is None or security_audit_table is None:
        return response(503, {"state": "identity_context_storage_unavailable"})
    session, context, failure = _mapping_context(event)
    if failure:
        return failure
    body = parse_json_body(event)
    if not isinstance(body, dict):
        return _mapping_failure(event, session, "invalid_mapping_preview")
    try:
        source_id = local_profile_source_id(body.get("local_profile_source_id"))
        commit_security_audit(_profile_binding_audit(
            event, session, "profile_mapping_previewed", "success", target_id=source_id,
            target_type="local_profile_mapping",
        ))
    except AccountFoundationError as error:
        return _mapping_failure(event, session, error.reason)
    except AuditReferenceError:
        return audit_unavailable_response()
    # Presentation metadata is deliberately not used to claim a match.
    return response(200, {
        "state": "candidate",
        "local_profile_source_id": source_id,
        "actions": ["link_existing_cloud_profile", "create_new_cloud_profile", "keep_local_only", "review_later"],
        "cloud_profiles": _mapping_eligible_profiles(context),
    })


def list_profile_mappings_v3(event):
    if profile_mappings_table is None:
        return response(503, {"state": "identity_context_storage_unavailable"})
    session, context, failure = _mapping_context(event)
    if failure:
        return failure
    installation_id = str(session.get("installation_id") or "")
    account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    usable = {str(item.get("profile_id") or "") for item in _mapping_eligible_profiles(context)}
    records = profile_mappings_table.query(
        KeyConditionExpression=Key("installation_id").eq(installation_id), ConsistentRead=True,
    ).get("Items", [])
    mappings = []
    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            validate_confirmed_mapping(
                record, installation_id=installation_id,
                source_id=str(record.get("local_profile_source_id") or ""),
                account_id=account_id, household_id=household_id,
            )
        except AccountFoundationError:
            continue
        mappings.append(public_mapping(record, usable_profile_ids=usable))
    return response(200, {"schema_version": 1, "mappings": sorted(mappings, key=lambda item: item["local_profile_source_id"])})


def confirm_profile_mapping_v3(event, *, verified_session=None, retry_on_conflict=True):
    if any(table is None for table in (profile_mappings_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session, context, failure = _mapping_context(event, verified_session=verified_session)
    if failure:
        return failure
    body = parse_json_body(event)
    if not isinstance(body, dict) or body.get("explicit_confirmation") is not True:
        return _mapping_failure(event, session, "explicit_confirmation_required")
    try:
        source_id = local_profile_source_id(body.get("local_profile_source_id"))
    except AccountFoundationError as error:
        return _mapping_failure(event, session, error.reason)
    cloud_profile_id = str(body.get("cloud_profile_id") or "").strip()
    eligible = {str(item.get("profile_id") or "") for item in _mapping_eligible_profiles(context)}
    if cloud_profile_id not in eligible:
        return _mapping_failure(event, session, "mapping_not_authorized", source_id=source_id)
    installation_id = str(session.get("installation_id") or "")
    account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    existing = profile_mappings_table.get_item(Key={
        "installation_id": installation_id, "local_profile_source_id": source_id,
    }, ConsistentRead=True).get("Item")
    if isinstance(existing, dict):
        if existing.get("mapping_state") == "confirmed" and existing.get("cloud_profile_id") == cloud_profile_id:
            return response(200, {"state": "mapping_already_confirmed", "mapping_id": existing.get("mapping_id"), "cloud_profile_id": cloud_profile_id})
        return _mapping_failure(event, session, "mapping_conflict", source_id=source_id)
    now = epoch_now()
    try:
        mapping = build_confirmed_mapping(
            installation_id=installation_id, local_source_id=source_id, account_id=account_id,
            household_id=household_id, cloud_profile_id=cloud_profile_id,
            now_iso=utc_now_iso(), now_epoch=now,
        )
        audit = _profile_binding_audit(
            event, session, "profile_mapping_confirmed", "success", target_id=mapping["mapping_id"],
            target_type="local_profile_mapping",
        )
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Put": {"TableName": PROFILE_MAPPINGS_TABLE, "Item": mapping,
                      "ConditionExpression": "attribute_not_exists(installation_id) AND attribute_not_exists(local_profile_source_id)"}},
            {"Put": {"TableName": SECURITY_AUDIT_TABLE, "Item": audit,
                      "ConditionExpression": "attribute_not_exists(event_id)"}},
        ])
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") != "TransactionCanceledException":
            raise
        if retry_on_conflict:
            return confirm_profile_mapping_v3(event, verified_session=session, retry_on_conflict=False)
        return _mapping_failure(event, session, "mapping_conflict", source_id=source_id)
    return response(200, {"state": "mapping_confirmed", "mapping_id": mapping["mapping_id"], "cloud_profile_id": cloud_profile_id})


def create_and_confirm_profile_mapping_v3(event):
    if any(table is None for table in (profiles_table, profile_bindings_table, profile_mappings_table, security_audit_table)):
        return response(503, {"state": "identity_context_storage_unavailable"})
    session, context, failure = _mapping_context(event)
    if failure:
        return failure
    if "household.manage" not in set((context.get("household") or {}).get("capabilities") or []):
        return _mapping_failure(event, session, "mapping_not_authorized")
    body = parse_json_body(event)
    if not isinstance(body, dict) or body.get("explicit_confirmation") is not True:
        return _mapping_failure(event, session, "explicit_confirmation_required")
    try:
        source_id = local_profile_source_id(body.get("local_profile_source_id"))
    except AccountFoundationError as error:
        return _mapping_failure(event, session, error.reason)
    installation_id = str(session.get("installation_id") or "")
    if profile_mappings_table.get_item(Key={"installation_id": installation_id, "local_profile_source_id": source_id}, ConsistentRead=True).get("Item"):
        return _mapping_failure(event, session, "mapping_conflict", source_id=source_id)
    account_id = str((context.get("account") or {}).get("account_id") or "")
    household_id = str((context.get("household") or {}).get("household_id") or "")
    now = epoch_now()
    try:
        creation = build_profile_creation(
            household_id=household_id, account_id=account_id, display_name=body.get("display_name"),
            profile_type=body.get("profile_type"), age_classification=body.get("age_classification"),
            now_iso=utc_now_iso(), now_epoch=now,
        )
        mapping = build_confirmed_mapping(
            installation_id=installation_id, local_source_id=source_id, account_id=account_id,
            household_id=household_id, cloud_profile_id=creation.profile["profile_id"],
            now_iso=utc_now_iso(), now_epoch=now,
        )
        audit = _profile_binding_audit(event, session, "cloud_profile_created_and_mapped", "success", target_id=mapping["mapping_id"], target_type="local_profile_mapping")
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Put": {"TableName": PROFILES_TABLE, "Item": creation.profile, "ConditionExpression": "attribute_not_exists(profile_id)"}},
            {"Put": {"TableName": PROFILE_BINDINGS_TABLE, "Item": creation.binding, "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(profile_id)"}},
            {"Put": {"TableName": PROFILE_MAPPINGS_TABLE, "Item": mapping, "ConditionExpression": "attribute_not_exists(installation_id) AND attribute_not_exists(local_profile_source_id)"}},
            {"Put": {"TableName": SECURITY_AUDIT_TABLE, "Item": audit, "ConditionExpression": "attribute_not_exists(event_id)"}},
        ])
    except AccountFoundationError as error:
        return _mapping_failure(event, session, error.reason, source_id=source_id)
    except AuditReferenceError:
        return audit_unavailable_response()
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "TransactionCanceledException":
            return _mapping_failure(event, session, "mapping_conflict", source_id=source_id)
        raise
    return response(200, {"state": "cloud_profile_created_and_mapped", "mapping_id": mapping["mapping_id"], "cloud_profile_id": creation.profile["profile_id"]})


def request_absolute_url(event):
    path = str(event.get("rawPath") or event.get("path") or "/")
    if not path.startswith("/"):
        path = f"/{path}"

    if PUBLIC_API_BASE_URL:
        public_base = urlsplit(PUBLIC_API_BASE_URL)
        if (
            public_base.scheme != "https"
            or not public_base.hostname
            or public_base.username
            or public_base.password
            or public_base.query
            or public_base.fragment
        ):
            raise IdentityError("invalid_public_api_origin", 503)
        request_context = event.get("requestContext") or {}
        stage = str(request_context.get("stage") or "").strip("/")
        stage_prefix = f"/{stage}/" if stage and stage != "$default" else ""
        if stage_prefix and path.startswith(stage_prefix):
            path = f"/{path[len(stage_prefix):]}"
        origin = f"{public_base.scheme}://{public_base.netloc}"
        base_path = public_base.path.rstrip("/")
        return f"{origin}{base_path}{path}"

    request_context = event.get("requestContext") or {}
    gateway_domain = str(request_context.get("domainName") or "").strip()
    if gateway_domain:
        # API Gateway supplies requestContext.domainName from the matched
        # execute-api or custom domain. Prefer that trusted value over
        # client-controlled forwarding headers so DPoP remains bound to the
        # public URL without permitting host-header substitution.
        forwarded_proto = "https"
        host = gateway_domain
    else:
        # Preserve local/disposable test support for events that do not pass
        # through API Gateway. Production HTTP API events always take the
        # trusted requestContext path above.
        forwarded_proto = str(header_value(event, "x-forwarded-proto") or "https").split(",")[0].strip()
        host = str(header_value(event, "x-forwarded-host") or header_value(event, "host") or "").split(",")[0].strip()
    return f"{forwarded_proto}://{host}{path}"


def record_dpop_jti(jti, expires_at):
    if app_sessions_table is None:
        return False
    try:
        app_sessions_table.put_item(
            Item={"token_hash": f"dpop#{secret_hash(jti)}", "record_type": "dpop_replay", "expires_at": expires_at},
            ConditionExpression="attribute_not_exists(token_hash)",
        )
        return True
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def authoritative_identity(event, capability, target=None):
    if principals_table is None:
        raise IdentityError("identity_storage_unavailable", 503)
    context = IdentityContext.from_gateway_event(event, now=epoch_now())
    principal = principals_table.get_item(Key={"principal_id": context.subject}, ConsistentRead=True).get("Item")
    if not principal:
        raise IdentityError("identity_not_registered", 401)
    authorize(context, principal, capability, target=target, now=epoch_now())
    return context, principal


def require_owner_capability(event, capability, *, profile_id=""):
    """Authorize a sensitive household action from authoritative owner records.

    Development credentials are accepted only by ``require_dev_key`` in an
    explicitly non-production environment. Production callers must present a
    recently authenticated Gateway-verified owner identity. The requested
    profile is checked against the principal's server-side membership list.
    """
    if require_dev_key(event):
        return None, None
    try:
        context, principal = authoritative_identity(event, capability)
        if profile_id:
            authorize(
                context,
                principal,
                capability,
                target={
                    "account_id": str(principal.get("account_id") or ""),
                    "household_id": str(principal.get("household_id") or ""),
                    "profile_id": profile_id,
                },
                now=epoch_now(),
            )
        return (context, principal), None
    except IdentityError as error:
        return None, identity_error_response(error)


def identity_error_response(error):
    return response(error.status_code, {"state": error.reason})


def request_correlation_id(event):
    return str((event.get("requestContext") or {}).get("requestId") or "")[:128]


def prepare_security_audit(
    event, household_id, event_type, subject, *, target_id="", target_type="",
    actor_type="cognito_subject", result="success", reason_code="", containment=False,
):
    try:
        return prepare_audit_item(
            scope_id=household_id,
            event_type=event_type,
            actor_subject=subject,
            actor_type=actor_type,
            target_id=target_id,
            target_type=target_type,
            result=result,
            reason_code=reason_code,
            request_id=request_correlation_id(event),
            now=epoch_now(),
        )
    except AuditReferenceError:
        if not containment:
            raise
        return fallback_audit_item(
            event_type=event_type,
            result=result,
            reason_code=reason_code or "audit_key_unavailable",
            now=epoch_now(),
        )


def commit_security_audit(item, *, containment=False):
    try:
        write_audit_item(security_audit_table, item)
    except Exception:
        if not containment:
            raise
        # Containment must proceed even if DynamoDB is unavailable. This
        # deliberately non-identifying log is the fallback audit trail.
        LOGGER.error("security_audit_write_failed event=%s", item.get("event_type", "security_event"))


def audit_unavailable_response():
    return response(503, {"state": "temporarily_unavailable"})


def require_profile_auth(event, profile_id):
    if require_dev_key(event):
        return True
    session = authenticated_app_session(event)
    return bool(
        session
        and profile_id
        and hmac.compare_digest(str(session.get("profile_id") or ""), str(profile_id))
    )


def _session_authorizes_parent_managed_switch(session, source, target, household_id):
    """Accept only the authenticated Owner's exact canonical managed child.

    Identity V3 already projects legacy parent-managed children through the
    Owner principal when the older Owner profile omitted the same child from
    ``switch_profile_ids``. Protected media authorization must honor that
    exact server-owned edge too, without widening access to an arbitrary
    household profile or authenticating the one-time DPoP proof again.
    """
    if principals_table is None:
        return False
    principal_id = str((session or {}).get("principal_id") or "").strip()
    account_id = str((session or {}).get("account_id") or "").strip()
    source_profile_id = str((source or {}).get("profile_id") or "").strip()
    target_profile_id = str((target or {}).get("profile_id") or "").strip()
    if not (
        principal_id
        and account_id
        and source_profile_id
        and target_profile_id
        and bool_value((target or {}).get("managed_by_owner"), False)
        and str((target or {}).get("profile_type") or "").strip().lower() in {"child", "kid"}
        and hmac.compare_digest(
            str((target or {}).get("owner_principal_id") or ""), principal_id,
        )
        and hmac.compare_digest(str((source or {}).get("account_id") or ""), account_id)
        and hmac.compare_digest(str((target or {}).get("account_id") or ""), account_id)
    ):
        return False
    try:
        principal = principals_table.get_item(
            Key={"principal_id": principal_id}, ConsistentRead=True,
        ).get("Item")
    except Exception:
        return False
    if not (
        isinstance(principal, dict)
        and principal.get("state") == "active"
        and not bool_value(principal.get("revoked"), False)
        and hmac.compare_digest(str(principal.get("principal_id") or ""), principal_id)
        and hmac.compare_digest(str(principal.get("account_id") or ""), account_id)
        and hmac.compare_digest(str(principal.get("household_id") or ""), household_id)
    ):
        return False
    canonical_role = str(
        principal.get("canonical_role") or principal.get("role") or ""
    ).strip().lower()
    access_role = str(
        principal.get("household_access_role")
        or ("owner" if canonical_role == "owner" else "member")
    ).strip().lower()
    if canonical_role != "owner" or access_role != "owner":
        return False
    profile_ids = principal.get("profile_ids") or []
    if not isinstance(profile_ids, list) or len(profile_ids) > 64:
        return False
    return all(any(
        hmac.compare_digest(str(candidate or ""), required_profile_id)
        for candidate in profile_ids
    ) for required_profile_id in (source_profile_id, target_profile_id))


def _verified_session_authorizes_profile_switch(session, profile_id):
    """Authorize one exact target from an already-verified app session.

    Protected DPoP proofs are single-use.  Callers which also need the
    installation or device binding must therefore reuse this verified session
    instead of authenticating the same request a second time.
    """
    target_profile_id = str(profile_id or "").strip()
    source_profile_id = str((session or {}).get("profile_id") or "").strip()
    household_id = str((session or {}).get("household_id") or "").strip()
    if not session or not target_profile_id or not source_profile_id:
        return False
    if hmac.compare_digest(source_profile_id, target_profile_id):
        return True
    if identity_profiles_table is None or not household_id:
        return False
    try:
        source = identity_profiles_table.get_item(
            Key={"profile_id": source_profile_id}, ConsistentRead=True,
        ).get("Item")
        target = identity_profiles_table.get_item(
            Key={"profile_id": target_profile_id}, ConsistentRead=True,
        ).get("Item")
    except Exception:
        return False
    if not (
        isinstance(source, dict)
        and isinstance(target, dict)
        and source.get("state") == "active"
        and target.get("state") == "active"
        and hmac.compare_digest(str(source.get("profile_id") or ""), source_profile_id)
        and hmac.compare_digest(str(target.get("profile_id") or ""), target_profile_id)
        and hmac.compare_digest(str(source.get("household_id") or ""), household_id)
        and hmac.compare_digest(str(target.get("household_id") or ""), household_id)
    ):
        return False
    granted = source.get("switch_profile_ids") or []
    if not isinstance(granted, list) or len(granted) > 64:
        return False
    if any(
        hmac.compare_digest(str(candidate or ""), target_profile_id)
        for candidate in granted
    ):
        return True
    return _session_authorizes_parent_managed_switch(
        session, source, target, household_id,
    )


def authorize_profile_switch_session(event, profile_id):
    """Return one authorization decision and its single verified session."""
    if require_dev_key(event):
        return True, None
    session = authenticated_app_session(event)
    return _verified_session_authorizes_profile_switch(session, profile_id), session


def require_profile_switch_auth(event, profile_id):
    """Authorize the signed-in profile or one exact switch-granted target.

    Profile Switching changes the viewing/content identity, not the Cognito or
    household principal behind the protected app session.  Media reads and
    playback commands may therefore act as an explicitly granted target while
    account, device, settings, and administrative routes continue to require
    the session's own profile.  Every non-self decision is a strongly-read,
    immutable-ID edge; a display name or household roster never grants access.
    """
    authorized, _ = authorize_profile_switch_session(event, profile_id)
    return authorized


def authorize_protected_owner_download_command(event, profile_id):
    """Authorize an exact same-household target from protected owner authority.

    The queue mutation is initiated by the native app session rather than a
    Gateway Cognito identity. Resolve the protected DPoP-bound session first,
    then re-read the canonical owner and target profiles by immutable ID. An
    owner may control a household member's visible request, but never a target
    outside the session's exact active household.
    """
    if require_dev_key(event):
        return None
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if str(session.get("household_access_role") or "").strip().lower() != "owner":
        return response(403, {"state": "owner_required"})
    if identity_profiles_table is None:
        return response(503, {"state": "identity_context_storage_unavailable"})

    source_profile_id = str(session.get("profile_id") or "").strip()
    household_id = str(session.get("household_id") or "").strip()
    if not source_profile_id or not household_id:
        return response(403, {"state": "owner_authority_missing"})

    source = identity_profiles_table.get_item(
        Key={"profile_id": source_profile_id},
        ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(source, dict)
        and source.get("state") == "active"
        and hmac.compare_digest(str(source.get("profile_id") or ""), source_profile_id)
        and hmac.compare_digest(str(source.get("household_id") or ""), household_id)
    ):
        return response(403, {"state": "owner_authority_missing"})

    target = source if hmac.compare_digest(source_profile_id, profile_id) else identity_profiles_table.get_item(
        Key={"profile_id": profile_id},
        ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(target, dict)
        and target.get("state") == "active"
        and hmac.compare_digest(str(target.get("profile_id") or ""), profile_id)
        and hmac.compare_digest(str(target.get("household_id") or ""), household_id)
    ):
        return response(404, {"state": "target_not_found"})
    return None


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


def pairing_v3_playback_grant_payload(payload):
    """Bind a V3 playback grant to the Cloud key that the plugin already trusts.

    V3 intentionally does not provision the legacy symmetric connector grant
    key.  Its relay payload is therefore signed with the existing Cloud
    Ed25519 authorization key; the plugin verifies it with its configured
    public key before forwarding anything to local Jellyfin.
    """
    claims = {
        **payload,
        "iss": f"kaevo-cloud-{KAEVO_ENV}",
        "aud": PAIRING_V3_PLAYBACK_GRANT_AUDIENCE,
        "protocol": PAIRING_V3_PROTOCOL,
    }
    header = {
        "alg": "EdDSA",
        "kid": PAIRING_V3_AUTHORIZATION_KEY_ID,
        "typ": PAIRING_V3_PLAYBACK_GRANT_TYPE,
    }
    encoded_header = pairing_v3_b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    encoded_claims = pairing_v3_b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = pairing_v3_sign_ed25519(
        pairing_v3_authorization_private_key(),
        f"{encoded_header}.{encoded_claims}".encode("ascii"),
    )
    return {**claims, "home_sig": f"{encoded_header}.{encoded_claims}.{signature}"}


def pairing_v3_connector_can_issue_playback_grants(connector):
    return bool(
        connector
        and connector.get("protocol_version") == PAIRING_V3_PROTOCOL
        and connector.get("auth_state") == "v3_active"
        and connector.get("state") == "active"
        and not bool_value(connector.get("revoked"), False)
    )


def create_connector_relay_ticket(event, path, *, pairing_v3=False):
    prefix = "/v3/home-connectors/" if pairing_v3 else "/v1/home-connectors/"
    connector_id = path.removeprefix(prefix).removesuffix("/relay-ticket").strip("/")
    body = parse_json_body(event)
    if not isinstance(body, dict):
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    authenticated = require_pairing_v3_connector_auth(event, connector_id, body) if pairing_v3 else require_connector_auth(event, connector_id)
    if not authenticated:
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
    if not item or bool_value(item.get("revoked"), False):
        return False
    lifecycle = bool(item.get("server_id"))
    if lifecycle:
        if item.get("state") not in {"active", "rotation_pending", "recovery_pending"}:
            return False
        if not hmac.compare_digest(str(item.get("environment") or ""), KAEVO_ENV):
            return False
        supplied_version = str(header_value(event, "x-kaevo-credential-version") or "")
        if not supplied_version or not hmac.compare_digest(supplied_version, str(item.get("credential_version") or "")):
            return False
        binding = home_connectors_table.get_item(
            Key={"connector_id": binding_key(str(item.get("server_id") or ""))}, ConsistentRead=True,
        ).get("Item")
        if not binding or any(not hmac.compare_digest(str(binding.get(key) or ""), str(expected)) for key, expected in (
            ("environment", KAEVO_ENV), ("account_id", item.get("account_id")),
            ("household_id", item.get("household_id")), ("active_connector_id", connector_id),
        )):
            return False
    elif item.get("auth_state") != "active":
        return False
    expected_thumbprint = str(item.get("key_thumbprint") or "")
    if expected_thumbprint:
        try:
            verify_dpop(
                str(header_value(event, "dpop") or ""),
                method=method_for(event),
                url=request_absolute_url(event),
                expected_thumbprint=expected_thumbprint,
                replay_guard=record_dpop_jti,
            )
            return True
        except IdentityError:
            return False
    if KAEVO_ENV not in {"dev", "development", "local", "test"}:
        return False
    supplied = connector_bearer_token(event)
    expected = str(item.get("connector_token_hash") or "")
    return bool(supplied and expected and hmac.compare_digest(secret_hash(supplied), expected))


def require_pairing_v3_connector_auth(event, connector_id, body):
    """Verify one V3 connector request without accepting a legacy credential.

    The connector's enrolled Ed25519 key is authoritative.  The signed
    transcript binds the request method, concrete route, canonical body,
    connector identity, plugin instance, key version, timestamp, and nonce.
    A verified nonce is recorded before the operation is allowed to proceed.
    """
    if home_connectors_table is None or app_sessions_table is None:
        return _pairing_v3_connector_auth_rejected(event, "AUTH_STORAGE_UNAVAILABLE", connector_id)
    if not connector_id:
        return _pairing_v3_connector_auth_rejected(event, "CONNECTOR_ID_MISSING")
    if not isinstance(body, dict):
        return _pairing_v3_connector_auth_rejected(event, "REQUEST_BODY_INVALID", connector_id)
    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and not hmac.compare_digest(body_connector_id, connector_id):
        return _pairing_v3_connector_auth_rejected(event, "BODY_CONNECTOR_MISMATCH", connector_id)
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}, ConsistentRead=True).get("Item")
    if not item:
        return _pairing_v3_connector_auth_rejected(event, "CONNECTOR_NOT_FOUND", connector_id)
    if bool_value(item.get("revoked"), False):
        return _pairing_v3_connector_auth_rejected(event, "CONNECTOR_REVOKED", connector_id)
    if item.get("protocol_version") != PAIRING_V3_PROTOCOL or item.get("auth_state") != "v3_active" or item.get("state") != "active":
        return _pairing_v3_connector_auth_rejected(event, "CONNECTOR_STATE_INVALID", connector_id)
    try:
        public_key = pairing_v3_b64url_decode(str(item.get("plugin_public_key") or ""))
        if len(public_key) != 32:
            raise PairingV3CryptoError("invalid plugin key")
    except (PairingV3CryptoError, TypeError, ValueError):
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_PUBLIC_KEY_INVALID", connector_id)
    fingerprint = str(item.get("plugin_public_key_fingerprint") or "")
    try:
        valid_fingerprint = SAFE_PAIRING_V3_FINGERPRINT.fullmatch(fingerprint) and pairing_v3_constant_time_equal(
            fingerprint, pairing_v3_plugin_fingerprint(public_key)
        )
    except (PairingV3CryptoError, TypeError, ValueError):
        valid_fingerprint = False
    if not valid_fingerprint:
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_FINGERPRINT_INVALID", connector_id)
    try:
        plugin_instance_id = pairing_v3_text(item.get("plugin_instance_id"))
    except (PairingV3CryptoError, TypeError, ValueError):
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_INSTANCE_INVALID", connector_id)
    plugin_key_id = str(header_value(event, "x-kaevo-plugin-key-id") or "")
    expected_key_id = str(item.get("plugin_key_id") or "1")
    if not plugin_key_id or not hmac.compare_digest(plugin_key_id, expected_key_id):
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_KEY_ID_MISMATCH", connector_id)
    timestamp = str(header_value(event, "x-kaevo-plugin-timestamp") or "")
    if not re.fullmatch(r"\d{13}", timestamp) or abs((int(timestamp) // 1000) - epoch_now()) > PAIRING_V3_PLUGIN_TIMESTAMP_SKEW_SECONDS:
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_TIMESTAMP_INVALID", connector_id)
    nonce = str(header_value(event, "x-kaevo-plugin-nonce") or "")
    if not SAFE_PAIRING_V3_NONCE.fullmatch(nonce):
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_NONCE_INVALID", connector_id)
    signature_version = str(header_value(event, "x-kaevo-plugin-signature-version") or "1")
    try:
        if signature_version == "2":
            parsed_body_digest = pairing_v3_b64url_encode(
                hashlib.sha256(_pairing_v3_exact_json_body_bytes(event)).digest()
            )
        elif signature_version == "1":
            parsed_body_digest = pairing_v3_canonical_json_digest(body)
        else:
            raise PairingV3CryptoError("unsupported connector signature version")
        transcript = _pairing_v3_connector_request_transcript(
            event, parsed_body_digest, timestamp, nonce, connector_id,
            plugin_instance_id, plugin_key_id, fingerprint,
        )
    except (PairingV3CryptoError, TypeError, ValueError, UnicodeDecodeError):
        return _pairing_v3_connector_auth_rejected(event, "REQUEST_CANONICALIZATION_INVALID", connector_id)
    signature = str(header_value(event, "x-kaevo-plugin-signature") or "")
    try:
        pairing_v3_verify_ed25519(public_key, transcript, signature)
    except (PairingV3CryptoError, TypeError, ValueError):
        if signature_version == "2":
            return _pairing_v3_connector_auth_rejected(event, "PLUGIN_SIGNATURE_INVALID", connector_id)
        try:
            compatibility_digest = pairing_v3_canonical_json_digest_preserving_number_lexemes(
                _pairing_v3_raw_event_json_body(event)
            )
            if hmac.compare_digest(compatibility_digest, parsed_body_digest):
                raise PairingV3CryptoError("canonical body digest unchanged")
            compatibility_transcript = _pairing_v3_connector_request_transcript(
                event, compatibility_digest, timestamp, nonce, connector_id,
                plugin_instance_id, plugin_key_id, fingerprint,
            )
            pairing_v3_verify_ed25519(public_key, compatibility_transcript, signature)
        except (PairingV3CryptoError, TypeError, ValueError, UnicodeDecodeError):
            return _pairing_v3_connector_auth_rejected(event, "PLUGIN_SIGNATURE_INVALID", connector_id)
        _pairing_v3_connector_auth_number_compatibility(event, connector_id)
    try:
        app_sessions_table.put_item(Item={
            "token_hash": pairing_v3_key("v3_connector_nonce", f"{connector_id}:{nonce}"),
            "record_type": "pairing_v3_connector_nonce",
            "expires_at": epoch_now() + PAIRING_V3_TERMINAL_RETENTION_SECONDS,
        }, ConditionExpression="attribute_not_exists(token_hash)")
        return True
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code") or "")
        reason = "PLUGIN_NONCE_REPLAY" if code == "ConditionalCheckFailedException" else "PLUGIN_NONCE_STORAGE_FAILURE"
        return _pairing_v3_connector_auth_rejected(event, reason, connector_id)
    except (PairingV3CryptoError, TypeError, ValueError):
        return _pairing_v3_connector_auth_rejected(event, "PLUGIN_NONCE_STORAGE_FAILURE", connector_id)


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


BUG_REPORT_EVENT_TYPES = {"bug_report_submitted", "bug_report_resolved"}
BUG_REPORT_EVENT_SCAN_LIMIT = 500
BUG_REPORT_EVENT_RESULT_LIMIT = 100


def bug_report_events(event):
    """Return only the authenticated profile's durable report lifecycle.

    Resolution text is server-authored by Kaevo's support workflow. The app
    can submit a pending record, but this read boundary never infers Resolved
    from Sentry timing, title matching, or a client-side toggle.
    """
    if events_table is None:
        return response(500, {"state": "server_error", "message": "events table is not configured"})

    params = query_params(event)
    profile_id = str(params.get("profile_id") or "").strip()
    if not profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})
    if not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    collected = []
    scanned = 0
    exclusive_start_key = None
    while scanned < BUG_REPORT_EVENT_SCAN_LIMIT and len(collected) < BUG_REPORT_EVENT_RESULT_LIMIT:
        request = {
            "KeyConditionExpression": Key("profile_id").eq(profile_id),
            "ScanIndexForward": False,
            "Limit": min(100, BUG_REPORT_EVENT_SCAN_LIMIT - scanned),
        }
        if exclusive_start_key:
            request["ExclusiveStartKey"] = exclusive_start_key
        result = events_table.query(**request)
        items = result.get("Items", [])
        scanned += len(items)
        for item in items:
            if item.get("event_type") not in BUG_REPORT_EVENT_TYPES:
                continue
            metadata = parse_json_field(item.get("metadata_json"), {})
            collected.append({
                "event_id": item.get("event_id"),
                "event_type": item.get("event_type"),
                "reference": item.get("item_id"),
                "timestamp": item.get("timestamp"),
                "metadata": metadata if isinstance(metadata, dict) else {},
            })
            if len(collected) >= BUG_REPORT_EVENT_RESULT_LIMIT:
                break
        exclusive_start_key = result.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    return response(200, {"profile_id": profile_id, "items": collected})


HOUSEHOLD_PROGRESS_EVENT_TYPE = "household_playback_progress"
HOUSEHOLD_PROGRESS_EVENT_PREFIX = "household-progress"
HOUSEHOLD_PROGRESS_MAX_POSITION_SECONDS = 172_800
FAMILY_SYNC_LIVE_TICKET_SECONDS = 300


def _household_progress_seconds(value):
    if isinstance(value, bool):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if not (0 <= seconds <= HOUSEHOLD_PROGRESS_MAX_POSITION_SECONDS):
        return None
    return seconds


def _household_progress_authorized_source(event, requested_profile_id=""):
    """Resolve the exact self or switch-authorized active Cloud profile.

    The request may identify an immutable target, but the one verified app
    session and the canonical switch graph remain the authority.  Older
    clients which omit the target continue to resolve to the session profile.
    """
    if identity_profiles_table is None:
        return None, None, None, response(503, {"state": "identity_context_storage_unavailable"})
    session = authenticated_app_session(event)
    session_profile_id = str((session or {}).get("profile_id") or "").strip()
    profile_id = str(requested_profile_id or session_profile_id).strip()
    if not session_profile_id or not profile_id:
        return None, None, None, response(401, {"state": "protected_session_required"})
    if not _verified_session_authorizes_profile_switch(session, profile_id):
        return None, None, None, response(403, {"state": "profile_access_not_authorized"})
    source = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    household_id = str((source or {}).get("household_id") or "").strip()
    if not (
        isinstance(source, dict)
        and source.get("state") == "active"
        and str(source.get("profile_id") or "") == profile_id
        and household_id
    ):
        return None, None, None, response(401, {"state": "identity_context_invalid"})
    # Return the already verified DPoP-bound session with the canonical
    # profile context. A request-bound DPoP proof is single-use by design;
    # callers must not authenticate the same request again to recover its
    # installation binding.
    return source, household_id, session, None


def _household_progress_authorized_target_ids(*, source_profile, household_id):
    """Resolve only current, explicit Who's Watching targets by immutable ID.

    Household Sync intentionally does not inspect a roster or use any display
    metadata. A target is eligible only while its exact canonical ID remains
    in the source profile's owner-managed watching grant and it is an active
    member of the same household.
    """
    candidates = source_profile.get("watching_profile_ids") or []
    if not isinstance(candidates, list) or len(candidates) > 64:
        return set()
    target_ids = set()
    for value in candidates:
        profile_id = str(value or "").strip()
        if not profile_id or profile_id in target_ids:
            continue
        target = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if (
            isinstance(target, dict)
            and target.get("state") == "active"
            and str(target.get("profile_id") or "") == profile_id
            and str(target.get("household_id") or "") == household_id
        ):
            target_ids.add(profile_id)
    return target_ids


def _household_progress_payload(body, *, source_profile, household_id):
    provider = str(body.get("provider") or "").strip().lower()
    item_id = str(body.get("item_id") or "").strip().lower()
    session_id = str(body.get("session_id") or "").strip()
    media_type = str(body.get("media_type") or "").strip().lower()
    # Millisecond precision makes a separately-started session on another
    # household device order independently from a session begun in the same
    # second. This is a server ordering key only, never identity authority.
    session_started_at_epoch_milliseconds = positive_int(
        body.get("session_started_at_epoch_milliseconds"),
        maximum=(epoch_now() + 86_400) * 1_000,
    )
    sequence = positive_int(body.get("sequence"), maximum=2_147_483_647)
    position_seconds = _household_progress_seconds(body.get("position_seconds"))
    runtime_seconds = _household_progress_seconds(body.get("runtime_seconds"))
    selected_ids = body.get("selected_viewer_profile_ids")
    departed_ids = body.get("departed_viewer_profile_ids") or []
    playback_state = str(body.get("playback_state") or "unknown").strip().lower()

    if provider != "jellyfin" or not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
        return None, "invalid_media_identity"
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(session_id):
        return None, "invalid_session_id"
    if media_type not in {"movie", "episode", "other"}:
        return None, "invalid_media_type"
    if session_started_at_epoch_milliseconds is None or sequence is None or position_seconds is None:
        return None, "invalid_progress"
    if runtime_seconds is not None and runtime_seconds < position_seconds:
        return None, "invalid_runtime"
    if not isinstance(selected_ids, list) or not selected_ids or len(selected_ids) > 64:
        return None, "invalid_viewer_selection"
    if not isinstance(departed_ids, list) or len(departed_ids) > 64:
        return None, "invalid_departed_viewers"
    if playback_state not in {"active", "paused", "stopped", "completed", "unknown"}:
        return None, "invalid_playback_state"

    source_profile_id = str(source_profile.get("profile_id") or "").strip()
    requested_ids = []
    for value in selected_ids:
        profile_id = str(value or "").strip()
        if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(profile_id) or profile_id in requested_ids:
            return None, "invalid_viewer_selection"
        requested_ids.append(profile_id)
    if source_profile_id not in requested_ids:
        return None, "active_profile_required"

    departed_profile_ids = []
    for value in departed_ids:
        profile_id = str(value or "").strip()
        if (
            not SAFE_PLAYBACK_IDENTIFIER.fullmatch(profile_id)
            or profile_id in requested_ids
            or profile_id in departed_profile_ids
        ):
            return None, "invalid_departed_viewers"
        departed_profile_ids.append(profile_id)

    allowed_ids = {source_profile_id}
    allowed_ids.update(
        _household_progress_authorized_target_ids(
            source_profile=source_profile,
            household_id=household_id,
        )
    )
    if not set(requested_ids + departed_profile_ids).issubset(allowed_ids):
        return None, "viewer_selection_not_authorized"

    return {
        "provider": provider,
        "item_id": item_id,
        "session_id": session_id,
        "media_type": media_type,
        "session_started_at_epoch_milliseconds": session_started_at_epoch_milliseconds,
        "sequence": sequence,
        "position_seconds": position_seconds,
        "runtime_seconds": runtime_seconds,
        "selected_viewer_profile_ids": sorted(requested_ids),
        "departed_viewer_profile_ids": sorted(departed_profile_ids),
        "playback_state": playback_state,
    }, None


def create_family_sync_live_ticket(event):
    """Issue a short-lived relay ticket from the protected app session.

    The relay never receives the app-session bearer or DPoP key. Cloud derives
    the immutable profile, household, and installation claims here, then signs
    the smallest capability needed by an observer or one exact playback
    session. Publisher audiences come only from the current Who's Watching
    grant plus this item's existing Family Sync membership.
    """
    if len(PLAYBACK_GRANT_SIGNING_KEY) < 32 or not PLAYBACK_RELAY_PUBLIC_URL:
        return response(503, {"state": "family_sync_live_unavailable"})
    body = parse_json_body(event)
    if not isinstance(body, dict):
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    source_profile, household_id, session, failure = _household_progress_authorized_source(
        event, body.get("profile_id"),
    )
    if failure:
        return failure
    installation_id = str((session or {}).get("installation_id") or "").strip()
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(installation_id):
        return response(401, {"state": "protected_installation_required"})

    role = str(body.get("role") or "").strip().lower()
    if role not in {"observer", "publisher"}:
        return response(400, {"state": "invalid_live_role"})

    source_profile_id = str(source_profile.get("profile_id") or "").strip()
    now = epoch_now()
    claims = {
        "v": 1,
        "type": "family_sync_live",
        "role": role,
        "profile_id": source_profile_id,
        "household_id": household_id,
        "installation_id": installation_id,
        "nonce": secrets.token_urlsafe(24),
        "iat": now,
        "nbf": now - 5,
        "exp": now + FAMILY_SYNC_LIVE_TICKET_SECONDS,
    }

    if role == "publisher":
        provider = str(body.get("provider") or "").strip().lower()
        item_id = str(body.get("item_id") or "").strip().lower()
        playback_session_id = str(body.get("session_id") or "").strip()
        media_type = str(body.get("media_type") or "").strip().lower()
        session_started_at = positive_int(
            body.get("session_started_at_epoch_milliseconds"),
            maximum=(now + 86_400) * 1_000,
        )
        selected_ids = body.get("selected_viewer_profile_ids")
        if provider != "jellyfin" or not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return response(400, {"state": "invalid_media_identity"})
        if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(playback_session_id):
            return response(400, {"state": "invalid_session_id"})
        if media_type not in {"movie", "episode", "other"}:
            return response(400, {"state": "invalid_media_type"})
        if session_started_at is None:
            return response(400, {"state": "invalid_progress"})
        if not isinstance(selected_ids, list) or not selected_ids or len(selected_ids) > 64:
            return response(400, {"state": "invalid_viewer_selection"})

        requested_ids = []
        for value in selected_ids:
            profile_id = str(value or "").strip()
            if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(profile_id) or profile_id in requested_ids:
                return response(400, {"state": "invalid_viewer_selection"})
            requested_ids.append(profile_id)
        if source_profile_id not in requested_ids:
            return response(400, {"state": "active_profile_required"})

        allowed_ids = {source_profile_id}
        allowed_ids.update(_household_progress_authorized_target_ids(
            source_profile=source_profile,
            household_id=household_id,
        ))
        if not set(requested_ids).issubset(allowed_ids):
            return response(403, {"state": "viewer_selection_not_authorized"})

        event_key = "#".join((HOUSEHOLD_PROGRESS_EVENT_PREFIX, provider, item_id))
        existing = events_table.get_item(
            Key={"profile_id": source_profile_id, "event_key": event_key},
            ConsistentRead=True,
        ).get("Item") if events_table is not None else None
        existing_metadata = parse_json_field((existing or {}).get("metadata_json"), {})
        existing_family_ids = existing_metadata.get("family_sync_profile_ids") or []
        audience_ids = {
            str(value or "").strip() for value in existing_family_ids
            if str(value or "").strip() in allowed_ids
        } if isinstance(existing_family_ids, list) else set()
        if len(requested_ids) > 1:
            audience_ids.update(requested_ids)
        if not audience_ids:
            audience_ids.add(source_profile_id)

        claims.update({
            "provider": provider,
            "item_id": item_id,
            "session_id": playback_session_id,
            "media_type": media_type,
            "session_started_at_epoch_milliseconds": session_started_at,
            "allowed_profile_ids": sorted(allowed_ids),
            "audience_profile_ids": sorted(audience_ids),
        })

    ticket = sign_playback_grant(claims)
    if ticket is None:
        return response(503, {"state": "family_sync_live_unavailable"})
    relay_base = PLAYBACK_RELAY_PUBLIC_URL.rstrip("/")
    websocket_base = re.sub(r"^https://", "wss://", relay_base, count=1)
    if websocket_base == relay_base:
        return response(503, {"state": "family_sync_live_unavailable"})
    return response(201, {
        "state": "issued",
        "relay_ticket": ticket,
        "websocket_url": f"{websocket_base}/v1/family-sync",
        "expires_at": claims["exp"],
        "audience_profile_ids": claims.get("audience_profile_ids") or [source_profile_id],
    })


def save_household_progress(event):
    """Project one playback checkpoint to explicit, currently-authorized viewers.

    Each selected profile receives its own progress row. A late packet cannot
    overwrite a newer playback session, or an earlier sequence in the same
    session, because DynamoDB applies a monotonic conditional update.
    """
    if events_table is None:
        return response(503, {"state": "household_progress_storage_unavailable"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    source_profile, household_id, _, failure = _household_progress_authorized_source(
        event, body.get("profile_id"),
    )
    if failure:
        return failure
    progress, error = _household_progress_payload(
        body,
        source_profile=source_profile,
        household_id=household_id,
    )
    if error:
        return response(400 if error.startswith("invalid") or error == "active_profile_required" else 403, {"state": error})

    # A fresh player reports position zero before its local resume seek has
    # settled. Do not let that provisional packet replace a meaningful
    # household checkpoint from another device/session. The iOS client also
    # defers these writes; this is the authoritative backwards-compatible
    # guard for an older client or a future caller.
    if progress["position_seconds"] < 10:
        return response(202, {
            "state": "ignored_below_threshold",
            "profile_ids": [],
            "deferred_profile_ids": [],
        })

    received_at = utc_now_iso()
    expires_at = epoch_now() + (90 * 24 * 60 * 60)
    written_profile_ids = []
    session_viewer_profile_ids = sorted(set(
        progress["selected_viewer_profile_ids"] + progress["departed_viewer_profile_ids"]
    ))
    event_key = "#".join((
        HOUSEHOLD_PROGRESS_EVENT_PREFIX,
        progress["provider"],
        progress["item_id"],
    ))

    # Family Sync membership is established only by an explicit multi-viewer
    # selection for this exact media item. A later solo session updates that
    # person's checkpoint without discovering unrelated household histories or
    # erasing the item's existing Family Sync relationship.
    family_sync_profile_ids = set()
    for profile_id in session_viewer_profile_ids:
        existing = events_table.get_item(
            Key={"profile_id": profile_id, "event_key": event_key},
            ConsistentRead=True,
        ).get("Item")
        if not isinstance(existing, dict):
            continue
        existing_metadata = parse_json_field(existing.get("metadata_json"), {})
        existing_family_ids = existing_metadata.get("family_sync_profile_ids") or []
        if isinstance(existing_family_ids, list):
            family_sync_profile_ids.update(
                str(value or "").strip() for value in existing_family_ids
            )
    if len(session_viewer_profile_ids) > 1:
        family_sync_profile_ids.update(session_viewer_profile_ids)

    currently_allowed_ids = {str(source_profile.get("profile_id") or "").strip()}
    currently_allowed_ids.update(_household_progress_authorized_target_ids(
        source_profile=source_profile,
        household_id=household_id,
    ))
    family_sync_profile_ids = sorted(
        profile_id for profile_id in family_sync_profile_ids
        if profile_id and profile_id in currently_allowed_ids
    )

    for profile_id in session_viewer_profile_ids:
        metadata = {
            "media_type": progress["media_type"],
            "position_seconds": progress["position_seconds"],
            "runtime_seconds": progress["runtime_seconds"],
            "viewer_profile_ids": session_viewer_profile_ids,
            "family_sync_profile_ids": family_sync_profile_ids,
            "source_profile_id": str(source_profile.get("profile_id") or ""),
            "is_currently_selected": profile_id in progress["selected_viewer_profile_ids"],
            "playback_state": (
                progress["playback_state"]
                if profile_id in progress["selected_viewer_profile_ids"]
                else "stopped"
            ),
        }
        try:
            events_table.update_item(
                Key={"profile_id": profile_id, "event_key": event_key},
                UpdateExpression=(
                    "SET #event_id = :event_id, #event_type = :event_type, #item_id = :item_id, "
                    "#source = :source, #session_id = :session_id, #timestamp = :timestamp, "
                    "#received_at = :received_at, #expires_at = :expires_at, #metadata_json = :metadata_json, "
                    "#session_started_at_epoch_milliseconds = :session_started_at_epoch_milliseconds, #sequence = :sequence"
                ),
                ConditionExpression=(
                    "attribute_not_exists(#session_started_at_epoch_milliseconds) "
                    "OR #session_started_at_epoch_milliseconds < :session_started_at_epoch_milliseconds "
                    "OR (#session_started_at_epoch_milliseconds = :session_started_at_epoch_milliseconds "
                    "AND #sequence < :sequence)"
                ),
                # ``source``, ``timestamp``, and ``sequence`` are reserved
                # DynamoDB expression words. Alias every persisted attribute
                # so this projection never depends on the current reserved
                # word list and Cloud writes reach every selected exact ID.
                ExpressionAttributeNames={
                    "#event_id": "event_id",
                    "#event_type": "event_type",
                    "#item_id": "item_id",
                    "#source": "source",
                    "#session_id": "session_id",
                    "#timestamp": "timestamp",
                    "#received_at": "received_at",
                    "#expires_at": "expires_at",
                    "#metadata_json": "metadata_json",
                    "#session_started_at_epoch_milliseconds": "session_started_at_epoch_milliseconds",
                    "#sequence": "sequence",
                },
                ExpressionAttributeValues={
                    ":event_id": str(uuid.uuid4()),
                    ":event_type": HOUSEHOLD_PROGRESS_EVENT_TYPE,
                    ":item_id": progress["item_id"],
                    ":source": "kaevo_household_sync",
                    ":session_id": progress["session_id"],
                    ":timestamp": received_at,
                    ":received_at": received_at,
                    ":expires_at": expires_at,
                    ":metadata_json": json.dumps(metadata, separators=(",", ":")),
                    ":session_started_at_epoch_milliseconds": progress["session_started_at_epoch_milliseconds"],
                    ":sequence": progress["sequence"],
                },
            )
            written_profile_ids.append(profile_id)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                continue
            LOGGER.error("household_progress_write_failed reason=%s", error.response.get("Error", {}).get("Code", "unknown"))
            return response(503, {"state": "household_progress_unavailable"})

    return response(202, {
        "state": "accepted",
        "profile_ids": written_profile_ids,
        "deferred_profile_ids": sorted(set(session_viewer_profile_ids) - set(written_profile_ids)),
    })


def _household_progress_viewer_snapshots(*, source_profile, household_id, item, metadata):
    """Return exact, still-authorized viewer checkpoints for one media item.

    The authenticated profile's row is the capability.  It may reveal only
    IDs explicitly present in that row and still present in the active
    profile's current Who's Watching grant.  We read each exact row by its
    primary key; this never scans a household or uses display metadata.
    """
    active_profile_id = str(source_profile.get("profile_id") or "").strip()
    event_key = str(item.get("event_key") or "").strip()
    allowed_ids = {active_profile_id}
    allowed_ids.update(_household_progress_authorized_target_ids(
        source_profile=source_profile,
        household_id=household_id,
    ))
    family_sync_ids = metadata.get("family_sync_profile_ids") or []
    if not isinstance(family_sync_ids, list):
        family_sync_ids = []
    # Exact-item membership is the discovery boundary. Current owner-managed
    # grants remain the authorization boundary, so a revoked profile is never
    # exposed even if it remains in historical metadata.
    family_viewer_ids = {
        str(value or "").strip() for value in family_sync_ids
        if str(value or "").strip() in allowed_ids
    }
    # The active profile's own row is always part of its authoritative
    # Continue Watching projection, even for ordinary solo playback. Family
    # Sync peers remain discoverable only when this exact item has an explicit
    # multi-viewer relationship. Omitting the active solo checkpoint forced
    # iOS to fall back to device-local history, which made two phones render
    # different rows for the same canonical profile.
    viewer_ids = {active_profile_id}
    if len(family_viewer_ids) >= 2:
        viewer_ids.update(family_viewer_ids)

    snapshots = []
    for viewer_profile_id in sorted(viewer_ids):
        candidate = item if viewer_profile_id == active_profile_id else events_table.get_item(
            Key={"profile_id": viewer_profile_id, "event_key": event_key},
            ConsistentRead=True,
        ).get("Item")
        if not isinstance(candidate, dict):
            continue
        if (
            candidate.get("event_type") != HOUSEHOLD_PROGRESS_EVENT_TYPE
            or str(candidate.get("item_id") or "") != str(item.get("item_id") or "")
        ):
            continue
        candidate_metadata = parse_json_field(candidate.get("metadata_json"), {})
        position_seconds = _household_progress_seconds(candidate_metadata.get("position_seconds"))
        if position_seconds is None:
            continue
        snapshots.append({
            "profile_id": viewer_profile_id,
            "position_seconds": position_seconds,
            "runtime_seconds": _household_progress_seconds(candidate_metadata.get("runtime_seconds")),
            "is_currently_selected": bool(candidate_metadata.get("is_currently_selected")),
            "playback_state": str(candidate_metadata.get("playback_state") or "unknown"),
            "updated_at": str(candidate.get("received_at") or ""),
        })
    return snapshots


def get_household_progress(event):
    """Return the active profile's rows plus exact authorized viewer checkpoints."""
    if events_table is None:
        return response(503, {"state": "household_progress_storage_unavailable"})
    source_profile, household_id, _, failure = _household_progress_authorized_source(
        event, query_params(event).get("profile_id"),
    )
    if failure:
        return failure
    profile_id = str(source_profile.get("profile_id") or "")
    result = events_table.query(
        KeyConditionExpression=(
            Key("profile_id").eq(profile_id)
            & Key("event_key").begins_with(f"{HOUSEHOLD_PROGRESS_EVENT_PREFIX}#")
        ),
        ScanIndexForward=False,
        Limit=100,
    )
    items = []
    revision_components = []
    for item in result.get("Items", []):
        if item.get("event_type") != HOUSEHOLD_PROGRESS_EVENT_TYPE:
            continue
        metadata = parse_json_field(item.get("metadata_json"), {})
        revision_components.append("|".join((
            str(item.get("event_key") or ""),
            str(item.get("session_started_at_epoch_milliseconds") or ""),
            str(item.get("sequence") or ""),
            str(item.get("received_at") or ""),
        )))
        items.append({
            "item_id": str(item.get("item_id") or ""),
            "provider": "jellyfin",
            "media_type": str(metadata.get("media_type") or "other"),
            "position_seconds": metadata.get("position_seconds"),
            "runtime_seconds": metadata.get("runtime_seconds"),
            "viewer_profile_ids": metadata.get("family_sync_profile_ids") or [],
            "session_id": str(item.get("session_id") or ""),
            "updated_at": str(item.get("received_at") or ""),
            "viewer_progress": _household_progress_viewer_snapshots(
                source_profile=source_profile,
                household_id=household_id,
                item=item,
                metadata=metadata,
            ),
        })
    revision = hashlib.sha256(
        "\n".join(sorted(revision_components)).encode("utf-8")
    ).hexdigest()[:24]
    return response(200, {
        "profile_id": profile_id,
        "revision": revision,
        "items": items,
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
    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    incoming_settings = body.get("settings") if isinstance(body.get("settings"), dict) else body

    if not isinstance(incoming_settings, dict):
        return response(400, {"state": "bad_request", "message": "settings must be an object"})

    protected_updates = OWNER_PROTECTED_PROFILE_SETTING_KEYS.intersection(incoming_settings)
    if protected_updates:
        _, owner_error = require_owner_capability(
            event,
            "manage_parental_policy",
            profile_id=profile_id,
        )
        if owner_error:
            return owner_error
    elif not require_profile_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

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
    _, owner_error = require_owner_capability(
        event,
        "configure_providers",
        profile_id=profile_id,
    )
    if owner_error:
        return owner_error

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
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id):
        return response(400, {"state": "bad_request", "message": "valid device_id is required"})
    now = utc_now_iso()

    existing = devices_table.get_item(Key={"device_id": device_id}).get("Item")
    if existing and not hmac.compare_digest(str(existing.get("profile_id") or ""), profile_id):
        return response(409, {"state": "device_already_registered"})
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


HOME_CONNECTORS_PROFILE_INDEX = "profile_id-updated_at-index"
HOME_CONNECTORS_HOUSEHOLD_INDEX = "household_id-updated_at-index"


def public_connector_item(item, *, requesting_profile_id=""):
    provider_status = parse_json_field(item.get("provider_status_json"), {})
    capabilities = parse_json_field(item.get("capabilities_json"), [])

    online = connector_online_from_item(item)

    return {
        "connector_id": item.get("connector_id"),
        # A connector belongs to a household even though its enrollment record
        # retains the Owner profile that paired it.  Service consumers receive
        # their own authorized profile identity instead of another member's
        # opaque profile identifier.
        "profile_id": requesting_profile_id or item.get("profile_id"),
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


def _direct_home_connectors_for_profile(profile_id):
    result = home_connectors_table.query(
        IndexName=HOME_CONNECTORS_PROFILE_INDEX,
        KeyConditionExpression=Key("profile_id").eq(profile_id),
        ScanIndexForward=False,
        Limit=10,
    )
    return [
        item for item in result.get("Items", [])
        if hmac.compare_digest(str(item.get("profile_id") or ""), profile_id)
    ]


def _authorized_parent_managed_connector_context(profile):
    """Resolve a managed child through its exact Owner authority graph.

    Parent-managed children intentionally share the Owner account and do not
    receive a second account membership or credential.  Connector ownership
    therefore comes from the strongly-read Owner principal and Owner
    membership, while the returned media identity remains the exact child.
    """
    if not all((
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
        household_memberships_table,
    )):
        return None
    profile_id = str((profile or {}).get("profile_id") or "").strip()
    principal_id = str((profile or {}).get("owner_principal_id") or "").strip()
    account_id = str((profile or {}).get("account_id") or "").strip()
    household_id = str((profile or {}).get("household_id") or "").strip()
    if not (
        profile_id
        and principal_id
        and account_id
        and household_id
        and bool_value((profile or {}).get("managed_by_owner"), False)
        and str((profile or {}).get("profile_type") or "").strip().lower()
        in {"child", "kid"}
    ):
        return None

    principal = principals_table.get_item(
        Key={"principal_id": principal_id}, ConsistentRead=True,
    ).get("Item")
    legacy_membership = identity_memberships_table.get_item(
        Key={"principal_id": principal_id}, ConsistentRead=True,
    ).get("Item")
    household = identity_households_table.get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item")
    owner_profile_id = str((legacy_membership or {}).get("profile_id") or "").strip()
    owner_profile = identity_profiles_table.get_item(
        Key={"profile_id": owner_profile_id}, ConsistentRead=True,
    ).get("Item") if owner_profile_id else None
    normalized_membership = household_memberships_table.get_item(Key={
        "household_id": household_id,
        "membership_id": household_membership_id(account_id, household_id),
    }, ConsistentRead=True).get("Item")
    normalized_membership = _repair_legacy_active_membership_profile_pointer(
        normalized_membership,
        expected_profile_id=owner_profile_id,
    )
    principal_profile_ids = (principal or {}).get("profile_ids") or []
    if not (
        isinstance(principal, dict)
        and principal.get("state") == "active"
        and not bool_value(principal.get("revoked"), False)
        and hmac.compare_digest(str(principal.get("principal_id") or ""), principal_id)
        and hmac.compare_digest(str(principal.get("account_id") or ""), account_id)
        and hmac.compare_digest(str(principal.get("household_id") or ""), household_id)
        and isinstance(principal_profile_ids, list)
        and len(principal_profile_ids) <= 64
        and all(any(
            hmac.compare_digest(str(candidate or ""), required_profile_id)
            for candidate in principal_profile_ids
        ) for required_profile_id in (owner_profile_id, profile_id))
        and isinstance(owner_profile, dict)
        and owner_profile.get("state") == "active"
        and hmac.compare_digest(str(owner_profile.get("profile_id") or ""), owner_profile_id)
        and hmac.compare_digest(str(owner_profile.get("account_id") or ""), account_id)
        and hmac.compare_digest(str(owner_profile.get("household_id") or ""), household_id)
    ):
        return None
    try:
        claims, role, resolved_membership = resolve_household_membership(
            subject=principal_id,
            principal=principal,
            legacy_membership=legacy_membership,
            household=household,
            profile=owner_profile,
            normalized_membership=normalized_membership,
        )
    except (AccountFoundationError, AuthorityError):
        return None
    if not (
        role is CanonicalRole.OWNER
        and claims.profile_id == owner_profile_id
        and claims.account_id == account_id
        and claims.household_id == household_id
    ):
        return None
    return {
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "role": CanonicalRole.CHILD.value,
        "membership": resolved_membership,
    }


def _authorized_household_connector_context(profile_id):
    """Resolve one active profile to its exact server-owned household.

    Missing legacy identity records deliberately return ``legacy`` so an
    Owner's already-paired connector keeps working during migration.  Once a
    profile has a principal binding, every incomplete or inconsistent graph is
    invalid and cannot fall back to a client-selected connector.
    """
    authority_tables = (
        principals_table,
        identity_memberships_table,
        identity_households_table,
        identity_profiles_table,
        household_memberships_table,
    )
    if not all(authority_tables):
        return "legacy", None

    profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(profile, dict):
        return "legacy", None
    if (
        str(profile.get("profile_id") or "") != profile_id
        or str(profile.get("state") or "") != "active"
        or bool_value(profile.get("revoked"), False)
    ):
        return "invalid", None

    if bool_value(profile.get("managed_by_owner"), False):
        context = _authorized_parent_managed_connector_context(profile)
        return ("authorized", context) if context is not None else ("invalid", None)

    member_subject = str(profile.get("member_principal_id") or "").strip()
    owner_subject = str(profile.get("owner_principal_id") or "").strip()
    subject = member_subject or owner_subject
    if not subject:
        return "legacy", None

    account_id = str(profile.get("account_id") or "").strip()
    household_id = str(profile.get("household_id") or "").strip()
    if not account_id or not household_id:
        return "invalid", None

    principal = principals_table.get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    legacy_membership = identity_memberships_table.get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    household = identity_households_table.get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item")
    normalized_membership = household_memberships_table.get_item(Key={
        "household_id": household_id,
        "membership_id": household_membership_id(account_id, household_id),
    }, ConsistentRead=True).get("Item")
    normalized_membership = _repair_legacy_active_membership_profile_pointer(
        normalized_membership,
        expected_profile_id=profile_id,
    )
    try:
        claims, role, resolved_membership = resolve_household_membership(
            subject=subject,
            principal=principal,
            legacy_membership=legacy_membership,
            household=household,
            profile=profile,
            normalized_membership=normalized_membership,
        )
    except (AccountFoundationError, AuthorityError):
        return "invalid", None

    if (
        claims.profile_id != profile_id
        or claims.account_id != account_id
        or claims.household_id != household_id
        or (role is CanonicalRole.OWNER and subject != owner_subject)
        or (role is not CanonicalRole.OWNER and subject != member_subject)
    ):
        return "invalid", None
    return "authorized", {
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "role": role.value,
        "membership": resolved_membership,
    }


def _home_connectors_for_profile_access(profile_id):
    """Return only connectors authorized by the profile's household graph."""
    mode, context = _authorized_household_connector_context(profile_id)
    if mode == "invalid":
        return []
    if mode == "legacy":
        return _direct_home_connectors_for_profile(profile_id)

    household_id = context["household_id"]
    try:
        result = home_connectors_table.query(
            IndexName=HOME_CONNECTORS_HOUSEHOLD_INDEX,
            KeyConditionExpression=Key("household_id").eq(household_id),
            ScanIndexForward=False,
            Limit=10,
        )
    except ClientError:
        # During a one-time GSI rollout an Owner can keep using the exact
        # connector they enrolled.  Members fail closed until the household
        # index is available; they never inherit a connector by profile guess.
        return (
            _direct_home_connectors_for_profile(profile_id)
            if context["role"] == CanonicalRole.OWNER.value
            else []
        )

    connectors = [
        item for item in result.get("Items", [])
        if hmac.compare_digest(str(item.get("household_id") or ""), household_id)
        and item.get("protocol_version") == PAIRING_V3_PROTOCOL
        and item.get("auth_state") == "v3_active"
        and item.get("state") == "active"
        and item.get("binding_status") == "bound"
        and not bool_value(item.get("revoked"), False)
    ]
    if connectors:
        return connectors
    return (
        _direct_home_connectors_for_profile(profile_id)
        if context["role"] == CanonicalRole.OWNER.value
        else []
    )


def create_pairing_record(profile_id, connector_name, *, account_id="", household_id=""):
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
        "account_id": account_id,
        "household_id": household_id,
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
    if not legacy_app_sessions_allowed():
        return response(410, {"state": "legacy_session_flow_disabled"})
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
    if not legacy_app_sessions_allowed():
        return response(410, {"state": "legacy_session_flow_disabled"})
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
    now = utc_now_iso()
    try:
        activation = app_sessions_table.update_item(
            Key={"token_hash": activation_hash},
            ConditionExpression=(
                "record_type = :record_type AND #state = :awaiting "
                "AND expires_at >= :now_epoch"
            ),
            UpdateExpression="SET #state = :consumed, consumed_at = :now, expires_at = :consumed_expiry",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":record_type": "trial_activation",
                ":awaiting": "awaiting_plugin",
                ":consumed": "consumed",
                ":now": now,
                ":now_epoch": now_epoch,
                ":consumed_expiry": now_epoch + 60 * 60,
            },
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(401, {"state": "activation_invalid"})
        raise

    trial_expires_at = now_epoch + TRIAL_DURATION_SECONDS
    session_token = issue_app_session(
        profile_id,
        connector_id,
        activation.get("installation_id_hash"),
        trial_expires_at,
        "plugin_confirmed_trial"
    )

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
    if not legacy_app_sessions_allowed():
        raise RuntimeError("portable app sessions are disabled outside non-production environments")
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


def register_installation_v2(event):
    if installations_table is None:
        return response(503, {"state": "installation_storage_unavailable"})
    try:
        # This installation is bound to the caller's own active profile and
        # DPoP key. Household members need this narrow, fresh-auth path after
        # Profile Setup; owner-only device-management capabilities remain
        # unchanged.
        identity, _ = authoritative_identity(event, "register_own_device")
    except IdentityError as error:
        LOGGER.info(
            "installation_registration_denied stage=identity reason=%s status=%s",
            error.reason,
            error.status_code,
        )
        return identity_error_response(error)
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request"})
    installation_id = str(body.get("installation_id") or "").strip()
    device_id = str(body.get("device_id") or "").strip()
    device_label = str(body.get("device_label") or "Kaevo device").strip()[:64]
    device_class = str(body.get("device_class") or "mobile").strip().lower()[:32]
    if not SAFE_PLAYBACK_IDENTIFIER.fullmatch(installation_id) or not SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id):
        return response(400, {"state": "invalid_installation"})
    if not device_label or not re.fullmatch(r"[A-Za-z0-9 ._'()-]{1,64}", device_label):
        return response(400, {"state": "invalid_device_label"})
    if device_class not in {"mobile", "tablet", "desktop", "browser", "other"}:
        return response(400, {"state": "invalid_device_class"})
    try:
        public_jwk = validate_public_jwk(body.get("public_jwk") or {})
        thumbprint = jwk_thumbprint(public_jwk)
        verify_dpop(
            str(header_value(event, "dpop") or ""),
            method=method_for(event),
            url=request_absolute_url(event),
            expected_thumbprint=thumbprint,
            replay_guard=record_dpop_jti,
        )
    except IdentityError as error:
        LOGGER.info(
            "installation_registration_denied stage=dpop reason=%s status=%s",
            error.reason,
            error.status_code,
        )
        denial = prepare_security_audit(
            event, identity.household_id, "dpop_proof_denied", identity.subject,
            target_id=installation_id, target_type="installation",
            result="denied", reason_code=error.reason, containment=True,
        )
        commit_security_audit(denial, containment=True)
        return identity_error_response(error)
    try:
        audit = prepare_security_audit(
            event, identity.household_id, "installation_registered", identity.subject,
            target_id=installation_id, target_type="installation",
        )
    except AuditReferenceError:
        LOGGER.warning("installation_registration_denied stage=audit_reference")
        return audit_unavailable_response()
    now = epoch_now()
    item = {
        "installation_id": installation_id,
        "device_id": device_id,
        "management_handle": secrets.token_urlsafe(24),
        "device_label": device_label,
        "device_class": device_class,
        "principal_id": identity.subject,
        "account_id": identity.account_id,
        "household_id": identity.household_id,
        "public_jwk_json": json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
        "key_thumbprint": thumbprint,
        "state": "active",
        "revoked": False,
        "created_at_epoch": now,
        "created_at": utc_now_iso(),
        "last_seen_at": utc_now_iso(),
    }
    try:
        installations_table.put_item(Item=item, ConditionExpression="attribute_not_exists(installation_id)")
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            LOGGER.error(
                "installation_registration_storage_failure code=%s",
                str(error.response.get("Error", {}).get("Code") or "unknown")[:80],
            )
            return response(503, {"state": "installation_storage_unavailable"})
        existing = installations_table.get_item(Key={"installation_id": installation_id}, ConsistentRead=True).get("Item")
        same_principal = bool(existing) and hmac.compare_digest(
            str(existing.get("principal_id") or ""), str(item.get("principal_id") or "")
        )
        same_device = bool(existing) and hmac.compare_digest(
            str(existing.get("device_id") or ""), str(item.get("device_id") or "")
        )
        if not same_principal or existing.get("state") != "active":
            LOGGER.warning(
                "installation_registration_conflict_scope principal_match=%s device_match=%s state_active=%s",
                bool(existing) and hmac.compare_digest(
                    str(existing.get("principal_id") or ""), str(item.get("principal_id") or "")
                ),
                bool(existing) and hmac.compare_digest(
                    str(existing.get("device_id") or ""), str(item.get("device_id") or "")
                ),
                bool(existing) and existing.get("state") == "active",
            )
            return response(409, {"state": "installation_binding_conflict"})
        same_key = hmac.compare_digest(
            str(existing.get("key_thumbprint") or ""),
            str(item.get("key_thumbprint") or ""),
        )
        same_authority = all(
            hmac.compare_digest(str(existing.get(key) or ""), str(item.get(key) or ""))
            for key in ("account_id", "household_id")
        )
        if same_key and same_device and same_authority:
            item = existing
        else:
            # A Secure Enclave/Keychain replacement can leave the stable local
            # installation identifier paired with a new signing key. Fresh
            # authenticated DPoP already proved possession of that new key.
            # Rotate only the exact active row owned by this same principal and
            # physical device. Current server-owned account and household
            # authority replace stale pre-migration values on that row; every
            # cross-identity or cross-device collision remains a conflict.
            replacement = dict(existing)
            replacement["account_id"] = item["account_id"]
            replacement["household_id"] = item["household_id"]
            replacement["device_id"] = item["device_id"]
            replacement["device_label"] = item["device_label"]
            replacement["device_class"] = item["device_class"]
            replacement["public_jwk_json"] = item["public_jwk_json"]
            replacement["key_thumbprint"] = item["key_thumbprint"]
            replacement["last_seen_at"] = item["last_seen_at"]
            replacement["key_rotated_at"] = item["last_seen_at"]
            try:
                installations_table.update_item(
                    Key={"installation_id": installation_id},
                    UpdateExpression=(
                        "SET #account = :account, #household = :household, #device = :device, "
                        "#device_label = :device_label, #device_class = :device_class, "
                        "#jwk = :jwk, #thumbprint = :thumbprint, "
                        "#last_seen = :last_seen, #rotated = :rotated"
                    ),
                    ConditionExpression=(
                        "#state = :active AND #principal = :principal"
                    ),
                    ExpressionAttributeNames={
                        "#state": "state",
                        "#principal": "principal_id",
                        "#device": "device_id",
                        "#device_label": "device_label",
                        "#device_class": "device_class",
                        "#account": "account_id",
                        "#household": "household_id",
                        "#jwk": "public_jwk_json",
                        "#thumbprint": "key_thumbprint",
                        "#last_seen": "last_seen_at",
                        "#rotated": "key_rotated_at",
                    },
                    ExpressionAttributeValues={
                        ":active": "active",
                        ":principal": identity.subject,
                        ":device": device_id,
                        ":device_label": item["device_label"],
                        ":device_class": item["device_class"],
                        ":account": identity.account_id,
                        ":household": identity.household_id,
                        ":jwk": item["public_jwk_json"],
                        ":thumbprint": item["key_thumbprint"],
                        ":last_seen": item["last_seen_at"],
                        ":rotated": item["last_seen_at"],
                    },
                )
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                    return response(409, {"state": "installation_binding_conflict"})
                LOGGER.error(
                    "installation_registration_storage_failure code=%s",
                    str(error.response.get("Error", {}).get("Code") or "unknown")[:80],
                )
                return response(503, {"state": "installation_storage_unavailable"})
            item = replacement
    commit_security_audit(audit)
    LOGGER.info("installation_registration_succeeded")
    return response(201, {
        "state": "installation_registered",
        "installation_id": installation_id,
        "device_id": device_id,
        "key_thumbprint": thumbprint,
    })


def issue_bound_session_v2(event):
    if app_sessions_table is None or installations_table is None:
        return response(503, {"state": "session_storage_unavailable"})
    try:
        identity, _ = authoritative_identity(event, "browse")
    except IdentityError as error:
        return identity_error_response(error)
    body = parse_json_body(event)
    installation_id = str((body or {}).get("installation_id") or "").strip()
    installation = installations_table.get_item(Key={"installation_id": installation_id}, ConsistentRead=True).get("Item")
    if not installation or installation.get("state") != "active" or bool_value(installation.get("revoked"), False):
        return response(404, {"state": "installation_not_found"})
    if not all(hmac.compare_digest(str(installation.get(key) or ""), expected) for key, expected in (
        ("principal_id", identity.subject), ("account_id", identity.account_id), ("household_id", identity.household_id)
    )):
        return response(404, {"state": "installation_not_found"})
    try:
        verify_dpop(
            str(header_value(event, "dpop") or ""),
            method=method_for(event),
            url=request_absolute_url(event),
            expected_thumbprint=str(installation.get("key_thumbprint") or ""),
            replay_guard=record_dpop_jti,
        )
    except IdentityError as error:
        denial = prepare_security_audit(
            event, identity.household_id, "dpop_proof_denied", identity.subject,
            target_id=installation_id, target_type="installation",
            result="denied", reason_code=error.reason, containment=True,
        )
        commit_security_audit(denial, containment=True)
        return identity_error_response(error)
    try:
        audit = prepare_security_audit(
            event, identity.household_id, "session_issued", identity.subject,
            target_id=installation_id, target_type="installation",
        )
    except AuditReferenceError:
        return audit_unavailable_response()
    if identity.profile_id:
        ensure_nonproduction_family_entitlement(identity.profile_id)
    access, refresh, access_token, refresh_token = new_session_material(identity, installation)
    app_sessions_table.put_item(Item=access)
    app_sessions_table.put_item(Item=refresh)
    commit_security_audit(audit)
    return response(201, {
        "state": "session_issued",
        # OAuth token_type protocol label, not a credential.
        "token_type": "DPoP",  # nosec B105
        "access_token": access_token,
        "access_expires_at": access["expires_at"],
        "refresh_token": refresh_token,
        "refresh_expires_at": refresh["expires_at"],
        "installation_id": installation_id,
    })


def revoke_session_family(family_id, reason):
    if app_sessions_table is None or not family_id:
        return 0
    records = app_sessions_table.query(
        IndexName="family_id-created_at_epoch-index",
        KeyConditionExpression=Key("family_id").eq(family_id),
    ).get("Items", [])
    now = epoch_now()
    for item in records:
        item["state"] = "revoked"
        item["revoked"] = True
        item["revoked_reason"] = reason
        item["revoked_at_epoch"] = now
        item["expires_at"] = min(int(item.get("expires_at") or now), now)
        app_sessions_table.put_item(Item=item)
    return len(records)


def refresh_bound_session_v2(event):
    if app_sessions_table is None or installations_table is None:
        return response(503, {"state": "session_storage_unavailable"})
    body = parse_json_body(event)
    refresh_token = str((body or {}).get("refresh_token") or "").strip()
    if not refresh_token:
        return response(400, {"state": "refresh_token_required"})
    key = f"refresh#{production_token_hash(refresh_token)}"
    record = app_sessions_table.get_item(Key={"token_hash": key}, ConsistentRead=True).get("Item")
    if not record:
        return response(401, {"state": "invalid_refresh"})
    if record.get("state") != "active":
        audit = prepare_security_audit(
            event, str(record.get("household_id") or ""), "refresh_reuse_detected",
            str(record.get("principal_id") or ""),
            target_id=str(record.get("installation_id") or ""), target_type="installation",
            result="denied", reason_code="refresh_token_reuse", containment=True,
        )
        revoke_session_family(str(record.get("family_id") or ""), "refresh_token_reuse")
        commit_security_audit(audit, containment=True)
        return response(401, {"state": "session_family_revoked"})
    installation_id = str(record.get("installation_id") or "")
    installation = installations_table.get_item(Key={"installation_id": installation_id}, ConsistentRead=True).get("Item")
    if not installation or installation.get("state") != "active" or bool_value(installation.get("revoked"), False):
        revoke_session_family(str(record.get("family_id") or ""), "installation_revoked")
        return response(401, {"state": "installation_revoked"})
    try:
        verify_dpop(
            str(header_value(event, "dpop") or ""),
            method=method_for(event),
            url=request_absolute_url(event),
            expected_thumbprint=str(record.get("key_thumbprint") or ""),
            replay_guard=record_dpop_jti,
        )
        access, next_refresh, access_token, next_refresh_token, consumed = rotate_refresh_record(record)
        app_sessions_table.put_item(
            Item=consumed,
            ConditionExpression="#state = :active",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":active": "active"},
        )
    except IdentityError as error:
        audit = prepare_security_audit(
            event, str(record.get("household_id") or ""), "dpop_proof_denied",
            str(record.get("principal_id") or ""), target_id=installation_id,
            target_type="installation", result="denied", reason_code=error.reason,
            containment=True,
        )
        commit_security_audit(audit, containment=True)
        return identity_error_response(error)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            audit = prepare_security_audit(
                event, str(record.get("household_id") or ""), "refresh_reuse_detected",
                str(record.get("principal_id") or ""), target_id=installation_id,
                target_type="installation", result="denied",
                reason_code="refresh_token_reuse", containment=True,
            )
            revoke_session_family(str(record.get("family_id") or ""), "refresh_token_reuse")
            commit_security_audit(audit, containment=True)
            return response(401, {"state": "session_family_revoked"})
        raise
    ensure_nonproduction_family_entitlement(str(record.get("profile_id") or ""))
    app_sessions_table.put_item(Item=access)
    app_sessions_table.put_item(Item=next_refresh)
    return response(200, {
        "state": "session_refreshed",
        # OAuth token_type protocol label, not a credential.
        "token_type": "DPoP",  # nosec B105
        "access_token": access_token,
        "access_expires_at": access["expires_at"],
        "refresh_token": next_refresh_token,
        "refresh_expires_at": next_refresh["expires_at"],
    })


def owner_bound_session(event):
    session = authenticated_app_session(event)
    # V3 is intentionally restricted to Owner Session Protected material.
    # In development, authenticated_app_session also recognizes legacy
    # app_session records for legacy routes. They must never authorize V3.
    if not session or session.get("record_type") != "access":
        return None, response(401, {"state": "owner_session_required"})
    if session.get("role") != "owner":
        return None, response(403, {"state": "owner_required"})
    return session, None


def household_manager_bound_session(event, *, verified_session=None):
    """Authorize Owner/Admin operations from live server-owned authority.

    The access token proves the principal and device binding. Household
    authority is read consistently from the active principal record so a
    stale or modified client cannot promote itself by changing local state.
    """
    session = verified_session or authenticated_app_session(event)
    if not session or session.get("record_type") != "access":
        return None, response(401, {"state": "household_manager_session_required"})
    if principals_table is None:
        return None, response(503, {"state": "identity_storage_unavailable"})
    principal_id = str(session.get("principal_id") or "")
    principal = principals_table.get_item(
        Key={"principal_id": principal_id},
        ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(principal, dict)
        or principal.get("state") != "active"
        or bool_value(principal.get("revoked"), False)
        or not hmac.compare_digest(
            str(principal.get("account_id") or ""),
            str(session.get("account_id") or ""),
        )
        or not hmac.compare_digest(
            str(principal.get("household_id") or ""),
            str(session.get("household_id") or ""),
        )
    ):
        return None, response(403, {"state": "household_manager_authority_missing"})
    canonical_name = str(principal.get("role") or "").strip().lower()
    access_name = str(
        principal.get("household_access_role") or (
            "owner" if canonical_name == "owner" else "member"
        )
    ).strip().lower()
    if (
        (canonical_name == "owner" and access_name != "owner")
        or (canonical_name != "owner" and access_name == "owner")
    ):
        return None, response(409, {"state": "household_authority_manual_review_required"})
    if access_name not in {"owner", "admin"}:
        return None, response(403, {"state": "household_manager_required"})
    authorized = dict(session)
    authorized["household_access_role"] = access_name
    return authorized, None


def social_provider_credentials(provider):
    canonical = canonical_social_provider(provider)
    secret_arn = (
        GOOGLE_IDENTITY_PROVIDER_SECRET_ARN
        if canonical == "google"
        else APPLE_IDENTITY_PROVIDER_SECRET_ARN
    )
    if not secret_arn:
        raise SocialIdentityError("identity_provider_unavailable", 503)
    cached = _social_provider_secret_cache.get(secret_arn)
    if cached is not None:
        return cached
    try:
        raw = secrets_client.get_secret_value(SecretId=secret_arn).get("SecretString")
        document = json.loads(str(raw or ""))
    except Exception as error:
        raise SocialIdentityError("identity_provider_unavailable", 503) from error
    required = {"client_id", "client_secret"} if canonical == "google" else {"client_id", "team_id", "key_id", "private_key"}
    if not isinstance(document, dict) or any(not str(document.get(key) or "").strip() for key in required):
        raise SocialIdentityError("identity_provider_unavailable", 503)
    minimized = {key: str(document[key]) for key in required}
    _social_provider_secret_cache[secret_arn] = minimized
    return minimized


def social_link_redirect(state):
    # The custom-scheme callback contains no provider subject, OAuth code,
    # token, email, account, household, or attempt identifier.
    return {
        "statusCode": 302,
        "headers": {
            "location": f"kaevo://oauth/social-link?state={state}",
            "cache-control": "no-store",
            "content-security-policy": "default-src 'none'",
            "referrer-policy": "no-referrer",
        },
        "body": "",
    }


def linked_social_providers(event):
    session, error_response = owner_bound_session(event)
    if error_response:
        return error_response
    if not COGNITO_USER_POOL_ID:
        return response(503, {"state": "identity_provider_unavailable"})
    try:
        username = resolve_cognito_username(
            cognito_client,
            user_pool_id=COGNITO_USER_POOL_ID,
            subject=str(session.get("principal_id") or ""),
        )
        user = cognito_client.admin_get_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)
        names = {str(item.get("providerName") or "") for item in parse_cognito_identities(user.get("UserAttributes") or [])}
        providers = [provider for provider, name in (("apple", "SignInWithApple"), ("google", "Google")) if name in names]
        return response(200, {"state": "social_identity_links", "providers": providers})
    except SocialIdentityError as error:
        return response(error.status_code, {"state": error.reason})
    except Exception:
        return response(503, {"state": "identity_provider_unavailable"})


def start_social_identity_link(event):
    session, error_response = owner_bound_session(event)
    if error_response:
        return error_response
    body = parse_json_body(event)
    if body is None or body.get("confirmed") is not True:
        return response(400, {"state": "explicit_confirmation_required"})
    if app_sessions_table is None or not COGNITO_USER_POOL_ID or not SOCIAL_IDENTITY_LINK_CALLBACK_URL:
        return response(503, {"state": "identity_provider_unavailable"})
    try:
        provider = canonical_social_provider(body.get("provider"))
        credentials = social_provider_credentials(provider)
        username = resolve_cognito_username(
            cognito_client,
            user_pool_id=COGNITO_USER_POOL_ID,
            subject=str(session.get("principal_id") or ""),
        )
        current = cognito_client.admin_get_user(UserPoolId=COGNITO_USER_POOL_ID, Username=username)
        if any(str(item.get("providerName") or "") == social_provider_name(provider) for item in parse_cognito_identities(current.get("UserAttributes") or [])):
            return response(409, {"state": "identity_provider_already_linked"})
        item, oauth_state = new_social_link_attempt(
            provider=provider,
            session=session,
            callback_url=SOCIAL_IDENTITY_LINK_CALLBACK_URL,
        )
        app_sessions_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(token_hash)",
        )
        url = social_authorization_url(
            provider,
            credentials,
            callback_url=SOCIAL_IDENTITY_LINK_CALLBACK_URL,
            state=oauth_state,
            nonce=str(item["oauth_nonce"]),
        )
        return response(201, {
            "state": "social_identity_authorization_required",
            "provider": provider,
            "authorization_url": url,
            "expires_at": int(item["expires_at"]),
        })
    except SocialIdentityError as error:
        return response(error.status_code, {"state": error.reason})
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, {"state": "social_identity_link_conflict"})
        return response(503, {"state": "identity_provider_unavailable"})
    except Exception:
        return response(503, {"state": "identity_provider_unavailable"})


def social_identity_link_callback(event):
    if app_sessions_table is None or not COGNITO_USER_POOL_ID:
        return social_link_redirect("failed")
    method = method_for(event)
    try:
        values = (
            decode_social_form_body(str(event.get("body") or ""), is_base64=bool(event.get("isBase64Encoded")))
            if method == "POST"
            else {key: str(value) for key, value in query_params(event).items()}
        )
        oauth_state = str(values.get("state") or "")
        code = str(values.get("code") or "")
        if not oauth_state or not code or values.get("error"):
            raise SocialIdentityError("invalid_identity_provider_response")
        key = social_state_key(oauth_state)
        item = app_sessions_table.get_item(Key={"token_hash": key}, ConsistentRead=True).get("Item")
        if not item or item.get("record_type") != "social_identity_link":
            raise SocialIdentityError("social_identity_link_expired", 410)
        if item.get("state") == "linked":
            return social_link_redirect("linked")
        if item.get("state") != "pending" or int(item.get("expires_at") or 0) < epoch_now():
            raise SocialIdentityError("social_identity_link_expired", 410)
        app_sessions_table.update_item(
            Key={"token_hash": key},
            UpdateExpression="SET #state = :exchanging",
            ConditionExpression="#state = :pending",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":pending": "pending", ":exchanging": "exchanging"},
        )
        provider = canonical_social_provider(item.get("provider"))
        credentials = social_provider_credentials(provider)
        identity_token = exchange_social_code(
            provider,
            credentials,
            code=code,
            callback_url=str(item.get("callback_url") or ""),
        )
        provider_identity = validate_social_identity_token(
            provider,
            identity_token,
            credentials,
            expected_nonce=str(item.get("oauth_nonce") or ""),
            key_resolver=resolve_social_signing_key,
        )
        # The audit record is durably committed before the external identity
        # mutation.  If audit storage is unavailable, the link is not made.
        audit = prepare_security_audit(
            event,
            str(item.get("household_id") or ""),
            "identity_provider_link_authorized",
            str(item.get("principal_id") or ""),
            target_id=provider_identity.subject,
            target_type="provider_subject",
            result="started",
        )
        commit_security_audit(audit)
        link_provider_identity(
            cognito_client,
            user_pool_id=COGNITO_USER_POOL_ID,
            destination_subject=str(item.get("principal_id") or ""),
            identity=provider_identity,
        )
        app_sessions_table.update_item(
            Key={"token_hash": key},
            UpdateExpression="SET #state = :linked, linked_at_epoch = :now REMOVE oauth_nonce, callback_url",
            ConditionExpression="#state = :exchanging",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":exchanging": "exchanging", ":linked": "linked", ":now": epoch_now()},
        )
        return social_link_redirect("linked")
    except Exception:
        # No exception text is logged or returned because OAuth/provider errors
        # can carry credential material.  A fresh explicit attempt is required.
        try:
            if 'key' in locals():
                app_sessions_table.update_item(
                    Key={"token_hash": key},
                    UpdateExpression="SET #state = :failed REMOVE oauth_nonce, callback_url",
                    ConditionExpression="#state = :exchanging",
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues={":exchanging": "exchanging", ":failed": "failed"},
                )
        except Exception:
            pass
        return social_link_redirect("failed")


# Pairing V3 is intentionally implemented beside, rather than inside, the
# legacy pairing handlers.  These helpers do not accept legacy credentials.
def pairing_v3_correlation_id(event):
    supplied = str(header_value(event, "x-kaevo-correlation-id") or "")
    try:
        return pairing_v3_canonical_uuid(supplied)
    except PairingV3CryptoError:
        return str(uuid.uuid4())


def pairing_v3_response(status_code, code, correlation_id, *, retryable=False, **extra):
    body = {
        "protocol": PAIRING_V3_PROTOCOL,
        "code": code,
        "retryable": bool(retryable),
        "correlationId": correlation_id,
        **extra,
    }
    result = response(status_code, body)
    result["headers"]["X-Kaevo-Correlation-Id"] = correlation_id
    return result


def pairing_v3_log(correlation_id, attempt_id, route, transition, status_code, outcome, *, aws_request_id=""):
    """Emit an allowlisted record only; no request/header/body value is logged."""
    record = {
        "event": "kaevo_pairing_v3",
        "timestamp": utc_now_iso(),
        "correlationId": correlation_id,
        # An attempt is linkable state, so retain only a one-way reference.
        "pairingAttemptRef": pairing_v3_key("v3_attempt_log", attempt_id),
        "route": route,
        "transition": transition,
        "httpStatus": int(status_code),
        "outcome": outcome,
    }
    if aws_request_id:
        record["awsRequestId"] = aws_request_id[:128]
    # Lambda's default Python logging threshold is WARNING.  This is the sole
    # V3 correlation record and contains only an allowlisted, redacted shape,
    # so emit it at that threshold rather than silently losing live proof.
    LOGGER.warning("%s", json.dumps(record, separators=(",", ":"), sort_keys=True))


def pairing_v3_key(prefix, value):
    return f"{prefix}#{secret_hash(value)}"


def pairing_v3_text(value, *, required=True, limit=256):
    result = str(value or "")
    if (required and not result) or len(result.encode("utf-8")) > limit or not SAFE_PAIRING_V3_OPAQUE_IDENTIFIER.fullmatch(result):
        raise PairingV3CryptoError("invalid pairing binding")
    return result


def pairing_v3_authorization_private_key():
    try:
        seed = pairing_v3_b64url_decode(PAIRING_V3_AUTHORIZATION_SIGNING_SEED)
    except PairingV3CryptoError as error:
        raise PairingV3CryptoError("pairing authorization signing key unavailable") from error
    if len(seed) != 32:
        raise PairingV3CryptoError("pairing authorization signing key unavailable")
    return seed


def pairing_v3_authorization_public_key():
    return ed25519_public_key_from_seed(pairing_v3_authorization_private_key())


def pairing_v3_authorization_claims(session, bindings, now):
    return {
        "iss": f"kaevo-cloud-{KAEVO_ENV}",
        "aud": AUTHORIZATION_AUDIENCE,
        "protocol": PAIRING_V3_PROTOCOL,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now - 5,
        "exp": now + PAIRING_V3_AUTHORIZATION_TTL_SECONDS,
        "sub": pairing_v3_sha256_b64url(str(session.get("principal_id") or "").encode("utf-8")),
        "accountBinding": pairing_v3_sha256_b64url(str(session.get("account_id") or "").encode("utf-8")),
        "familyBinding": pairing_v3_sha256_b64url(str(session.get("household_id") or "").encode("utf-8")),
        "ownerSessionProvenance": pairing_v3_sha256_b64url(str(session.get("family_id") or session.get("token_hash") or "").encode("utf-8")),
        "iosDeviceBinding": pairing_v3_sha256_b64url(bindings["ios_device_id"].encode("utf-8")),
        "pairingAttemptId": bindings["pairing_attempt_id"],
        "ticketId": bindings["ticket_id"],
        "pluginInstanceId": bindings["plugin_instance_id"],
        "pluginPublicKeyFingerprint": bindings["plugin_public_key_fingerprint"],
        "jellyfinServerId": bindings["jellyfin_server_id"],
        "jellyfinUserProvenance": pairing_v3_sha256_b64url(bindings["jellyfin_user_id"].encode("utf-8")),
        "entitlement": "cloud_enabled",
    }


def pairing_v3_bindings(body, session):
    if not isinstance(body, dict) or body.get("protocol") != PAIRING_V3_PROTOCOL:
        raise PairingV3CryptoError("invalid pairing protocol")
    attempt_id = pairing_v3_canonical_uuid(str(body.get("pairingAttemptId") or ""))
    values = {
        "pairing_attempt_id": attempt_id,
        "ticket_id": pairing_v3_text(body.get("ticketId")),
        "plugin_instance_id": pairing_v3_text(body.get("pluginInstanceId")),
        "jellyfin_server_id": pairing_v3_text(body.get("jellyfinServerId")),
        "jellyfin_user_id": pairing_v3_text(body.get("jellyfinUserId")),
        "ios_device_id": pairing_v3_text(body.get("iosDeviceId")),
        "plugin_public_key_fingerprint": str(body.get("pluginPublicKeyFingerprint") or ""),
    }
    if not SAFE_PAIRING_V3_FINGERPRINT.fullmatch(values["plugin_public_key_fingerprint"]):
        raise PairingV3CryptoError("invalid plugin fingerprint")
    if not pairing_v3_constant_time_equal(values["ios_device_id"], str(session.get("device_id") or "")):
        raise PairingV3CryptoError("device binding mismatch")
    return values


def pairing_v3_entitled(session):
    entitlement, _ = load_entitlements_for_profile(str(session.get("profile_id") or ""))
    return bool_value(entitlement.get("cloud_enabled"), False)


def pairing_v3_audit_item(correlation_id, attempt_id, route, transition, status_code, outcome, now):
    return {
        "token_hash": pairing_v3_key("v3_audit", f"{attempt_id}:{transition}:{now}"),
        "record_type": "pairing_v3_audit",
        "correlation_id": correlation_id,
        "pairing_attempt_ref": pairing_v3_key("v3_attempt_audit", attempt_id),
        "route": route,
        "transition": transition,
        "http_status": int(status_code),
        "outcome": outcome,
        "created_at": utc_now_iso(),
        "expires_at": now + PAIRING_V3_AUDIT_RETENTION_SECONDS,
    }


def issue_home_connector_pairing_authorization_v3(event):
    route = "/v3/home-connectors/pairing/authorizations"
    correlation_id = pairing_v3_correlation_id(event)
    session, error_response = owner_bound_session(event)
    if error_response:
        try:
            owner_error = json.loads(str(error_response.get("body") or "{}"))
        except json.JSONDecodeError:
            owner_error = {}
        code = owner_error.get("state") if owner_error.get("state") in {"owner_session_required", "owner_required"} else "owner_session_required"
        pairing_v3_log(correlation_id, "none", route, "authorization_denied", error_response["statusCode"], code)
        return pairing_v3_response(error_response["statusCode"], code, correlation_id)
    try:
        bindings = pairing_v3_bindings(parse_json_body(event), session)
    except PairingV3CryptoError:
        pairing_v3_log(correlation_id, "none", route, "authorization_rejected", 400, "malformed_request")
        return pairing_v3_response(400, "malformed_request", correlation_id)
    if not pairing_v3_entitled(session):
        pairing_v3_log(correlation_id, bindings["pairing_attempt_id"], route, "authorization_denied", 403, "entitlement_required")
        return pairing_v3_response(403, "entitlement_required", correlation_id)
    if app_sessions_table is None:
        pairing_v3_log(correlation_id, bindings["pairing_attempt_id"], route, "authorization_failed", 503, "cloud_unavailable")
        return pairing_v3_response(503, "cloud_unavailable", correlation_id, retryable=True)
    now = epoch_now()
    try:
        claims = pairing_v3_authorization_claims(session, bindings, now)
        authorization = pairing_v3_sign_authorization(pairing_v3_authorization_private_key(), PAIRING_V3_AUTHORIZATION_KEY_ID, claims)
    except PairingV3CryptoError:
        pairing_v3_log(correlation_id, bindings["pairing_attempt_id"], route, "authorization_failed", 503, "pairing_dependency_failure")
        return pairing_v3_response(503, "pairing_dependency_failure", correlation_id, retryable=True)
    item = {
        "token_hash": pairing_v3_key("v3_authorization", claims["jti"]),
        "record_type": "pairing_v3_authorization",
        "state": "active",
        "authorization_jti_hash": secret_hash(claims["jti"]),
        "pairing_attempt_id": bindings["pairing_attempt_id"],
        "ticket_id": bindings["ticket_id"],
        "plugin_instance_id": bindings["plugin_instance_id"],
        "plugin_public_key_fingerprint": bindings["plugin_public_key_fingerprint"],
        "jellyfin_server_id": bindings["jellyfin_server_id"],
        "jellyfin_user_provenance": claims["jellyfinUserProvenance"],
        "account_binding": claims["accountBinding"],
        "family_binding": claims["familyBinding"],
        "ios_device_binding": claims["iosDeviceBinding"],
        "owner_session_provenance": claims["ownerSessionProvenance"],
        # Cloud-internal authoritative profile binding.  It is deliberately
        # not placed in the signed Pairing Authorization returned to iOS or
        # forwarded to the plugin.
        "profile_id": str(session.get("profile_id") or ""),
        # This is retained only in the Cloud-side authorization record.  The
        # signed QR never carries a household identifier.  Redemption uses it
        # to bind the *exact* authenticated profile to the exact Jellyfin user
        # selected by the administrator while rejecting cross-household or
        # already-owned identities before any connector state is changed.
        "household_id": str(session.get("household_id") or ""),
        "authorization_expires_at": claims["exp"],
        "created_at": utc_now_iso(),
        # The logical token expires in 60 seconds. This TTL retains its replay
        # and idempotency state for the approved 24-hour terminal window.
        "expires_at": now + PAIRING_V3_TERMINAL_RETENTION_SECONDS,
    }
    try:
        app_sessions_table.put_item(Item=item, ConditionExpression="attribute_not_exists(token_hash)")
        app_sessions_table.put_item(Item=pairing_v3_audit_item(correlation_id, bindings["pairing_attempt_id"], route, "authorization_issued", 201, "pairing_authorization_issued", now))
    except ClientError:
        pairing_v3_log(correlation_id, bindings["pairing_attempt_id"], route, "authorization_failed", 503, "cloud_unavailable")
        return pairing_v3_response(503, "cloud_unavailable", correlation_id, retryable=True)
    pairing_v3_log(correlation_id, bindings["pairing_attempt_id"], route, "authorization_issued", 201, "pairing_authorization_issued")
    return pairing_v3_response(201, "pairing_authorization_issued", correlation_id, authorization=authorization, expiresAt=claims["exp"])


def pairing_v3_verify_authorization_claims(authorization, now):
    verified = pairing_v3_verify_authorization(authorization, pairing_v3_authorization_public_key())
    claims = verified.claims
    required = ("iss", "aud", "protocol", "jti", "iat", "nbf", "exp", "pairingAttemptId", "ticketId",
                "pluginInstanceId", "pluginPublicKeyFingerprint", "jellyfinServerId", "jellyfinUserProvenance",
                "accountBinding", "familyBinding", "iosDeviceBinding", "ownerSessionProvenance")
    if any(not claims.get(key) for key in required):
        raise PairingV3CryptoError("authorization claims missing")
    if claims["iss"] != f"kaevo-cloud-{KAEVO_ENV}" or claims["aud"] != AUTHORIZATION_AUDIENCE or claims["protocol"] != PAIRING_V3_PROTOCOL:
        raise PairingV3CryptoError("authorization claims invalid")
    pairing_v3_canonical_uuid(str(claims["pairingAttemptId"]))
    if not isinstance(claims["nbf"], int) or not isinstance(claims["exp"], int) or claims["nbf"] > now or claims["exp"] <= now:
        raise PairingV3CryptoError("authorization expired")
    return verified


def pairing_v3_plugin_request(event, body, authorization_jti, operation):
    try:
        public_key = pairing_v3_b64url_decode(str(body.get("pluginPublicKey") or ""))
        if len(public_key) != 32:
            raise PairingV3CryptoError("invalid plugin key")
        plugin_instance_id = pairing_v3_text(body.get("pluginInstanceId"))
        pairing_attempt_id = pairing_v3_canonical_uuid(str(body.get("pairingAttemptId") or ""))
        jellyfin_server_id = pairing_v3_text(body.get("jellyfinServerId"))
        fingerprint = str(body.get("pluginPublicKeyFingerprint") or "")
        if not SAFE_PAIRING_V3_FINGERPRINT.fullmatch(fingerprint) or not pairing_v3_constant_time_equal(fingerprint, pairing_v3_plugin_fingerprint(public_key)):
            raise PairingV3CryptoError("plugin fingerprint mismatch")
        timestamp = str(header_value(event, "x-kaevo-plugin-timestamp") or "")
        if not re.fullmatch(r"\d{13}", timestamp) or abs((int(timestamp) // 1000) - epoch_now()) > PAIRING_V3_PLUGIN_TIMESTAMP_SKEW_SECONDS:
            raise PairingV3CryptoError("plugin timestamp invalid")
        nonce = str(header_value(event, "x-kaevo-plugin-nonce") or "")
        if not SAFE_PAIRING_V3_NONCE.fullmatch(nonce):
            raise PairingV3CryptoError("plugin nonce invalid")
        signature = str(header_value(event, "x-kaevo-plugin-signature") or "")
        method = method_for(event).upper()
        route = normalized_path(event)
        if operation == "redemption":
            transcript = pairing_v3_redemption_transcript(
                method=method, route=route, body_digest=pairing_v3_canonical_json_digest(body), timestamp=timestamp,
                nonce=nonce, pairing_attempt_id=pairing_attempt_id, authorization_jti=authorization_jti,
                plugin_instance_id=plugin_instance_id, plugin_public_key_fingerprint=fingerprint,
                jellyfin_server_id=jellyfin_server_id,
            )
        else:
            transcript = pairing_v3_canonical_transcript("attempt-status", (
                ("httpMethod", method), ("canonicalRoute", route), ("bodyDigest", pairing_v3_canonical_json_digest(body)),
                ("timestamp", timestamp), ("nonce", nonce), ("pairingAttemptId", pairing_attempt_id),
                ("authorizationJti", authorization_jti), ("pluginInstanceId", plugin_instance_id),
                ("pluginPublicKeyFingerprint", fingerprint), ("jellyfinServerId", jellyfin_server_id),
            ))
        pairing_v3_verify_ed25519(public_key, transcript, signature)
    except (PairingV3CryptoError, TypeError, ValueError) as error:
        raise PairingV3CryptoError("plugin request invalid") from error
    return {
        "public_key": public_key,
        "plugin_instance_id": plugin_instance_id,
        "pairing_attempt_id": pairing_attempt_id,
        "jellyfin_server_id": jellyfin_server_id,
        "fingerprint": fingerprint,
        "nonce": nonce,
        "timestamp": timestamp,
    }


def pairing_v3_transact_write(items):
    def encode(value):
        # ``dynamodb`` is a resource and its meta client applies the DynamoDB
        # attribute-value transformer. Passing already-serialized values here
        # would store an invalid nested map and breaks real transactions.
        return dict(value)

    def put(table_name, item, condition, values=None, names=None):
        value = {"TableName": table_name, "Item": encode(item)}
        if condition:
            value["ConditionExpression"] = condition
        if values:
            value["ExpressionAttributeValues"] = encode(values)
        if names:
            value["ExpressionAttributeNames"] = names
        return {"Put": value}

    def update(table_name, key, expression, condition, values=None, names=None):
        value = {"TableName": table_name, "Key": encode(key), "UpdateExpression": expression}
        if condition:
            value["ConditionExpression"] = condition
        if values:
            value["ExpressionAttributeValues"] = encode(values)
        if names:
            value["ExpressionAttributeNames"] = names
        return {"Update": value}

    dynamodb.meta.client.transact_write_items(TransactItems=[
        update(item["table"], item["key"], item["update_expression"], item.get("condition"), item.get("values"), item.get("names"))
        if item.get("kind") == "update" else
        put(item["table"], item["item"], item.get("condition"), item.get("values"), item.get("names")) for item in items
    ])


def pairing_v3_transaction_conflict(error):
    code = str((error.response or {}).get("Error", {}).get("Code") or "")
    return code in {"ConditionalCheckFailedException", "TransactionCanceledException"}


def pairing_v3_authorization_record(authorization_jti):
    return app_sessions_table.get_item(
        Key={"token_hash": pairing_v3_key("v3_authorization", authorization_jti)}, ConsistentRead=True,
    ).get("Item") if app_sessions_table else None


def pairing_v3_profile_jellyfin_binding_writes(authorization, connector, jellyfin_user_id):
    """Build exact profile binding writes for a V3 redemption or connector repair.

    The QR proof binds a concrete Jellyfin user to the authenticated Owner's
    profile.  It must become the canonical profile binding used by cellular
    metadata and playback.  This deliberately refuses display-name recovery,
    cross-household writes, and replacement of a different active binding.
    """
    if identity_profiles_table is None or home_connectors_table is None:
        return [], "profile_binding_unavailable"
    profile_id = str(authorization.get("profile_id") or "")
    expected_household_id = str(authorization.get("household_id") or "")
    connector_id = str((connector or {}).get("connector_id") or "")
    user_id = _normalized_jellyfin_user_id(jellyfin_user_id)
    if not profile_id or not expected_household_id or not connector_id or not user_id:
        return [], "profile_binding_unavailable"
    profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if (
        not isinstance(profile, dict)
        or str(profile.get("profile_id") or "") != profile_id
        or profile.get("state") != "active"
        or not hmac.compare_digest(str(profile.get("household_id") or ""), expected_household_id)
    ):
        return [], "profile_binding_target_missing"

    current_user_id = _normalized_jellyfin_user_id(profile.get("jellyfin_user_id"))
    current_connector_id = str(profile.get("jellyfin_connector_id") or "")
    if str(profile.get("jellyfin_binding_state") or "") == "active":
        if hmac.compare_digest(current_connector_id, connector_id) and current_user_id and hmac.compare_digest(current_user_id, user_id):
            # The exact edge already exists. Redemption remains idempotent and
            # no unnecessary profile mutation is performed.
            return [], None
        if not current_user_id or not hmac.compare_digest(current_user_id, user_id):
            return [], "profile_jellyfin_binding_conflict"

        # A plugin reinstallation receives a fresh key and connector ID. A
        # freshly signed Owner authorization may rotate that *household's*
        # connector only when it proves the same Owner/Jellyfin user on the
        # same server. Every existing profile bound to the retired connector is
        # migrated atomically while retaining its own immutable user ID.
        previous = home_connectors_table.get_item(
            Key={"connector_id": current_connector_id}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(previous, dict) or not (
            previous.get("protocol_version") == PAIRING_V3_PROTOCOL
            and previous.get("state") == "active"
            and previous.get("auth_state") == "v3_active"
            and not bool_value(previous.get("revoked"), False)
            and hmac.compare_digest(str(previous.get("account_binding") or ""), str(connector.get("account_binding") or ""))
            and hmac.compare_digest(str(previous.get("family_binding") or ""), str(connector.get("family_binding") or ""))
            and hmac.compare_digest(str(previous.get("jellyfin_server_id") or ""), str(connector.get("jellyfin_server_id") or ""))
        ):
            return [], "profile_jellyfin_binding_conflict"

        profile_updates = []
        profiles = _household_identity_profile_records(expected_household_id)
        # A Kaevo household is intentionally small. Refuse rather than risk a
        # non-atomic migration beyond DynamoDB's transaction limit.
        if len(profiles) > 16:
            return [], "household_connector_repair_too_large"
        for candidate in profiles:
            candidate_id = str(candidate.get("profile_id") or "")
            if candidate.get("state") != "active" or not candidate_id:
                continue
            if str(candidate.get("jellyfin_binding_state") or "") != "active":
                continue
            if not hmac.compare_digest(str(candidate.get("jellyfin_connector_id") or ""), current_connector_id):
                continue
            candidate_user_id = _normalized_jellyfin_user_id(candidate.get("jellyfin_user_id"))
            if not candidate_user_id:
                return [], "profile_jellyfin_binding_conflict"
            if candidate_id != profile_id and hmac.compare_digest(candidate_user_id, user_id):
                return [], "jellyfin_identity_already_bound"
            profile_updates.append({
                "kind": "update",
                "table": identity_profiles_table.name,
                "key": {"profile_id": candidate_id},
                "update_expression": (
                    "SET jellyfin_connector_id = :connector_id, jellyfin_binding_updated_at = :updated_at"
                ),
                "condition": (
                    "#state = :profile_active AND household_id = :household_id AND "
                    "jellyfin_binding_state = :binding_state AND jellyfin_connector_id = :previous_connector_id AND "
                    "attribute_exists(jellyfin_user_id)"
                ),
                "names": {"#state": "state"},
                "values": {
                    ":profile_active": "active", ":household_id": expected_household_id,
                    ":binding_state": "active", ":previous_connector_id": current_connector_id,
                    ":connector_id": connector_id, ":updated_at": utc_now_iso(),
                },
            })
        if not profile_updates:
            return [], "profile_jellyfin_binding_conflict"
        profile_updates.append({
            "kind": "update",
            "table": home_connectors_table.name,
            "key": {"connector_id": current_connector_id},
            "update_expression": "SET #state = :retired, auth_state = :retired_auth, revoked = :revoked, revoked_at = :revoked_at",
                "condition": "#state = :active AND auth_state = :active_auth AND (attribute_not_exists(revoked) OR revoked = :not_revoked)",
            "names": {"#state": "state"},
            "values": {
                ":active": "active", ":active_auth": "v3_active", ":not_revoked": False,
                ":retired": "retired", ":retired_auth": "v3_retired", ":revoked": True,
                ":revoked_at": utc_now_iso(),
            },
        })
        return profile_updates, None

    # A provider identity may belong to only one active canonical profile in a
    # household. This uses membership Query + exact profile gets; never Scan.
    for other in _household_identity_profile_records(expected_household_id):
        other_id = str(other.get("profile_id") or "")
        if other_id == profile_id or other.get("state") != "active":
            continue
        if (
            str(other.get("jellyfin_binding_state") or "") == "active"
            and hmac.compare_digest(str(other.get("jellyfin_connector_id") or ""), connector_id)
            and hmac.compare_digest(_normalized_jellyfin_user_id(other.get("jellyfin_user_id")), user_id)
        ):
            return [], "jellyfin_identity_already_bound"

    return [{
        "kind": "update",
        "table": identity_profiles_table.name,
        "key": {"profile_id": profile_id},
        "update_expression": (
            "SET jellyfin_connector_id = :connector_id, jellyfin_user_id = :user_id, "
            "jellyfin_binding_state = :binding_state, jellyfin_binding_updated_at = :updated_at"
        ),
        # A raced update may only be the exact idempotent mapping. Any other
        # active edge fails the redemption transaction rather than overwriting
        # identity state.
        "condition": (
            "#state = :profile_active AND household_id = :household_id AND "
            "(attribute_not_exists(jellyfin_binding_state) OR jellyfin_binding_state <> :binding_state "
            "OR (jellyfin_connector_id = :connector_id AND jellyfin_user_id = :user_id))"
        ),
        "names": {"#state": "state"},
        "values": {
            ":profile_active": "active",
            ":household_id": expected_household_id,
            ":connector_id": connector_id,
            ":user_id": user_id,
            ":binding_state": "active",
            ":updated_at": utc_now_iso(),
        },
    }], None


def redeem_home_connector_pairing_v3(event):
    route = "/v3/home-connectors/pairing/redemptions"
    correlation_id = pairing_v3_correlation_id(event)
    body = parse_json_body(event)
    if not isinstance(body, dict) or body.get("protocol") != PAIRING_V3_PROTOCOL:
        pairing_v3_log(correlation_id, "none", route, "redemption_rejected", 400, "malformed_request")
        return pairing_v3_response(400, "malformed_request", correlation_id)
    if app_sessions_table is None or home_connectors_table is None or identity_profiles_table is None:
        pairing_v3_log(correlation_id, "none", route, "redemption_failed", 503, "cloud_unavailable")
        return pairing_v3_response(503, "cloud_unavailable", correlation_id, retryable=True)
    now = epoch_now()
    try:
        verified = pairing_v3_verify_authorization_claims(str(body.get("authorization") or ""), now)
        claims = verified.claims
        request = pairing_v3_plugin_request(event, body, str(claims["jti"]), "redemption")
        jellyfin_user_id = pairing_v3_text(body.get("jellyfinUserId"))
        plugin_key_id = pairing_v3_text(body.get("pluginKeyId"), limit=32)
    except PairingV3CryptoError:
        pairing_v3_log(correlation_id, "none", route, "redemption_rejected", 422, "invalid_pairing_authorization")
        return pairing_v3_response(422, "invalid_pairing_authorization", correlation_id)
    attempt_id = request["pairing_attempt_id"]
    expected = (
        ("pairingAttemptId", attempt_id), ("ticketId", str(body.get("ticketId") or "")),
        ("pluginInstanceId", request["plugin_instance_id"]), ("pluginPublicKeyFingerprint", request["fingerprint"]),
        ("jellyfinServerId", request["jellyfin_server_id"]),
        ("jellyfinUserProvenance", pairing_v3_sha256_b64url(jellyfin_user_id.encode("utf-8"))),
    )
    if any(not pairing_v3_constant_time_equal(str(claims.get(key) or ""), value) for key, value in expected):
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 403, "binding_mismatch")
        return pairing_v3_response(403, "binding_mismatch", correlation_id)
    authorization = pairing_v3_authorization_record(str(claims["jti"]))
    if not authorization or authorization.get("record_type") != "pairing_v3_authorization":
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 422, "invalid_pairing_authorization")
        return pairing_v3_response(422, "invalid_pairing_authorization", correlation_id)
    nonce_key = pairing_v3_key("v3_nonce", f"{request['plugin_instance_id']}:{request['nonce']}")
    if app_sessions_table.get_item(Key={"token_hash": nonce_key}, ConsistentRead=True).get("Item"):
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 409, "plugin_nonce_replayed")
        return pairing_v3_response(409, "plugin_nonce_replayed", correlation_id)
    if authorization.get("state") != "active":
        attempt = app_sessions_table.get_item(Key={"token_hash": pairing_v3_key("v3_attempt", f"{request['plugin_instance_id']}:{attempt_id}")}, ConsistentRead=True).get("Item")
        if attempt and pairing_v3_constant_time_equal(str(attempt.get("authorization_jti_hash") or ""), secret_hash(str(claims["jti"]))):
            pairing_v3_log(correlation_id, attempt_id, route, "redemption_idempotent", 200, "pairing_redeemed")
            return pairing_v3_response(200, "pairing_redeemed", correlation_id, connectorId=attempt.get("connector_id"), idempotent=True)
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 409, "pairing_authorization_redeemed")
        return pairing_v3_response(409, "pairing_authorization_redeemed", correlation_id)
    if int(authorization.get("authorization_expires_at") or 0) < now:
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 410, "pairing_authorization_expired")
        return pairing_v3_response(410, "pairing_authorization_expired", correlation_id)
    stored = (
        ("pairing_attempt_id", attempt_id), ("ticket_id", str(claims["ticketId"])),
        ("plugin_instance_id", request["plugin_instance_id"]), ("plugin_public_key_fingerprint", request["fingerprint"]),
        ("jellyfin_server_id", request["jellyfin_server_id"]),
        ("jellyfin_user_provenance", str(claims["jellyfinUserProvenance"])),
    )
    if any(not pairing_v3_constant_time_equal(str(authorization.get(key) or ""), value) for key, value in stored):
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 403, "binding_mismatch")
        return pairing_v3_response(403, "binding_mismatch", correlation_id)
    attempt_key = pairing_v3_key("v3_attempt", f"{request['plugin_instance_id']}:{attempt_id}")
    if app_sessions_table.get_item(Key={"token_hash": attempt_key}, ConsistentRead=True).get("Item"):
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 409, "pairing_authorization_redeemed")
        return pairing_v3_response(409, "pairing_authorization_redeemed", correlation_id)
    binding_key_v3 = pairing_v3_key("v3_plugin", request["plugin_instance_id"])
    binding = home_connectors_table.get_item(Key={"connector_id": binding_key_v3}, ConsistentRead=True).get("Item")
    existing_connector_binding = binding is not None
    connector = None
    if binding:
        if any(not pairing_v3_constant_time_equal(str(binding.get(key) or ""), value) for key, value in (
            ("plugin_public_key_fingerprint", request["fingerprint"]), ("jellyfin_server_id", request["jellyfin_server_id"]),
            ("account_binding", str(claims["accountBinding"])),
        )) or binding.get("state") != "active":
            pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 403, "binding_mismatch")
            return pairing_v3_response(403, "binding_mismatch", correlation_id)
        connector = home_connectors_table.get_item(Key={"connector_id": str(binding.get("active_connector_id") or "")}, ConsistentRead=True).get("Item")
        if not connector:
            pairing_v3_log(correlation_id, attempt_id, route, "redemption_failed", 503, "pairing_status_pending")
            return pairing_v3_response(202, "pairing_status_pending", correlation_id, retryable=True)
    else:
        connector_id = f"v3_{uuid.uuid4()}"
        connector = {
            "connector_id": connector_id, "protocol_version": PAIRING_V3_PROTOCOL, "state": "active", "auth_state": "v3_active",
            "plugin_instance_id": request["plugin_instance_id"], "plugin_public_key": pairing_v3_b64url_encode(request["public_key"]),
            "plugin_public_key_fingerprint": request["fingerprint"], "plugin_key_id": plugin_key_id,
            "server_id": request["jellyfin_server_id"],
            "jellyfin_server_id": request["jellyfin_server_id"], "jellyfin_user_provenance": claims["jellyfinUserProvenance"],
            "account_binding": claims["accountBinding"], "family_binding": claims["familyBinding"],
            "ios_device_binding": claims["iosDeviceBinding"], "owner_session_provenance": claims["ownerSessionProvenance"],
            "profile_id": str(authorization.get("profile_id") or ""),
            "paired_at": utc_now_iso(), "last_contact_at": utc_now_iso(), "revoked": False,
        }
    profile_binding_writes, profile_binding_error = pairing_v3_profile_jellyfin_binding_writes(
        authorization, connector, jellyfin_user_id,
    )
    if profile_binding_error:
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_rejected", 409, profile_binding_error)
        return pairing_v3_response(409, profile_binding_error, correlation_id)
    nonce_item = {
        "token_hash": nonce_key,
        "record_type": "pairing_v3_plugin_nonce", "expires_at": now + PAIRING_V3_TERMINAL_RETENTION_SECONDS,
    }
    attempt = {
        "token_hash": attempt_key, "record_type": "pairing_v3_attempt", "state": "redeemed",
        "pairing_attempt_id": attempt_id, "authorization_jti_hash": secret_hash(str(claims["jti"])),
        "plugin_instance_id": request["plugin_instance_id"], "plugin_public_key_fingerprint": request["fingerprint"],
        "connector_id": connector["connector_id"], "created_at": utc_now_iso(),
        "expires_at": now + PAIRING_V3_TERMINAL_RETENTION_SECONDS,
    }
    writes = [
        {"table": app_sessions_table.name, "item": nonce_item, "condition": "attribute_not_exists(token_hash)"},
        {"kind": "update", "table": app_sessions_table.name, "key": {"token_hash": authorization["token_hash"]},
         "update_expression": "SET #state = :redeemed, redeemed_at = :redeemed_at",
         "condition": "#state = :active", "names": {"#state": "state"},
         "values": {":active": "active", ":redeemed": "redeemed", ":redeemed_at": utc_now_iso()}},
        {"table": app_sessions_table.name, "item": attempt, "condition": "attribute_not_exists(token_hash)"},
        {"table": app_sessions_table.name, "item": pairing_v3_audit_item(correlation_id, attempt_id, route, "authorization_redeemed", 201, "pairing_redeemed", now), "condition": "attribute_not_exists(token_hash)"},
    ]
    if binding is None:
        binding = {
            "connector_id": binding_key_v3, "record_type": "pairing_v3_plugin_binding", "state": "active",
            "active_connector_id": connector["connector_id"], "plugin_instance_id": request["plugin_instance_id"],
            "plugin_public_key_fingerprint": request["fingerprint"], "jellyfin_server_id": request["jellyfin_server_id"],
            "account_binding": claims["accountBinding"], "created_at": utc_now_iso(),
        }
        writes.extend((
            {"table": home_connectors_table.name, "item": connector, "condition": "attribute_not_exists(connector_id)"},
            {"table": home_connectors_table.name, "item": binding, "condition": "attribute_not_exists(connector_id)"},
        ))
    writes.extend(profile_binding_writes)
    try:
        pairing_v3_transact_write(writes)
    except ClientError as error:
        if not pairing_v3_transaction_conflict(error):
            pairing_v3_log(correlation_id, attempt_id, route, "redemption_failed", 503, "cloud_unavailable")
            return pairing_v3_response(503, "cloud_unavailable", correlation_id, retryable=True)
        pairing_v3_log(correlation_id, attempt_id, route, "redemption_conflict", 409, "pairing_authorization_redeemed")
        return pairing_v3_response(409, "pairing_authorization_redeemed", correlation_id)
    pairing_v3_log(correlation_id, attempt_id, route, "authorization_redeemed", 201, "pairing_redeemed")
    return pairing_v3_response(201, "pairing_redeemed", correlation_id, connectorId=connector["connector_id"], idempotent=existing_connector_binding)


def pairing_attempt_status_v3(event, path):
    route = "/v3/home-connectors/pairing/attempts/{pairingAttemptId}"
    correlation_id = pairing_v3_correlation_id(event)
    attempt_id = path.removeprefix("/v3/home-connectors/pairing/attempts/").strip()
    body = parse_json_body(event)
    if not isinstance(body, dict) or body.get("protocol") != PAIRING_V3_PROTOCOL:
        return pairing_v3_response(400, "malformed_request", correlation_id)
    try:
        attempt_id = pairing_v3_canonical_uuid(attempt_id)
        authorization_jti = pairing_v3_text(body.get("authorizationJti"))
        request = pairing_v3_plugin_request(event, body, authorization_jti, "attempt-status")
    except PairingV3CryptoError:
        return pairing_v3_response(422, "invalid_pairing_authorization", correlation_id)
    if request["pairing_attempt_id"] != attempt_id or app_sessions_table is None:
        return pairing_v3_response(403, "binding_mismatch", correlation_id)
    nonce = {"token_hash": pairing_v3_key("v3_nonce", f"{request['plugin_instance_id']}:{request['nonce']}"), "record_type": "pairing_v3_plugin_nonce", "expires_at": epoch_now() + PAIRING_V3_TERMINAL_RETENTION_SECONDS}
    try:
        app_sessions_table.put_item(Item=nonce, ConditionExpression="attribute_not_exists(token_hash)")
    except ClientError:
        return pairing_v3_response(409, "pairing_authorization_redeemed", correlation_id)
    attempt = app_sessions_table.get_item(Key={"token_hash": pairing_v3_key("v3_attempt", f"{request['plugin_instance_id']}:{attempt_id}")}, ConsistentRead=True).get("Item")
    if not attempt:
        pairing_v3_log(correlation_id, attempt_id, route, "status_pending", 202, "pairing_status_pending")
        return pairing_v3_response(202, "pairing_status_pending", correlation_id, retryable=True)
    if not pairing_v3_constant_time_equal(str(attempt.get("authorization_jti_hash") or ""), secret_hash(authorization_jti)) or not pairing_v3_constant_time_equal(str(attempt.get("plugin_public_key_fingerprint") or ""), request["fingerprint"]):
        return pairing_v3_response(403, "binding_mismatch", correlation_id)
    pairing_v3_log(correlation_id, attempt_id, route, "status_redeemed", 200, "pairing_redeemed")
    return pairing_v3_response(200, "pairing_redeemed", correlation_id, connectorId=attempt.get("connector_id"), idempotent=True)


def _gateway_jwt_claims(event):
    authorizer = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {})
    claims = authorizer.get("claims")
    return claims if isinstance(claims, dict) else {}


def _join_code_hash(code):
    normalized = re.sub(r"[^A-Z0-9]", "", str(code or "").upper())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest() if normalized else ""


def _opaque_join_resume_hash(handle):
    value = str(handle or "")
    if not re.fullmatch(r"jr_[A-Za-z0-9_-]{32,128}", value):
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _join_binding_hash(value):
    text = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,256}", text):
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _join_correlation_hash(value):
    text = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", text):
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _join_email_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalized_join_email(value):
    email = str(value or "").strip().casefold()
    if not re.fullmatch(r"[^\s@]{1,64}@[^\s@]{1,255}", email):
        return ""
    return email


def _invitation_code_from_join_payload(body):
    value = str(body.get("invitation") or body.get("join_code") or "").strip()
    if value.lower().startswith("kaevo://"):
        parts = urlsplit(value)
        if parts.scheme != "kaevo" or parts.netloc != "join":
            return ""
        value = parse_qs(parts.query, keep_blank_values=True).get("code", [""])[0]
    return value


def _household_join_transaction(item):
    return {
        "join_resume_hash": str(item.get("join_resume_hash") or ""),
        "entity_type": "HouseholdJoinResume",
        "invitation_code_hash": str(item.get("invitation_code_hash") or ""),
        "invitation_id": str(item.get("invitation_id") or ""),
        "device_binding_hash": str(item.get("device_binding_hash") or ""),
        "correlation_hash": str(item.get("correlation_hash") or ""),
        "state": str(item.get("state") or "initiated"),
        "created_at": str(item.get("created_at") or ""),
        "expires_at": int(item.get("expires_at") or 0),
        "schema_version": 1,
    }


def _join_route_error(state, status=400, retryable=False):
    return response(status, {"state": state, "retryable": retryable})


def _consume_household_join_rate_limit(device_binding_hash, correlation_hash, now):
    """Rate-limit join routing without retaining an IP address or raw device ID."""
    if household_join_transactions_table is None:
        return False
    # A ten-minute, hashed device+correlation bucket permits the normal
    # invitation -> routing sequence while limiting automated enumeration.
    bucket = now // (10 * 60)
    rate_key = hashlib.sha256(
        f"household-join-rate:{device_binding_hash}:{correlation_hash}:{bucket}".encode("utf-8")
    ).hexdigest()
    try:
        household_join_transactions_table.update_item(
            Key={"join_resume_hash": f"rate_{rate_key}"},
            UpdateExpression=(
                "SET attempts = if_not_exists(attempts, :zero) + :one, "
                "expires_at = :expires_at, cleanup_at = :cleanup_at, entity_type = :entity_type"
            ),
            ConditionExpression="attribute_not_exists(attempts) OR attempts < :maximum",
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":maximum": HOUSEHOLD_JOIN_MAX_ATTEMPTS,
                ":expires_at": (bucket + 1) * (10 * 60),
                ":cleanup_at": now + HOUSEHOLD_JOIN_TRANSACTION_RETENTION_SECONDS,
                ":entity_type": "HouseholdJoinRateLimit",
            },
        )
        return True
    except ClientError:
        return False


def begin_household_join(event):
    """Validate a family invitation without accepting membership or reading email."""
    if household_invitations_table is None or household_join_transactions_table is None:
        return _join_route_error("household_join_unavailable", 503, True)
    body = parse_json_body(event) or {}
    code_hash = _join_code_hash(_invitation_code_from_join_payload(body))
    device_binding_hash = _join_binding_hash(body.get("installation_id"))
    correlation_hash = _join_correlation_hash(body.get("correlation_nonce"))
    if not code_hash or not device_binding_hash or not correlation_hash:
        return _join_route_error("household_join_invalid_request")
    now = epoch_now()
    if not _consume_household_join_rate_limit(device_binding_hash, correlation_hash, now):
        return _join_route_error("household_join_retry_later", 429, True)
    invitation = household_invitations_table.get_item(Key={"code_hash": code_hash}, ConsistentRead=True).get("Item")
    if not invitation or str(invitation.get("state") or "") != "pending":
        return _join_route_error("invitation_invalid_or_expired", 410)
    if household_invitation_code_expiration(invitation) <= now:
        return _join_route_error("invitation_invalid_or_expired", 410)
    # The invitation schema is server-created. A connector QR has no pending
    # invitation record and therefore never reaches this transaction path.
    handle = f"jr_{secrets.token_urlsafe(32)}"
    record = _household_join_transaction({
        "join_resume_hash": _opaque_join_resume_hash(handle),
        "invitation_code_hash": code_hash,
        "invitation_id": str(invitation.get("invitation_id") or ""),
        "device_binding_hash": device_binding_hash,
        "correlation_hash": correlation_hash,
        "state": "initiated",
        "created_at": utc_now_iso(),
        "expires_at": now + HOUSEHOLD_JOIN_TRANSACTION_TTL_SECONDS,
    })
    record["cleanup_at"] = now + HOUSEHOLD_JOIN_TRANSACTION_RETENTION_SECONDS
    try:
        household_join_transactions_table.put_item(
            Item=record, ConditionExpression="attribute_not_exists(join_resume_hash)"
        )
    except ClientError:
        return _join_route_error("household_join_unavailable", 503, True)
    return response(201, {
        "state": "household_join_ready",
        "join_resume_handle": handle,
        "expires_at": record["expires_at"],
        "next": "collect_email",
    })


def _cognito_user_exists(email):
    if not COGNITO_USER_POOL_ID:
        raise RuntimeError("Cognito user pool unavailable")
    escaped = email.replace("\\", "\\\\").replace('"', '\\"')
    result = cognito_client.list_users(
        UserPoolId=COGNITO_USER_POOL_ID, Filter=f'email = "{escaped}"', Limit=2,
    )
    return bool(result.get("Users") or [])


def route_household_join_auth(event):
    """Privately choose Cognito sign-in or signup for one bound invitation."""
    if household_join_transactions_table is None or not NATIVE_OIDC_AUTHORIZATION_ENDPOINT or not EXPECTED_NATIVE_CALLBACK_URI:
        return _join_route_error("household_join_unavailable", 503, True)
    body = parse_json_body(event) or {}
    handle_hash = _opaque_join_resume_hash(body.get("join_resume_handle"))
    device_binding_hash = _join_binding_hash(body.get("installation_id"))
    email = _normalized_join_email(body.get("email"))
    oauth_state = str(body.get("oauth_state") or "")
    code_challenge = str(body.get("code_challenge") or "")
    if not handle_hash or not device_binding_hash or not email or not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", oauth_state) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", code_challenge):
        return _join_route_error("household_join_invalid_request")
    item = household_join_transactions_table.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    now = epoch_now()
    if not item or int(item.get("expires_at") or 0) <= now:
        return _join_route_error("household_join_expired", 410)
    if not hmac.compare_digest(str(item.get("device_binding_hash") or ""), device_binding_hash):
        return _join_route_error("household_join_invalid_request", 403)
    if not _consume_household_join_rate_limit(device_binding_hash, str(item.get("correlation_hash") or ""), now):
        return _join_route_error("household_join_retry_later", 429, True)
    if str(item.get("state") or "") not in {"initiated", "auth_routing"}:
        return _join_route_error("household_join_not_resumable", 409)
    try:
        existing = _cognito_user_exists(email)
    except Exception:
        return _join_route_error("household_join_unavailable", 503, True)
    endpoint = NATIVE_OIDC_AUTHORIZATION_ENDPOINT.rstrip("/")
    if not existing:
        endpoint = endpoint.rsplit("/oauth2/authorize", 1)[0] + "/signup"
    query = urlencode({
        "client_id": os.environ.get("EXPECTED_NATIVE_CLIENT_ID", ""),
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": EXPECTED_NATIVE_CALLBACK_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": oauth_state,
        "login_hint": email,
    })
    if not os.environ.get("EXPECTED_NATIVE_CLIENT_ID", ""):
        return _join_route_error("household_join_unavailable", 503, True)
    try:
        household_join_transactions_table.update_item(
            Key={"join_resume_hash": handle_hash},
            UpdateExpression="SET #state = :state, auth_state_hash = :state_hash, email_hash = :email_hash, updated_at = :updated_at",
            ConditionExpression="#state IN (:initiated, :routing) AND expires_at > :now",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":state": "awaiting_callback", ":state_hash": hashlib.sha256(oauth_state.encode("utf-8")).hexdigest(),
                ":email_hash": _join_email_hash(email), ":updated_at": utc_now_iso(), ":initiated": "initiated", ":routing": "auth_routing", ":now": now,
            },
        )
    except ClientError:
        return _join_route_error("household_join_not_resumable", 409)
    return response(200, {"state": "household_join_auth_ready", "redirect_url": f"{endpoint}?{query}", "oauth_state": oauth_state, "expires_at": int(item["expires_at"])})


def ensure_nonproduction_family_entitlement(profile_id):
    """Grant the documented internal tester plan only outside production."""
    if KAEVO_ENV not in {"dev", "security-stage"} or entitlements_table is None or not profile_id:
        return None
    entitlement, _ = load_entitlements_for_profile(profile_id)
    if bool_value(entitlement.get("family_enabled"), False) and bool_value(entitlement.get("cloud_enabled"), False):
        return entitlement
    entitlement = {
        **DEFAULT_ENTITLEMENTS,
        "plan": "family",
        "subscription_state": "active",
        "cloud_enabled": True,
        "family_enabled": True,
        "family_seats": 6,
        "source": f"{KAEVO_ENV.replace('-', '_')}_owner_testing",
        "feature_flags": {
            "cloud_sync": True,
            "family_profiles": True,
            "household_participants": True,
            "household_playback_sync": True,
        },
    }
    timestamp = utc_now_iso()
    entitlements_table.put_item(Item={
        "profile_id": profile_id,
        "entitlements_json": json.dumps(entitlement, separators=(",", ":")),
        "created_at": timestamp,
        "updated_at": timestamp,
    })
    return entitlement


def household_invitation_code_expiration(invitation):
    return int(invitation.get("code_expires_at") or invitation.get("expires_at") or 0)


GUEST_PASS_RECORD_RETENTION_SECONDS = 30 * 24 * 60 * 60
GUEST_PASS_ACCESS_TOKEN_MAX_SECONDS = 60 * 24 * 60 * 60


def _guest_pass_owner_session(event):
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return None, error_response
    if str(session.get("household_access_role") or "").strip().lower() != "owner":
        return None, response(403, {"state": "owner_required"})
    return session, None


def _guest_pass_records(household_id):
    if guest_passes_table is None or not household_id:
        return []
    records = []
    query = {
        "IndexName": "household_id-created_at_epoch-index",
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ScanIndexForward": False,
    }
    while True:
        page = guest_passes_table.query(**query)
        for candidate in page.get("Items", []):
            if candidate.get("record_type") != "guest_pass":
                continue
            pass_id = str(candidate.get("pass_id") or "")
            if not pass_id:
                continue
            exact = guest_passes_table.get_item(
                Key={"pass_id": pass_id}, ConsistentRead=True,
            ).get("Item")
            if (
                isinstance(exact, dict)
                and hmac.compare_digest(str(exact.get("household_id") or ""), household_id)
            ):
                records.append(exact)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def create_guest_pass(event):
    session, error_response = _guest_pass_owner_session(event)
    if error_response:
        return error_response
    if guest_passes_table is None:
        return response(503, {"state": "guest_pass_storage_unavailable"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "invalid_guest_pass"})
    now = epoch_now()
    try:
        normalized = normalize_guest_pass_create_request(body, now=now)
    except GuestPassValidationError as error:
        return response(400, {"state": error.state})

    household_id = str(session.get("household_id") or "")
    source_profile_id = normalized["source_profile_id"]
    if identity_profiles_table is None:
        return response(503, {"state": "identity_storage_unavailable"})
    source_profile = identity_profiles_table.get_item(
        Key={"profile_id": source_profile_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(source_profile, dict)
        and source_profile.get("state") == "active"
        and hmac.compare_digest(str(source_profile.get("household_id") or ""), household_id)
    ):
        return response(404, {"state": "source_profile_not_found"})
    owner_profile = identity_profiles_table.get_item(
        Key={"profile_id": str(session.get("profile_id") or "")},
        ConsistentRead=True,
    ).get("Item")
    owner_display_name = (
        str(owner_profile.get("display_name") or "Owner").strip()[:50]
        if isinstance(owner_profile, dict)
        else "Owner"
    ) or "Owner"

    pass_id = f"guest_{secrets.token_urlsafe(24)}"
    claim_secret = new_claim_secret()
    pin_salt, pin_digest = guest_pass_pin_record(normalized.pop("pin"))
    created_at = utc_now_iso()
    expiration = normalized["expiration"]
    if expiration["kind"] == "fixed":
        slot_expires_at = int(expiration["at"]) + GUEST_PASS_RECORD_RETENTION_SECONDS
    else:
        slot_expires_at = (
            int(normalized["start_by"])
            + int(expiration["seconds"])
            + GUEST_PASS_RECORD_RETENTION_SECONDS
        )
    item = {
        "pass_id": pass_id,
        "record_type": "guest_pass",
        "household_id": household_id,
        "account_id": str(session.get("account_id") or ""),
        "owner_principal_id": str(session.get("principal_id") or ""),
        "owner_profile_id": str(session.get("profile_id") or ""),
        "owner_display_name": owner_display_name,
        **normalized,
        "claim_secret_hash": guest_pass_secret_digest(claim_secret),
        "pin_salt": pin_salt,
        "pin_digest": pin_digest,
        "state": "pending",
        "created_at": created_at,
        "created_at_epoch": now,
        "expires_at": slot_expires_at,
    }
    if expiration["kind"] == "fixed":
        item["access_expires_at"] = int(expiration["at"])
    household_slot_prefix = guest_pass_secret_digest(household_id)[:24]
    claimed_slot_id = None
    for slot_index in range(MAX_ACTIVE_PASSES):
        slot_id = f"guest_slot_{household_slot_prefix}_{slot_index}"
        candidate = dict(item)
        candidate["slot_id"] = slot_id
        try:
            dynamodb.meta.client.transact_write_items(TransactItems=[
                {"Put": {
                    "TableName": guest_passes_table.name,
                    "Item": {
                        "pass_id": slot_id,
                        "record_type": "guest_pass_slot",
                        "household_id": household_id,
                        "created_at_epoch": now,
                        "occupant_pass_id": pass_id,
                        "expires_at": slot_expires_at,
                    },
                    "ConditionExpression": "attribute_not_exists(pass_id) OR expires_at < :now",
                    "ExpressionAttributeValues": {":now": now},
                }},
                {"Put": {
                    "TableName": guest_passes_table.name,
                    "Item": candidate,
                    "ConditionExpression": "attribute_not_exists(pass_id)",
                }},
            ])
            item = candidate
            claimed_slot_id = slot_id
            break
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in {
                "ConditionalCheckFailedException", "TransactionCanceledException",
            }:
                continue
            raise
    if claimed_slot_id is None:
        return response(409, {"state": "guest_pass_limit_reached", "limit": MAX_ACTIVE_PASSES})
    projected = public_guest_pass(item, now=now)
    projected.update({
        "state": "guest_pass_created",
        "claim_url": f"kaevo://guest-pass/claim?pass_id={pass_id}&claim={claim_secret}",
        "pin_required": bool(pin_digest),
    })
    return response(201, projected)


def list_guest_passes(event):
    session, error_response = _guest_pass_owner_session(event)
    if error_response:
        return error_response
    if guest_passes_table is None:
        return response(503, {"state": "guest_pass_storage_unavailable"})
    now = epoch_now()
    items = [
        public_guest_pass(item, now=now)
        for item in _guest_pass_records(str(session.get("household_id") or ""))
    ]
    return response(200, {"state": "guest_passes_listed", "items": items})


def revoke_guest_pass(event, path):
    session, error_response = _guest_pass_owner_session(event)
    if error_response:
        return error_response
    if guest_passes_table is None:
        return response(503, {"state": "guest_pass_storage_unavailable"})
    pass_id = path.removeprefix("/v1/guest-passes/").removesuffix("/revoke").strip("/")
    item = guest_passes_table.get_item(
        Key={"pass_id": pass_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(item, dict)
        and hmac.compare_digest(str(item.get("household_id") or ""), str(session.get("household_id") or ""))
    ):
        return response(404, {"state": "guest_pass_not_found"})
    now = epoch_now()
    if guest_pass_effective_state(item, now=now) == "revoked":
        return response(200, {"state": "guest_pass_revoked", "pass_id": pass_id})
    slot_id = str(item.get("slot_id") or "")
    try:
        transactions = [{"Update": {
            "TableName": guest_passes_table.name,
            "Key": {"pass_id": pass_id},
            "UpdateExpression": "SET #state = :revoked, revoked_at = :revoked_at, expires_at = :expires_at",
            "ConditionExpression": "household_id = :household_id AND #state <> :revoked",
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": {
                ":revoked": "revoked",
                ":revoked_at": utc_now_iso(),
                ":expires_at": now + GUEST_PASS_RECORD_RETENTION_SECONDS,
                ":household_id": str(session.get("household_id") or ""),
            },
        }}]
        if slot_id:
            transactions.append({"Delete": {
                "TableName": guest_passes_table.name,
                "Key": {"pass_id": slot_id},
                "ConditionExpression": "occupant_pass_id = :pass_id AND household_id = :household_id",
                "ExpressionAttributeValues": {
                    ":pass_id": pass_id,
                    ":household_id": str(session.get("household_id") or ""),
                },
            }})
        dynamodb.meta.client.transact_write_items(TransactItems=transactions)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, {"state": "guest_pass_revoke_conflict"})
        raise
    return response(200, {"state": "guest_pass_revoked", "pass_id": pass_id})


def claim_guest_pass(event):
    if guest_passes_table is None or app_sessions_table is None:
        return response(503, {"state": "guest_pass_storage_unavailable"})
    body = parse_json_body(event)
    if not isinstance(body, dict):
        return response(400, {"state": "invalid_guest_pass_claim"})
    pass_id = str(body.get("pass_id") or "").strip()
    claim_secret = str(body.get("claim_secret") or "").strip()
    device_id = str(body.get("device_id") or "").strip()
    public_jwk = body.get("public_jwk")
    if not (
        re.fullmatch(r"guest_[A-Za-z0-9_-]{16,128}", pass_id)
        and 32 <= len(claim_secret) <= 256
        and SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id)
        and isinstance(public_jwk, dict)
    ):
        return response(400, {"state": "invalid_guest_pass_claim"})
    try:
        validate_public_jwk(public_jwk)
        thumbprint = jwk_thumbprint(public_jwk)
        verify_dpop(
            str(header_value(event, "dpop") or ""),
            method=method_for(event),
            url=request_absolute_url(event),
            expected_thumbprint=thumbprint,
            replay_guard=record_dpop_jti,
        )
    except IdentityError as error:
        return identity_error_response(error)

    item = guest_passes_table.get_item(
        Key={"pass_id": pass_id}, ConsistentRead=True,
    ).get("Item")
    now = epoch_now()
    if not isinstance(item, dict) or guest_pass_effective_state(item, now=now) not in {"pending", "claimed"}:
        return response(404, {"state": "guest_pass_unavailable"})
    if not hmac.compare_digest(
        str(item.get("claim_secret_hash") or ""), guest_pass_secret_digest(claim_secret),
    ) or not guest_pass_pin_matches(body.get("pin"), str(item.get("pin_salt") or ""), str(item.get("pin_digest") or "")):
        return response(404, {"state": "guest_pass_unavailable"})

    already_claimed = str(item.get("state") or "") == "claimed"
    if already_claimed and not (
        hmac.compare_digest(str(item.get("device_id") or ""), device_id)
        and hmac.compare_digest(str(item.get("key_thumbprint") or ""), thumbprint)
    ):
        return response(409, {"state": "guest_pass_device_bound"})
    if not already_claimed:
        try:
            guest_passes_table.update_item(
                Key={"pass_id": pass_id},
                UpdateExpression=(
                    "SET #state = :claimed, claimed_at = :claimed_at, "
                    "device_id = :device_id, key_thumbprint = :thumbprint"
                ),
                ConditionExpression="#state = :pending AND start_by >= :now",
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":claimed": "claimed", ":pending": "pending",
                    ":claimed_at": utc_now_iso(), ":device_id": device_id,
                    ":thumbprint": thumbprint, ":now": now,
                },
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return response(409, {"state": "guest_pass_claim_conflict"})
            raise

    access_token = secrets.token_urlsafe(32)
    expires_at = now + GUEST_PASS_ACCESS_TOKEN_MAX_SECONDS
    app_sessions_table.put_item(Item={
        "token_hash": f"guest#{production_token_hash(access_token)}",
        "record_type": "guest_access",
        "pass_id": pass_id,
        "household_id": str(item.get("household_id") or ""),
        "profile_id": str(item.get("source_profile_id") or ""),
        "device_id": device_id,
        "key_thumbprint": thumbprint,
        "state": "active",
        "created_at_epoch": now,
        "expires_at": expires_at,
    })
    projection = public_guest_pass({**item, "state": "claimed", "device_id": device_id}, now=now)
    return response(200, {
        "state": "guest_pass_claimed",
        "server_time": now,
        "token_type": "DPoP",  # nosec B105
        "access_token": access_token,
        "access_expires_at": expires_at,
        "guest_pass": projection,
    })


def _guest_access_context(event, *, allow_expired_finish_current=False):
    """Resolve one exact DPoP-bound Guest Pass without creating a profile."""
    if app_sessions_table is None or guest_passes_table is None:
        return None, None, response(503, {"state": "guest_pass_storage_unavailable"})
    token = app_bearer_token(event)
    if not token:
        return None, None, response(401, {"state": "guest_pass_unauthorized"})
    access = app_sessions_table.get_item(
        Key={"token_hash": f"guest#{production_token_hash(token)}"},
        ConsistentRead=True,
    ).get("Item")
    now = epoch_now()
    if not (
        isinstance(access, dict)
        and access.get("record_type") == "guest_access"
        and access.get("state") == "active"
        and int(access.get("expires_at") or 0) > now
    ):
        return None, None, response(401, {"state": "guest_pass_unauthorized"})
    try:
        verify_dpop(
            str(header_value(event, "dpop") or ""),
            method=method_for(event),
            url=request_absolute_url(event),
            expected_thumbprint=str(access.get("key_thumbprint") or ""),
            access_token=token,
            replay_guard=record_dpop_jti,
        )
    except IdentityError:
        return None, None, response(401, {"state": "guest_pass_unauthorized"})
    guest_pass = guest_passes_table.get_item(
        Key={"pass_id": str(access.get("pass_id") or "")},
        ConsistentRead=True,
    ).get("Item")
    guest_state = guest_pass_effective_state(guest_pass, now=now) if isinstance(guest_pass, dict) else "unavailable"
    finish_current = bool(
        allow_expired_finish_current
        and guest_state == "expired"
        and str((guest_pass or {}).get("expiration_behavior") or "") == "finish_current_video"
        and isinstance((guest_pass or {}).get("active_playback"), dict)
    )
    if not (
        isinstance(guest_pass, dict)
        and hmac.compare_digest(str(guest_pass.get("pass_id") or ""), str(access.get("pass_id") or ""))
        and hmac.compare_digest(str(guest_pass.get("household_id") or ""), str(access.get("household_id") or ""))
        and hmac.compare_digest(str(guest_pass.get("source_profile_id") or ""), str(access.get("profile_id") or ""))
        and hmac.compare_digest(str(guest_pass.get("device_id") or ""), str(access.get("device_id") or ""))
        and hmac.compare_digest(str(guest_pass.get("key_thumbprint") or ""), str(access.get("key_thumbprint") or ""))
        and (guest_state in {"claimed", "active"} or finish_current)
    ):
        return None, None, response(403, {"state": "guest_pass_unavailable"})
    return access, guest_pass, None


def guest_pass_session(event):
    _access, guest_pass, error_response = _guest_access_context(event)
    if error_response:
        return error_response
    now = epoch_now()
    return response(200, {
        "state": "guest_pass_active",
        "server_time": now,
        "guest_pass": public_guest_pass(guest_pass, now=now),
    })


def _guest_item_authorized(guest_pass, item):
    if not isinstance(item, dict):
        return False
    item_id = str(item.get("Id") or item.get("id") or "").strip().lower()
    raw_kind = str(item.get("Type") or item.get("type") or "").strip().lower()
    item_kind = {"series": "show"}.get(raw_kind, raw_kind)
    ancestry = {
        "show": str(item.get("SeriesId") or item.get("series_id") or "").strip().lower(),
        "season": str(item.get("SeasonId") or item.get("season_id") or "").strip().lower(),
    }
    return guest_pass_scope_authorizes(
        guest_pass.get("scope") or {},
        item_id=item_id,
        item_kind=item_kind,
        ancestor_ids=ancestry,
    )


def _guest_filter_item_page(guest_pass, page):
    if not isinstance(page, dict):
        return {"Items": [], "TotalRecordCount": 0, "StartIndex": 0}
    items_key = "Items" if isinstance(page.get("Items"), list) else "items"
    filtered = [
        item for item in (page.get(items_key) or [])
        if _guest_item_authorized(guest_pass, item)
    ]
    result = dict(page)
    result[items_key] = filtered
    for count_key in ("TotalRecordCount", "totalRecordCount"):
        if count_key in result:
            result[count_key] = len(filtered)
    return result


def _guest_annotate_item_page(guest_pass, page):
    """Keep an owner-authorized full-library search browse-only by default."""
    if not isinstance(page, dict):
        return {"Items": [], "TotalRecordCount": 0, "StartIndex": 0}
    items_key = "Items" if isinstance(page.get("Items"), list) else "items"
    result = dict(page)
    result[items_key] = [
        {**item, "GuestPlayable": _guest_item_authorized(guest_pass, item)}
        for item in (page.get(items_key) or [])
        if isinstance(item, dict)
    ]
    return result


def _guest_filter_main_snapshot(guest_pass, payload):
    if not isinstance(payload, dict):
        return {"state": "guest_content_unavailable"}
    result = dict(payload)
    for key in ("movies", "shows", "continueWatching", "recentlyAdded"):
        result[key] = _guest_filter_item_page(guest_pass, payload.get(key))
    if str((guest_pass.get("scope") or {}).get("kind") or "") != "full_library":
        # Library and collection names can reveal content outside the pass.
        result["collections"] = _guest_filter_item_page(guest_pass, None)
        result["views"] = _guest_filter_item_page(guest_pass, None)
    return result


def _queue_guest_remote_request(
    guest_pass, request_payload, *, connector=None, guest_search_full=False,
    guest_authorization_request_id=None,
):
    connector = connector or latest_online_connector_for_profile(str(guest_pass.get("source_profile_id") or ""))
    if not connector:
        return None
    now_iso = utc_now_iso()
    request_id = str(uuid.uuid4())
    priority = remote_request_priority(request_payload)
    item = {
        "request_id": request_id,
        "profile_id": str(guest_pass.get("source_profile_id") or ""),
        "guest_pass_id": str(guest_pass.get("pass_id") or ""),
        "guest_search_full": bool(guest_search_full),
        "connector_id": str(connector.get("connector_id") or ""),
        "status": "pending",
        "status_created_at": status_sort_key("pending", now_iso, request_id, priority),
        "priority": priority,
        "request_json": json.dumps(request_payload, separators=(",", ":"), sort_keys=True),
        "created_at": now_iso,
        "updated_at": now_iso,
        "expires_at": epoch_now() + REMOTE_REQUEST_TTL_SECONDS,
    }
    if guest_authorization_request_id:
        item["guest_authorization_request_id"] = guest_authorization_request_id
    remote_requests_table.put_item(Item=item)
    return item


def _guest_authorization_request(guest_pass, request_id):
    try:
        normalized_request_id = str(uuid.UUID(str(request_id or "")))
    except (ValueError, AttributeError, TypeError):
        return None
    item = remote_requests_table.get_item(
        Key={"request_id": normalized_request_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(item, dict)
        and item.get("status") == "completed"
        and hmac.compare_digest(
            str(item.get("guest_pass_id") or ""), str(guest_pass.get("pass_id") or ""),
        )
        and hmac.compare_digest(
            str(item.get("profile_id") or ""), str(guest_pass.get("source_profile_id") or ""),
        )
    ):
        return None
    return item


def _guest_list_request_authorizes_item(guest_pass, request_id, item_id):
    anchor = _guest_authorization_request(guest_pass, request_id)
    if anchor is None:
        return False
    request_payload = parse_json_field(anchor.get("request_json"), {})
    path = str(request_payload.get("path") or "")
    if not (
        re.fullmatch(r"/Shows/[0-9a-fA-F]{32}/(Seasons|Episodes)", path)
        or re.fullmatch(r"/Users/[0-9a-fA-F]{32}/Items", path)
        or path == "/kaevo/internal/guest-scope"
    ):
        return False
    page = _guest_filter_item_page(
        guest_pass, decode_remote_response_payload(anchor, {}),
    )
    values = page.get("Items") if isinstance(page.get("Items"), list) else page.get("items")
    return any(
        isinstance(value, dict)
        and hmac.compare_digest(
            str(value.get("Id") or value.get("id") or "").strip().lower(), item_id,
        )
        for value in (values or [])
    )


def _guest_detail_anchor_authorizes_target(guest_pass, request_id, target_id):
    anchor = _guest_authorization_request(guest_pass, request_id)
    if anchor is None:
        return False
    request_payload = parse_json_field(anchor.get("request_json"), {})
    if not re.fullmatch(
        r"/Users/[0-9a-fA-F]{32}/Items/[0-9a-fA-F]{32}",
        str(request_payload.get("path") or ""),
    ):
        return False
    detail = decode_remote_response_payload(anchor, {})
    if not _guest_item_authorized(guest_pass, detail):
        return False
    related_series_id = str(
        detail.get("SeriesId") or detail.get("series_id") or ""
    ).strip().lower()
    return bool(related_series_id) and hmac.compare_digest(related_series_id, target_id)


def create_guest_content_request(event):
    _access, guest_pass, error_response = _guest_access_context(event)
    if error_response:
        return error_response
    if remote_requests_table is None:
        return response(503, {"state": "guest_content_unavailable"})
    body = parse_json_body(event) or {}
    resource = str(body.get("resource") or "home").strip().lower()
    authorization_request_id = str(body.get("authorization_request_id") or "").strip()
    if authorization_request_id:
        try:
            authorization_request_id = str(uuid.UUID(authorization_request_id))
        except (ValueError, AttributeError, TypeError):
            return response(400, {"state": "invalid_guest_authorization_request"})
    connector = latest_online_connector_for_profile(str(guest_pass.get("source_profile_id") or ""))
    if not connector:
        return response(409, {"state": "connector_unavailable"})
    if resource == "home":
        scope = guest_pass.get("scope") or {}
        if str(scope.get("kind") or "") == "full_library":
            path = "/kaevo/internal/main-snapshot"
            query = {
                "moviesLimit": "80", "showsLimit": "80", "collectionsLimit": "50",
                "resumeLimit": "20", "recentLimit": "30",
            }
        else:
            item_ids = [
                str(entry.get("item_id") or "").strip().lower()
                for entry in (scope.get("entries") or [])
                if isinstance(entry, dict)
            ]
            path = "/kaevo/internal/guest-scope"
            query = {"itemIds": ",".join(item_ids)}
    elif resource == "detail":
        item_id = str(body.get("item_id") or "").strip().lower()
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
            return response(400, {"state": "invalid_guest_content_item"})
        if authorization_request_id and not _guest_detail_anchor_authorizes_target(
            guest_pass, authorization_request_id, item_id,
        ):
            return response(403, {"state": "guest_related_detail_not_allowed"})
        path = f"/Users/00000000000000000000000000000000/Items/{item_id}"
        query = {
            "Fields": (
                "Overview,Genres,People,Studios,ProviderIds,PrimaryImageAspectRatio,"
                "Taglines,Tags,DateCreated,PremiereDate,ProductionYear,ImageTags,"
                "BackdropImageTags,RunTimeTicks"
            ),
            "EnableUserData": "false",
        }
        path, query, binding_error = _authorized_jellyfin_metadata_request(
            str(guest_pass.get("source_profile_id") or ""),
            str(connector.get("connector_id") or ""),
            path,
            query,
        )
        if binding_error:
            return response(409, {"state": "guest_content_unavailable"})
    elif resource in {"seasons", "episodes"}:
        series_id = str(body.get("series_id") or "").strip().lower()
        if not SAFE_JELLYFIN_ITEM_ID.fullmatch(series_id):
            return response(400, {"state": "invalid_guest_content_scope"})
        path = f"/Shows/{series_id}/{'Seasons' if resource == 'seasons' else 'Episodes'}"
        query = {}
        season_id = str(body.get("season_id") or "").strip().lower()
        if resource == "episodes" and season_id:
            if not SAFE_JELLYFIN_ITEM_ID.fullmatch(season_id):
                return response(400, {"state": "invalid_guest_content_scope"})
            query["seasonId"] = season_id
        path, query, binding_error = _authorized_jellyfin_metadata_request(
            str(guest_pass.get("source_profile_id") or ""),
            str(connector.get("connector_id") or ""),
            path,
            query,
        )
        if binding_error:
            return response(409, {"state": "guest_content_unavailable"})
    elif resource == "search":
        permissions = guest_pass.get("permissions") or {}
        if not (
            bool_value(permissions.get("search_granted_content"), False)
            or bool_value(permissions.get("search_full_library"), False)
        ):
            return response(403, {"state": "guest_search_not_allowed"})
        search_text = str(body.get("query") or "").strip()
        if not 2 <= len(search_text) <= 100 or any(ord(char) < 32 for char in search_text):
            return response(400, {"state": "invalid_guest_search"})
        path = "/Users/00000000000000000000000000000000/Items"
        query = {
            "SearchTerm": search_text,
            "Recursive": "true",
            "StartIndex": "0",
            "Limit": "50",
            "IncludeItemTypes": "Movie,Series,Season,Episode",
            "Fields": "Overview,Genres,Studios,ProviderIds,PrimaryImageAspectRatio",
            "EnableUserData": "false",
            "EnableImages": "true",
            "ImageTypeLimit": "1",
            "EnableImageTypes": "Primary,Backdrop,Logo",
        }
        path, query, binding_error = _authorized_jellyfin_metadata_request(
            str(guest_pass.get("source_profile_id") or ""),
            str(connector.get("connector_id") or ""),
            path,
            query,
        )
        if binding_error:
            return response(409, {"state": "guest_content_unavailable"})
    elif resource == "image":
        item_id = str(body.get("item_id") or "").strip().lower()
        image_type = str(body.get("image_type") or "primary").strip().lower()
        if (
            not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id)
            or image_type not in REMOTE_IMAGE_TYPES
        ):
            return response(400, {"state": "invalid_guest_image"})
        scope = guest_pass.get("scope") or {}
        exact_scope_item = any(
            isinstance(entry, dict)
            and hmac.compare_digest(
                str(entry.get("item_id") or "").strip().lower(), item_id,
            )
            for entry in (scope.get("entries") or [])
        )
        if str(scope.get("kind") or "") != "full_library" and not exact_scope_item:
            # A completed, pass-bound list response is trusted ancestry for its
            # already filtered children. Client-supplied IDs alone remain
            # insufficient authority.
            if not _guest_list_request_authorizes_item(
                guest_pass, authorization_request_id, item_id,
            ):
                return response(403, {"state": "guest_image_not_allowed"})
        path = "/kaevo/internal/image"
        query = {
            "item_id": item_id,
            "image_type": image_type,
            "tag": str(body.get("tag") or "").strip()[:256],
            "max_width": str(bounded_int_param(body, "max_width", 900, REMOTE_IMAGE_MAX_DIMENSION)),
            "max_height": str(bounded_int_param(body, "max_height", 1350, REMOTE_IMAGE_MAX_DIMENSION)),
            "quality": str(bounded_int_param(body, "quality", 88, 95)),
        }
    else:
        return response(400, {"state": "invalid_guest_content_resource"})
    request_payload = {"provider": "jellyfin", "method": "GET", "path": path, "query": query}
    queued = _queue_guest_remote_request(
        guest_pass,
        request_payload,
        connector=connector,
        guest_search_full=(
            resource == "search"
            and bool_value((guest_pass.get("permissions") or {}).get("search_full_library"), False)
        ),
        guest_authorization_request_id=authorization_request_id or None,
    )
    if queued is None:
        return response(409, {"state": "connector_unavailable"})
    return response(202, {"state": "queued", "request_id": queued["request_id"]})


def create_guest_playback_request(event):
    access, guest_pass, error_response = _guest_access_context(event)
    if error_response:
        return error_response
    if remote_requests_table is None:
        return response(503, {"state": "guest_playback_unavailable"})
    body = parse_json_body(event) or {}
    item_id = str(body.get("item_id") or "").strip().lower()
    if not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id):
        return response(400, {"state": "invalid_guest_playback_item"})
    request_payload, error = normalize_remote_command(
        "jellyfin.prepare_playback",
        {
            "item_id": item_id,
            "device_id": str(access.get("device_id") or ""),
            "max_bitrate": min(positive_int(body.get("max_bitrate") or 40_000_000, maximum=100_000_000) or 40_000_000, 40_000_000),
            "media_segments_enabled": False,
        },
    )
    if request_payload is None:
        return response(400, {"state": "invalid_guest_playback", "message": error})
    queued = _queue_guest_remote_request(guest_pass, request_payload)
    if queued is None:
        return response(409, {"state": "connector_unavailable"})
    return response(202, {"state": "queued", "request_id": queued["request_id"]})


def record_guest_playback_activity(event):
    _access, guest_pass, error_response = _guest_access_context(
        event, allow_expired_finish_current=True,
    )
    if error_response:
        return error_response
    body = parse_json_body(event) or {}
    activity = str(body.get("event") or "").strip().lower()
    item_id = str(body.get("item_id") or "").strip().lower()
    playback_session_id = str(body.get("playback_session_id") or "").strip()
    position_ticks = body.get("position_ticks")
    if (
        activity not in {"started", "progress", "stopped", "completed", "marked_watched"}
        or not SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id)
        or not SAFE_PLAYBACK_IDENTIFIER.fullmatch(playback_session_id)
        or isinstance(position_ticks, bool)
        or not isinstance(position_ticks, int)
        or not 0 <= position_ticks <= 6_048_000_000_000
    ):
        return response(400, {"state": "invalid_guest_playback_activity"})
    if activity == "marked_watched" and not bool_value(
        (guest_pass.get("permissions") or {}).get("mark_watched"), False,
    ):
        return response(403, {"state": "guest_mark_watched_not_allowed"})
    active = guest_pass.get("active_playback") or {}
    if not (
        isinstance(active, dict)
        and hmac.compare_digest(str(active.get("item_id") or ""), item_id)
        and hmac.compare_digest(str(active.get("playback_session_id") or ""), playback_session_id)
    ):
        return response(409, {"state": "guest_playback_session_mismatch"})
    runtime_ticks = int(active.get("runtime_ticks") or 0)
    completed = activity == "marked_watched" or (
        activity == "completed"
        and (runtime_ticks <= 0 or position_ticks >= int(runtime_ticks * 0.9))
    )
    now = epoch_now()
    progress_by_item = dict(guest_pass.get("progress_by_item") or {})
    if len(progress_by_item) >= 500 and item_id not in progress_by_item:
        oldest_item_id = min(
            progress_by_item,
            key=lambda key: str((progress_by_item.get(key) or {}).get("updated_at") or ""),
        )
        progress_by_item.pop(oldest_item_id, None)
    progress_by_item[item_id] = {
        "position_ticks": position_ticks,
        "runtime_ticks": max(runtime_ticks, 0),
        "completed": completed,
        "updated_at": utc_now_iso(),
    }
    set_clauses = ["last_activity = :activity", "progress_by_item = :progress_by_item"]
    values = {
        ":activity": {
            "event": activity,
            "item_id": item_id,
            "playback_session_id": playback_session_id,
            "position_ticks": position_ticks,
            "recorded_at": utc_now_iso(),
        },
        ":pass_id": str(guest_pass.get("pass_id") or ""),
        ":session_id": playback_session_id,
        ":progress_by_item": progress_by_item,
    }
    if completed and str(guest_pass.get("replay_policy") or "") == "one_completed_view":
        set_clauses.append(
            "completed_item_ids = list_append(if_not_exists(completed_item_ids, :empty), :item)"
        )
        values[":empty"] = []
        values[":item"] = [item_id]
    update = "SET " + ", ".join(set_clauses)
    if activity in {"stopped", "completed", "marked_watched"}:
        update += " REMOVE active_playback"
    try:
        guest_passes_table.update_item(
            Key={"pass_id": str(guest_pass.get("pass_id") or "")},
            UpdateExpression=update,
            ConditionExpression=(
                "pass_id = :pass_id AND active_playback.playback_session_id = :session_id"
            ),
            ExpressionAttributeValues=values,
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, {"state": "guest_playback_session_mismatch"})
        raise
    return response(200, {
        "state": "guest_playback_completed" if completed else "guest_playback_activity_recorded",
        "server_time": now,
    })


def _activate_guest_pass_for_playback(guest_pass, item_id):
    now = epoch_now()
    if guest_pass_effective_state(guest_pass, now=now) not in {"claimed", "active"}:
        return None
    completed = guest_pass.get("completed_item_ids") or []
    if (
        guest_pass.get("replay_policy") == "one_completed_view"
        and any(hmac.compare_digest(str(value or ""), item_id) for value in completed)
    ):
        return None
    if guest_pass.get("started_at"):
        return guest_pass
    expiration = guest_pass.get("expiration") or {}
    access_expires_at = (
        now + int(expiration.get("seconds") or 0)
        if expiration.get("kind") == "duration_after_first_play"
        else int(expiration.get("at") or 0)
    )
    if access_expires_at <= now:
        return None
    try:
        guest_passes_table.update_item(
            Key={"pass_id": str(guest_pass.get("pass_id") or "")},
            UpdateExpression=(
                "SET #state = :active, started_at = :started_at, "
                "access_expires_at = :access_expires_at REMOVE claim_secret_hash"
            ),
            ConditionExpression=(
                "attribute_not_exists(started_at) AND start_by >= :now "
                "AND #state = :claimed"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":active": "active", ":claimed": "claimed", ":started_at": utc_now_iso(),
                ":access_expires_at": access_expires_at, ":now": now,
            },
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
    exact = guest_passes_table.get_item(
        Key={"pass_id": str(guest_pass.get("pass_id") or "")}, ConsistentRead=True,
    ).get("Item")
    return exact if isinstance(exact, dict) and guest_pass_effective_state(exact, now=now) == "active" else None


def get_guest_remote_request(event, path):
    _access, guest_pass, error_response = _guest_access_context(event)
    if error_response:
        return error_response
    request_id = path.removeprefix("/v1/guest-pass/remote-requests/").strip("/")
    if not request_id or remote_requests_table is None:
        return response(404, {"state": "not_found"})
    item = remote_requests_table.get_item(
        Key={"request_id": request_id}, ConsistentRead=True,
    ).get("Item")
    if not (
        isinstance(item, dict)
        and hmac.compare_digest(str(item.get("guest_pass_id") or ""), str(guest_pass.get("pass_id") or ""))
        and hmac.compare_digest(str(item.get("profile_id") or ""), str(guest_pass.get("source_profile_id") or ""))
    ):
        return response(404, {"state": "not_found"})
    projected = public_remote_request_item(item, include_payload=True)
    if item.get("status") == "completed":
        request_payload = parse_json_field(item.get("request_json"), {})
        if request_payload.get("path") == "/commands/jellyfin.prepare_playback":
            # Pairing V3 completion is intentionally owned by the
            # least-privilege connector-control Lambda, which cannot read
            # Guest Pass policy or activate its first-play clock. Finalize
            # the already authenticated, pass-bound request here before the
            # guest sees it. This preserves one Cloud authority for scope,
            # timing, device binding, and relay-grant issuance without giving
            # the connector-control role access to Guest Pass records.
            projected["response"] = _completion_with_embedded_playback_grant(
                item,
                decode_remote_response_payload(item, {}),
            )
        elif request_payload.get("path") == "/kaevo/internal/main-snapshot":
            projected["response"] = _guest_filter_main_snapshot(
                guest_pass, decode_remote_response_payload(item, {}),
            )
        elif request_payload.get("path") == "/kaevo/internal/guest-scope":
            projected["response"] = {
                "scopeItems": _guest_filter_item_page(
                    guest_pass, decode_remote_response_payload(item, {}),
                )
            }
        elif re.fullmatch(
            r"/Shows/[0-9a-fA-F]{32}/(Seasons|Episodes)",
            str(request_payload.get("path") or ""),
        ):
            projected["response"] = {
                "scopeItems": _guest_filter_item_page(
                    guest_pass, decode_remote_response_payload(item, {}),
                )
            }
        elif re.fullmatch(
            r"/Users/[0-9a-fA-F]{32}/Items/[0-9a-fA-F]{32}",
            str(request_payload.get("path") or ""),
        ):
            detail = decode_remote_response_payload(item, {})
            detail_id = str(detail.get("Id") or detail.get("id") or "").strip().lower()
            detail_authorized = _guest_item_authorized(guest_pass, detail) or (
                bool(detail_id)
                and _guest_detail_anchor_authorizes_target(
                    guest_pass,
                    item.get("guest_authorization_request_id"),
                    detail_id,
                )
            )
            projected["response"] = {
                "detail": detail if detail_authorized else None
            }
        elif item.get("guest_pass_id") and re.fullmatch(
            r"/Users/[0-9a-fA-F]{32}/Items",
            str(request_payload.get("path") or ""),
        ):
            page = decode_remote_response_payload(item, {})
            projected["response"] = {
                "scopeItems": _guest_annotate_item_page(guest_pass, page)
                if bool_value(item.get("guest_search_full"), False)
                else _guest_filter_item_page(guest_pass, page)
            }
    return response(200, {"state": str(item.get("status") or "unknown"), "request": projected})


def household_invitation_response(invitation, join_code, *, state):
    payload = {
        "state": state,
        "invitation_id": str(invitation.get("invitation_id") or ""),
        "profile_id": str(invitation.get("profile_id") or ""),
        "display_name": str(invitation.get("display_name") or "Household member"),
        "profile_type": str(invitation.get("profile_type") or "adult"),
        "age_classification": str(invitation.get("role") or "adult"),
        "household_access_role": str(
            invitation.get("household_access_role") or "member"
        ),
        "cloud_access_enabled": bool_value(
            invitation.get("cloud_access_enabled"), True
        ),
        "switch_profile_ids": list(invitation.get("switch_profile_ids") or []),
        "join_code": join_code,
        "join_url": f"kaevo://join?code={join_code}",
        # Opaque exact-key locator for the protected Owner binding flow. This
        # SHA-256 value is not the one-time join secret and grants no authority
        # by itself.
        "binding_handle": str(invitation.get("code_hash") or ""),
        "expires_at": household_invitation_code_expiration(invitation),
    }
    # Keep the public contract compatible for invitations created before the
    # policy fields existed.  Modern callers always receive their explicit
    # values; a missing legacy field is not reinterpreted as a new default.
    if "request_access_enabled" in invitation:
        payload["request_access_enabled"] = bool_value(
            invitation.get("request_access_enabled"), False
        )
    if "parental_controls" in invitation:
        payload["parental_controls"] = invitation.get("parental_controls")
    return response(201, payload)


def _invitation_switch_profile_ids(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("invalid_switch_profile_grants")
    resolved = []
    for candidate in value:
        profile_id = str(candidate or "").strip()
        if (
            not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
            or profile_id in resolved
        ):
            raise ValueError("invalid_switch_profile_grants")
        resolved.append(profile_id)
    return resolved


def _invitation_watching_profile_ids(value):
    """Validate only explicit immutable Who's Watching target IDs."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("invalid_watching_targets")
    resolved = []
    for candidate in value:
        profile_id = str(candidate or "").strip()
        if (
            not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
            or profile_id in resolved
        ):
            raise ValueError("invalid_watching_targets")
        resolved.append(profile_id)
    return resolved


def _normalized_parental_controls(value, *, require_child_safe=False):
    """Validate and retain the owner-selected viewing policy exactly.

    This is policy data, not an entitlement.  Keeping it on the canonical
    profile/invitation prevents a device-local default from silently changing
    what a child can watch after joining on another device.
    """
    if value is None:
        if require_child_safe:
            raise ValueError("missing_child_viewing_level")
        return None
    if not isinstance(value, dict):
        raise ValueError("invalid_parental_controls")
    if type(value.get("version", 1)) is not int or value.get("version", 1) != 1:
        raise ValueError("invalid_parental_controls")
    preset = str(value.get("preset") or "").strip()
    if preset not in {"littleKids", "olderKids", "teens", "unrestricted"}:
        raise ValueError("invalid_parental_controls")
    enabled = value.get("is_enabled")
    hide_unrated = value.get("hide_unrated_content")
    if not isinstance(enabled, bool) or not isinstance(hide_unrated, bool):
        raise ValueError("invalid_parental_controls")
    if require_child_safe and (not enabled or preset == "unrestricted"):
        raise ValueError("invalid_child_viewing_level")

    def string_values(key, maximum):
        raw = value.get(key) or []
        if not isinstance(raw, list) or len(raw) > maximum:
            raise ValueError("invalid_parental_controls")
        cleaned = []
        for candidate in raw:
            if not isinstance(candidate, str):
                raise ValueError("invalid_parental_controls")
            text = str(candidate or "").strip()
            if not text or len(text) > 120 or text in cleaned:
                raise ValueError("invalid_parental_controls")
            cleaned.append(text)
        return cleaned

    exceptions = value.get("exceptions") or []
    if not isinstance(exceptions, list) or len(exceptions) > 64:
        raise ValueError("invalid_parental_controls")
    normalized_exceptions = []
    for exception in exceptions:
        if not isinstance(exception, dict):
            raise ValueError("invalid_parental_controls")
        if not all(isinstance(exception.get(key), str) for key in ("id", "title", "scope")):
            raise ValueError("invalid_parental_controls")
        identifier = exception["id"].strip()
        if not identifier or len(identifier) > 160:
            raise ValueError("invalid_parental_controls")
        scope = str(exception.get("scope") or "").strip()
        provider_item_ids = exception.get("provider_item_ids") or []
        if scope not in {"title", "collection"} or not isinstance(provider_item_ids, list):
            raise ValueError("invalid_parental_controls")
        cleaned_item_ids = []
        for provider_item_id in provider_item_ids:
            if not isinstance(provider_item_id, str):
                raise ValueError("invalid_parental_controls")
            item_id = str(provider_item_id or "").strip()
            if not item_id or len(item_id) > 160 or item_id in cleaned_item_ids:
                raise ValueError("invalid_parental_controls")
            cleaned_item_ids.append(item_id)
        if not cleaned_item_ids:
            raise ValueError("invalid_parental_controls")
        normalized_exceptions.append({
            "id": identifier,
            "title": str(exception.get("title") or "").strip()[:160],
            "scope": scope,
            "provider_item_ids": cleaned_item_ids,
        })
    return {
        "version": 1,
        "is_enabled": enabled,
        "preset": preset,
        "allowed_tags": string_values("allowed_tags", 64),
        "blocked_genres": string_values("blocked_genres", 64),
        "blocked_tags": string_values("blocked_tags", 64),
        "exceptions": normalized_exceptions,
        "hide_unrated_content": hide_unrated,
    }


def create_parent_managed_kid_profile(
    session, display_name, owner_entitlement, *, request_access_enabled=False,
    parental_controls=None, watching_profile_ids=None,
):
    """Create a household kid profile without creating a child identity.

    The owner can use this profile on an already-authorized device. A child
    principal is added only if the owner later creates and the child redeems
    a one-time invitation for this exact profile.
    """
    if not all((identity_profiles_table, principals_table, entitlements_table)):
        return response(503, {"state": "identity_storage_unavailable"})
    profile_id = f"profile_{secrets.token_urlsafe(24)}"
    created_at = utc_now_iso()
    profile = {
        "profile_id": profile_id,
        "account_id": str(session.get("account_id") or ""),
        "household_id": str(session.get("household_id") or ""),
        "owner_principal_id": str(session.get("principal_id") or ""),
        "display_name": display_name,
        "profile_type": "kid",
        "role": "child",
        "canonical_role": "child",
        "household_access_role": HouseholdAccessRole.MEMBER.value,
        "cloud_access_enabled": False,
        "request_access_enabled": bool(request_access_enabled),
        "parental_controls": parental_controls,
        "switch_profile_ids": [],
        "watching_profile_ids": list(watching_profile_ids or []),
        "state": "active",
        "managed_by_owner": True,
        "created_at": created_at,
    }
    entitlement = {
        "profile_id": profile_id,
        "entitlements_json": json.dumps(owner_entitlement, separators=(",", ":")),
        "created_at": created_at,
        "updated_at": created_at,
    }
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Put": {
                "TableName": identity_profiles_table.name,
                "Item": profile,
                "ConditionExpression": "attribute_not_exists(profile_id)",
            }},
            {"Put": {
                "TableName": entitlements_table.name,
                "Item": entitlement,
                "ConditionExpression": "attribute_not_exists(profile_id)",
            }},
            {"Update": {
                "TableName": principals_table.name,
                "Key": {"principal_id": str(session.get("principal_id") or "")},
                "UpdateExpression": "SET profile_ids = list_append(profile_ids, :profile)",
                "ConditionExpression": "contains(profile_ids, :owner_profile) AND NOT contains(profile_ids, :managed_profile)",
                "ExpressionAttributeValues": {
                    ":profile": [profile_id],
                    ":owner_profile": str(session.get("profile_id") or ""),
                    ":managed_profile": profile_id,
                },
            }},
            {"Update": {
                "TableName": identity_profiles_table.name,
                "Key": {"profile_id": str(session.get("profile_id") or "")},
                "UpdateExpression": (
                    "SET switch_profile_ids = list_append(if_not_exists(switch_profile_ids, :empty), :profile), "
                    "watching_profile_ids = list_append(if_not_exists(watching_profile_ids, :empty), :profile), "
                    "updated_at = :updated, updated_at_epoch = :epoch"
                ),
                "ConditionExpression": (
                    "#state = :active AND household_id = :household "
                    "AND NOT contains(switch_profile_ids, :managed_profile) "
                    "AND NOT contains(watching_profile_ids, :managed_profile)"
                ),
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {
                    ":empty": [],
                    ":profile": [profile_id],
                    ":managed_profile": profile_id,
                    ":updated": created_at,
                    ":epoch": epoch_now(),
                    ":active": "active",
                    ":household": str(session.get("household_id") or ""),
                },
            }},
        ])
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") in {
            "ConditionalCheckFailedException", "TransactionCanceledException",
        }:
            return response(409, {"state": "profile_create_conflict"})
        raise
    return response(201, {
        "state": "parent_managed_profile_created",
        "profile_id": profile_id,
        "display_name": display_name,
        "profile_type": "kid",
        "age_classification": "child",
        "household_access_role": HouseholdAccessRole.MEMBER.value,
        "cloud_access_enabled": False,
        "request_access_enabled": bool(request_access_enabled),
        "parental_controls": parental_controls,
        "switch_profile_ids": [],
        "watching_profile_ids": list(watching_profile_ids or []),
    })


def create_household_invitation(event):
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if household_invitations_table is None:
        return response(503, {"state": "invitation_storage_unavailable"})
    profile_id = str(session.get("profile_id") or "")
    entitlement, _ = load_entitlements_for_profile(profile_id)
    if KAEVO_ENV in {"dev", "security-stage"} and not bool_value(entitlement.get("family_enabled"), False):
        entitlement = ensure_nonproduction_family_entitlement(profile_id) or entitlement
    if not bool_value(entitlement.get("family_enabled"), False):
        return response(409, {"state": "family_plan_required", "message": "Kaevo Family is required to invite a household member."})
    body = parse_json_body(event) or {}
    display_name = str(body.get("display_name") or "").strip()[:80]
    profile_type = str(body.get("profile_type") or "adult").strip().lower()
    age_classification = str(
        body.get("age_classification")
        or ("child" if profile_type == "kid" else "adult")
    ).strip().lower()
    access_mode = str(body.get("access_mode") or "device_invitation").strip().lower()
    requested_access_role = str(
        body.get("household_access_role") or HouseholdAccessRole.MEMBER.value
    ).strip().lower()
    request_access_enabled = bool_value(
        body.get("request_access_enabled"), False
    )
    cloud_access_enabled = bool_value(
        body.get("cloud_access_enabled"), access_mode == "device_invitation"
    )
    try:
        access_role = household_access_role(
            requested_access_role,
            canonical=canonical_role(age_classification),
        )
        switch_profile_ids = _invitation_switch_profile_ids(
            body.get("switch_profile_ids")
        )
        watching_profile_ids = _invitation_watching_profile_ids(
            body.get("watching_profile_ids")
        )
        # A current client must make a deliberate Kid viewing-level choice.
        # Preserve already-issued invitations that predate this field rather
        # than inventing an Older Kids default on the server.
        parental_controls = _normalized_parental_controls(
            body.get("parental_controls"),
            require_child_safe=(
                profile_type == "kid" and "parental_controls" in body
            ),
        )
    except (AccountFoundationError, ValueError):
        return response(400, {"state": "invalid_invitation_authority"})
    if (
        not display_name
        or profile_type not in {"adult", "kid"}
        or age_classification not in {"adult", "teen", "child"}
        or (profile_type == "kid") != (age_classification in {"teen", "child"})
        or access_role is HouseholdAccessRole.OWNER
    ):
        return response(400, {"state": "invalid_invitation"})
    issuer_access_role = str(
        session.get("household_access_role") or HouseholdAccessRole.MEMBER.value
    )
    if (
        issuer_access_role == HouseholdAccessRole.ADMIN.value
        and access_role is not HouseholdAccessRole.MEMBER
    ):
        return response(403, {"state": "owner_required_for_authority_grant"})
    if access_role is HouseholdAccessRole.ADMIN and age_classification != "adult":
        return response(400, {"state": "admin_requires_adult_profile"})
    if (
        watching_profile_ids
        and issuer_access_role != HouseholdAccessRole.OWNER.value
    ):
        return response(403, {"state": "watching_targets_owner_required"})
    if watching_profile_ids:
        if identity_profiles_table is None:
            return response(503, {"state": "identity_storage_unavailable"})
        for watching_profile_id in watching_profile_ids:
            watching_profile = identity_profiles_table.get_item(
                Key={"profile_id": watching_profile_id},
                ConsistentRead=True,
            ).get("Item")
            if (
                not isinstance(watching_profile, dict)
                or watching_profile.get("state") != "active"
                or not hmac.compare_digest(
                    str(watching_profile.get("account_id") or ""),
                    str(session.get("account_id") or ""),
                )
                or not hmac.compare_digest(
                    str(watching_profile.get("household_id") or ""),
                    str(session.get("household_id") or ""),
                )
            ):
                return response(400, {"state": "invalid_watching_targets"})
    if access_mode == "parent_managed":
        if (
            profile_type != "kid"
            or access_role is not HouseholdAccessRole.MEMBER
            or cloud_access_enabled
            or switch_profile_ids
        ):
            return response(400, {"state": "invalid_parent_managed_profile"})
        return create_parent_managed_kid_profile(
            session,
            display_name,
            entitlement,
            request_access_enabled=request_access_enabled,
            parental_controls=parental_controls,
            watching_profile_ids=watching_profile_ids,
        )
    if access_mode != "device_invitation":
        return response(400, {"state": "invalid_invitation_access_mode"})

    requested_profile_id = str(body.get("profile_id") or "").strip()
    managed_profile = None
    if requested_profile_id:
        if profile_type != "kid" or not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", requested_profile_id):
            return response(400, {"state": "invalid_managed_profile"})
        if identity_profiles_table is None:
            return response(503, {"state": "identity_storage_unavailable"})
        managed_profile = identity_profiles_table.get_item(
            Key={"profile_id": requested_profile_id}, ConsistentRead=True,
        ).get("Item")
        if not managed_profile:
            return response(404, {"state": "managed_profile_not_found"})
        expected = (
            hmac.compare_digest(str(managed_profile.get("account_id") or ""), str(session.get("account_id") or ""))
            and hmac.compare_digest(str(managed_profile.get("household_id") or ""), str(session.get("household_id") or ""))
            and hmac.compare_digest(str(managed_profile.get("owner_principal_id") or ""), str(session.get("principal_id") or ""))
            and bool(managed_profile.get("managed_by_owner"))
            and not str(managed_profile.get("member_principal_id") or "")
        )
        if not expected:
            return response(403, {"state": "managed_profile_mismatch"})
    if switch_profile_ids:
        if identity_profiles_table is None:
            return response(503, {"state": "identity_storage_unavailable"})
        for granted_profile_id in switch_profile_ids:
            granted_profile = identity_profiles_table.get_item(
                Key={"profile_id": granted_profile_id},
                ConsistentRead=True,
            ).get("Item")
            if (
                not isinstance(granted_profile, dict)
                or granted_profile.get("state") != "active"
                or not hmac.compare_digest(
                    str(granted_profile.get("account_id") or ""),
                    str(session.get("account_id") or ""),
                )
                or not hmac.compare_digest(
                    str(granted_profile.get("household_id") or ""),
                    str(session.get("household_id") or ""),
                )
            ):
                return response(400, {"state": "invalid_switch_profile_grants"})
    now = epoch_now()
    code_expires_at = now + HOUSEHOLD_INVITATION_CODE_TTL_SECONDS
    raw_code = secrets.token_hex(5).upper()
    join_code = f"{raw_code[:5]}-{raw_code[5:]}"
    invitation_id = f"invite_{secrets.token_urlsafe(18)}"
    profile_id = requested_profile_id or f"profile_{secrets.token_urlsafe(24)}"
    item = {
        "code_hash": _join_code_hash(join_code),
        "invitation_id": invitation_id,
        "account_id": str(session.get("account_id") or ""),
        "household_id": str(session.get("household_id") or ""),
        "owner_principal_id": str(session.get("principal_id") or ""),
        "owner_profile_id": str(session.get("profile_id") or ""),
        "profile_id": profile_id,
        "display_name": display_name,
        "profile_type": profile_type,
        "role": age_classification,
        "canonical_role": age_classification,
        "household_access_role": access_role.value,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
        "state": "pending",
        "managed_profile": bool(managed_profile),
        "created_at": utc_now_iso(),
        "code_expires_at": code_expires_at,
        # DynamoDB TTL is cleanup, not the security expiration. Keeping the
        # pending record longer lets an owner explicitly refresh an expired
        # code without creating a duplicate household member.
        "expires_at": now + HOUSEHOLD_INVITATION_RETENTION_SECONDS,
    }
    if managed_profile:
        try:
            dynamodb.meta.client.transact_write_items(TransactItems=[
                {"Update": {
                    "TableName": identity_profiles_table.name,
                    "Key": {"profile_id": profile_id},
                    "UpdateExpression": "SET pending_invitation_id = :invitation_id",
                    "ConditionExpression": "attribute_not_exists(pending_invitation_id) AND attribute_not_exists(member_principal_id)",
                    "ExpressionAttributeValues": {":invitation_id": invitation_id},
                }},
                {"Put": {
                    "TableName": household_invitations_table.name,
                    "Item": item,
                    "ConditionExpression": "attribute_not_exists(code_hash)",
                }},
            ])
        except ClientError as error:
            if str((error.response or {}).get("Error", {}).get("Code") or "") in {
                "ConditionalCheckFailedException", "TransactionCanceledException",
            }:
                return response(409, {"state": "managed_profile_invitation_exists"})
            raise
    else:
        household_invitations_table.put_item(Item=item, ConditionExpression="attribute_not_exists(code_hash)")
    return household_invitation_response(item, join_code, state="invitation_created")


def _household_invitation_records(household_id):
    """Read only one household invitation partition; never Scan.

    GSI results are re-read by their exact primary key before use because a
    DynamoDB secondary-index query cannot be strongly consistent.
    """
    if household_invitations_table is None or not household_id:
        return []
    records = []
    query = {
        "IndexName": "household_id-index",
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ConsistentRead": False,
    }
    while True:
        page = household_invitations_table.query(**query)
        for candidate in page.get("Items", []):
            code_hash = str(candidate.get("code_hash") or "")
            if not code_hash:
                continue
            exact = household_invitations_table.get_item(
                Key={"code_hash": code_hash}, ConsistentRead=True,
            ).get("Item")
            if (
                isinstance(exact, dict)
                and hmac.compare_digest(
                    str(exact.get("household_id") or ""), household_id,
                )
            ):
                records.append(exact)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def _household_invitation_by_id(household_id, invitation_id):
    if (
        not household_id
        or not re.fullmatch(r"invite_[A-Za-z0-9_-]{8,128}", str(invitation_id or ""))
    ):
        return None
    for item in _household_invitation_records(household_id):
        if hmac.compare_digest(
            str(item.get("invitation_id") or ""), str(invitation_id),
        ):
            return item
    return None


def refresh_household_invitation(event):
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if household_invitations_table is None:
        return response(503, {"state": "invitation_storage_unavailable"})
    body = parse_json_body(event) or {}
    invitation_id = str(body.get("invitation_id") or "").strip()
    if not re.fullmatch(r"invite_[A-Za-z0-9_-]{8,128}", invitation_id):
        return response(400, {"state": "invalid_invitation"})
    household_id = str(session.get("household_id") or "")
    invitation = _household_invitation_by_id(household_id, invitation_id)
    if not invitation:
        return response(404, {"state": "invitation_not_found"})
    current_state = str(invitation.get("state") or "pending")
    if current_state == "consumed":
        return response(409, {"state": "invitation_already_used"})
    if current_state != "pending":
        return response(409, {"state": "invitation_not_refreshable"})

    now = epoch_now()
    raw_code = secrets.token_hex(5).upper()
    join_code = f"{raw_code[:5]}-{raw_code[5:]}"
    refreshed = dict(invitation)
    refreshed.update({
        "code_hash": _join_code_hash(join_code),
        "code_expires_at": now + HOUSEHOLD_INVITATION_CODE_TTL_SECONDS,
        "expires_at": now + HOUSEHOLD_INVITATION_RETENTION_SECONDS,
        "refreshed_at": utc_now_iso(),
    })
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Delete": {
                "TableName": household_invitations_table.name,
                "Key": {"code_hash": str(invitation["code_hash"])},
                "ConditionExpression": "#state = :pending AND invitation_id = :invitation_id AND household_id = :household_id",
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {
                    ":pending": "pending",
                    ":invitation_id": invitation_id,
                    ":household_id": household_id,
                },
            }},
            {"Put": {
                "TableName": household_invitations_table.name,
                "Item": refreshed,
                "ConditionExpression": "attribute_not_exists(code_hash)",
            }},
        ])
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") in {
            "ConditionalCheckFailedException", "TransactionCanceledException",
        }:
            return response(409, {"state": "invitation_refresh_conflict"})
        raise
    return household_invitation_response(refreshed, join_code, state="invitation_refreshed")


def list_household_invitations(event):
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if household_invitations_table is None:
        return response(503, {"state": "invitation_storage_unavailable"})
    records = _household_invitation_records(
        str(session.get("household_id") or "")
    )
    now = epoch_now()
    public = []
    for item in records:
        state = str(item.get("state") or "pending")
        if state in {"revoked", "deleted", "deletion_pending"}:
            # Terminal/deleting workflow records are retained for recovery and
            # audit only. They are never household profile presentation data.
            continue
        code_expires_at = household_invitation_code_expiration(item)
        if state == "pending" and code_expires_at < now:
            state = "expired"
        try:
            age_classification = canonical_role(
                item.get("canonical_role")
                or item.get("role")
                or item.get("profile_type")
            ).value
        except AccountFoundationError:
            age_classification = ""
        projected = {
            "invitation_id": str(item.get("invitation_id") or ""),
            "profile_id": str(item.get("profile_id") or ""),
            "display_name": str(item.get("display_name") or "Household member"),
            "profile_type": str(item.get("profile_type") or "adult"),
            "canonical_role": age_classification,
            "household_access_role": str(item.get("household_access_role") or "member"),
            "cloud_access_enabled": bool_value(item.get("cloud_access_enabled"), True),
            "request_access_enabled": bool_value(
                item.get("request_access_enabled"), False
            ),
            "switch_profile_ids": list(item.get("switch_profile_ids") or []),
            "state": state,
            "expires_at": code_expires_at,
        }
        if "parental_controls" in item:
            projected["parental_controls"] = item.get("parental_controls")
        if "watching_profile_ids" in item:
            projected["watching_profile_ids"] = list(
                item.get("watching_profile_ids") or []
            )
        public.append(projected)
    return response(200, {"state": "invitations_listed", "invitations": public})


def revoke_household_invitation(event, path):
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    invitation_id = path.removeprefix("/v2/household/invitations/").removesuffix("/revoke").strip("/")
    household_id = str(session.get("household_id") or "")
    invitation = _household_invitation_by_id(household_id, invitation_id)
    if not invitation:
        return response(404, {"state": "invitation_not_found"})
    invitation["state"] = "revoked"
    invitation["revoked_at"] = utc_now_iso()
    invitation["expires_at"] = epoch_now() + HOUSEHOLD_INVITATION_RETENTION_SECONDS
    if bool(invitation.get("managed_profile")) and identity_profiles_table is not None:
        try:
            dynamodb.meta.client.transact_write_items(TransactItems=[
                {"Put": {
                    "TableName": household_invitations_table.name,
                    "Item": invitation,
                    "ConditionExpression": "#state = :pending",
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": {":pending": "pending"},
                }},
                {"Update": {
                    "TableName": identity_profiles_table.name,
                    "Key": {"profile_id": str(invitation.get("profile_id") or "")},
                    "UpdateExpression": "REMOVE pending_invitation_id",
                    "ConditionExpression": "pending_invitation_id = :invitation_id AND attribute_not_exists(member_principal_id)",
                    "ExpressionAttributeValues": {":invitation_id": invitation_id},
                }},
            ])
        except ClientError:
            return response(409, {"state": "invitation_revoke_conflict"})
    else:
        household_invitations_table.put_item(Item=invitation)
    return response(200, {"state": "invitation_revoked"})


def delete_household_invitation(event, path):
    """Permanently delete one exact, unconsumed household invitation.

    The household-scoped index is used only to resolve the exact primary key.
    The conditional delete then proves household, invitation, profile, and
    terminal eligibility together. Consumed invitations are never deleted by
    this workflow because they belong to an accepted identity graph.
    """
    session, error_response = household_manager_bound_session(event)
    if error_response:
        return error_response
    if household_invitations_table is None:
        return response(503, {"state": "invitation_storage_unavailable"})
    invitation_id = path.removeprefix("/v2/household/invitations/").strip("/")
    household_id = str(session.get("household_id") or "")
    invitation = _household_invitation_by_id(household_id, invitation_id)
    if not invitation:
        return response(200, {"state": "invitation_already_absent"})
    if str(invitation.get("state") or "") not in {"pending", "revoked", "deletion_pending"}:
        return response(409, {"state": "invitation_not_deletable"})
    code_hash = str(invitation.get("code_hash") or "")
    profile_id = str(invitation.get("profile_id") or "")
    if not code_hash or not profile_id:
        return response(409, {"state": "invitation_delete_manual_review"})
    try:
        household_invitations_table.delete_item(
            Key={"code_hash": code_hash},
            ConditionExpression=(
                "household_id = :household_id AND invitation_id = :invitation_id "
                "AND profile_id = :profile_id AND #state IN (:pending, :revoked, :deletion_pending)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":household_id": household_id,
                ":invitation_id": invitation_id,
                ":profile_id": profile_id,
                ":pending": "pending",
                ":revoked": "revoked",
                ":deletion_pending": "deletion_pending",
            },
        )
    except ClientError as error:
        if str((error.response or {}).get("Error", {}).get("Code") or "") == "ConditionalCheckFailedException":
            return response(409, {"state": "invitation_delete_conflict"})
        raise
    if _household_invitation_by_id(household_id, invitation_id):
        return response(409, {"state": "invitation_delete_not_confirmed"})
    return response(200, {"state": "invitation_deleted"})


def _promote_invitation_provider_bindings(profile, invitation, created_at):
    """Promote only complete, internally consistent exact provider tuples."""
    invitation_jellyfin_user_id = _normalized_jellyfin_user_id(
        invitation.get("jellyfin_user_id"),
    )
    invitation_jellyfin_connector_id = str(
        invitation.get("jellyfin_connector_id") or "",
    )
    if (
        str(invitation.get("jellyfin_binding_state") or "") == "active"
        and invitation_jellyfin_user_id
        and invitation_jellyfin_connector_id
    ):
        profile.update({
            "jellyfin_connector_id": invitation_jellyfin_connector_id,
            "jellyfin_user_id": invitation_jellyfin_user_id,
            "jellyfin_binding_state": "active",
            "jellyfin_binding_updated_at": str(
                invitation.get("jellyfin_binding_updated_at") or created_at,
            ),
        })

    invitation_seerr_user_id = _normalized_seerr_user_id(
        invitation.get("seerr_user_id"),
    )
    invitation_seerr_jellyfin_user_id = _normalized_jellyfin_user_id(
        invitation.get("seerr_jellyfin_user_id"),
    )
    invitation_seerr_connector_id = str(
        invitation.get("seerr_connector_id") or "",
    )
    if (
        str(invitation.get("seerr_binding_state") or "") == "active"
        and invitation_seerr_user_id
        and invitation_jellyfin_user_id
        and invitation_jellyfin_connector_id
        and hmac.compare_digest(
            invitation_seerr_jellyfin_user_id, invitation_jellyfin_user_id,
        )
        and hmac.compare_digest(
            invitation_seerr_connector_id, invitation_jellyfin_connector_id,
        )
    ):
        profile.update({
            "seerr_connector_id": invitation_seerr_connector_id,
            "seerr_jellyfin_user_id": invitation_seerr_jellyfin_user_id,
            "seerr_user_id": invitation_seerr_user_id,
            "seerr_binding_state": "active",
            "seerr_binding_updated_at": str(
                invitation.get("seerr_binding_updated_at") or created_at,
            ),
            "request_access_enabled": True,
        })
    return profile


def join_household(event):
    if not all((household_invitations_table, principals_table, identity_memberships_table, identity_profiles_table)):
        return response(503, {"state": "identity_storage_unavailable"})
    try:
        standard = validate_access_token_claims(
            _gateway_jwt_claims(event),
            expected_issuer=os.environ.get("EXPECTED_COGNITO_ISSUER", ""),
            expected_client_id=os.environ.get("EXPECTED_NATIVE_CLIENT_ID", ""),
            now=epoch_now(),
        )
    except AuthorityError:
        return response(401, {"state": "not_authorized"})
    subject = standard["sub"]
    body = parse_json_body(event) or {}
    resume_hash = _opaque_join_resume_hash(body.get("join_resume_handle"))
    resume = None
    if resume_hash:
        if household_join_transactions_table is None:
            return response(503, {"state": "household_join_unavailable"})
        resume = household_join_transactions_table.get_item(
            Key={"join_resume_hash": resume_hash}, ConsistentRead=True,
        ).get("Item")
        state = str(body.get("oauth_state") or "")
        if (
            not resume
            or str(resume.get("state") or "") != "awaiting_callback"
            or int(resume.get("expires_at") or 0) <= epoch_now()
            or not hmac.compare_digest(str(resume.get("device_binding_hash") or ""), _join_binding_hash(body.get("installation_id")))
            or not state
            or not hmac.compare_digest(str(resume.get("auth_state_hash") or ""), hashlib.sha256(state.encode("utf-8")).hexdigest())
        ):
            return response(409, {"state": "household_join_callback_mismatch"})
        code_hash = str(resume.get("invitation_code_hash") or "")
    else:
        # Compatibility path for already-issued clients. Intent-first clients
        # always complete using a callback-bound opaque transaction.
        code_hash = _join_code_hash(body.get("join_code"))
    invitation = household_invitations_table.get_item(Key={"code_hash": code_hash}, ConsistentRead=True).get("Item") if code_hash else None
    now = epoch_now()
    if not invitation or invitation.get("state") != "pending" or household_invitation_code_expiration(invitation) < now:
        return response(410, {"state": "invitation_invalid_or_expired"})
    existing_principal = principals_table.get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    if existing_principal:
        # A resume can safely continue only for the household that issued the
        # invitation; silently crossing households would reuse authority.
        if resume and hmac.compare_digest(
            str(existing_principal.get("household_id") or ""),
            str(invitation.get("household_id") or ""),
        ):
            return response(200, {"state": "already_member", "next": "refresh_identity"})
        return response(409, {"state": "identity_already_enrolled"})
    created_at = utc_now_iso()
    profile_id = str(invitation["profile_id"])
    account_id = str(invitation["account_id"])
    household_id = str(invitation["household_id"])
    try:
        age_role = canonical_role(
            invitation.get("canonical_role") or invitation.get("role")
        )
        access_role = household_access_role(
            invitation.get("household_access_role"), canonical=age_role
        )
        switch_profile_ids = _invitation_switch_profile_ids(
            invitation.get("switch_profile_ids")
        )
        watching_profile_ids = _invitation_watching_profile_ids(
            invitation.get("watching_profile_ids")
        )
    except (AccountFoundationError, ValueError):
        return response(409, {"state": "invitation_authority_invalid"})
    role = age_role.value
    household_access = access_role.value
    cloud_access_enabled = bool_value(
        invitation.get("cloud_access_enabled"), True
    )
    request_access_enabled = bool_value(
        invitation.get("request_access_enabled"), False
    )
    try:
        parental_controls = _normalized_parental_controls(
            invitation.get("parental_controls"),
            require_child_safe=(
                str(invitation.get("profile_type") or "") == "kid"
                and "parental_controls" in invitation
            ),
        )
    except ValueError:
        return response(409, {"state": "invitation_parental_controls_invalid"})
    principal = {
        "principal_id": subject, "account_id": account_id, "household_id": household_id,
        "role": role, "canonical_role": role,
        "household_access_role": household_access,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
        "authz_version": 1, "profile_ids": [profile_id],
        "state": "active", "revoked": False, "created_at": created_at,
    }
    membership = {
        "principal_id": subject, "account_id": account_id, "household_id": household_id,
        "profile_id": profile_id, "role": role, "canonical_role": role,
        "household_access_role": household_access,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
        "authz_version": 1,
        "state": "active", "created_at": created_at,
    }
    is_managed_profile = bool(invitation.get("managed_profile"))
    existing_managed_profile = identity_profiles_table.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item") if is_managed_profile else None
    if is_managed_profile and (
        not existing_managed_profile
        or not bool(existing_managed_profile.get("managed_by_owner"))
        or str(existing_managed_profile.get("member_principal_id") or "")
        or not hmac.compare_digest(str(existing_managed_profile.get("pending_invitation_id") or ""), str(invitation.get("invitation_id") or ""))
    ):
        return response(409, {"state": "managed_profile_binding_invalid"})
    profile = dict(existing_managed_profile or {})
    profile.update({
        "profile_id": profile_id, "account_id": account_id, "household_id": household_id,
        "owner_principal_id": str(invitation["owner_principal_id"]),
        "member_principal_id": subject, "display_name": str(invitation["display_name"]),
        "profile_type": str(invitation["profile_type"]),
        "role": role, "canonical_role": role,
        "household_access_role": household_access,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
        "state": "active",
        "created_at": str((existing_managed_profile or {}).get("created_at") or created_at),
        "device_access_enabled": True,
    })
    _promote_invitation_provider_bindings(profile, invitation, created_at)
    profile.pop("pending_invitation_id", None)
    consumed = dict(invitation)
    consumed.update({"state": "consumed", "consumed_at": created_at, "member_principal_id": subject})
    owner_entitlement, _ = load_entitlements_for_profile(str(invitation.get("owner_profile_id") or ""))
    member_entitlement = {
        "profile_id": profile_id,
        "entitlements_json": json.dumps(owner_entitlement, separators=(",", ":")),
        "created_at": created_at,
        "updated_at": created_at,
    }
    transaction = [
        {"Put": {"TableName": PRINCIPALS_TABLE, "Item": principal, "ConditionExpression": "attribute_not_exists(principal_id)"}},
        {"Put": {"TableName": IDENTITY_MEMBERSHIPS_TABLE, "Item": membership, "ConditionExpression": "attribute_not_exists(principal_id)"}},
        {"Put": {"TableName": HOUSEHOLD_INVITATIONS_TABLE, "Item": consumed, "ConditionExpression": "#state = :pending", "ExpressionAttributeNames": {"#state": "state"}, "ExpressionAttributeValues": {":pending": "pending"}}},
    ]
    if resume_hash:
        transaction.append({"Update": {
            "TableName": HOUSEHOLD_JOIN_TRANSACTIONS_TABLE,
            "Key": {"join_resume_hash": resume_hash},
            "UpdateExpression": "SET #state = :accepted, authenticated_subject = :subject, completed_at = :completed_at",
            "ConditionExpression": "#state = :awaiting AND expires_at > :now",
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": {":accepted": "membership_accepted", ":awaiting": "awaiting_callback", ":subject": subject, ":completed_at": created_at, ":now": epoch_now()},
        }})
    if is_managed_profile:
        transaction.append({"Put": {
            "TableName": IDENTITY_PROFILES_TABLE,
            "Item": profile,
            "ConditionExpression": "pending_invitation_id = :invitation_id AND attribute_not_exists(member_principal_id)",
            "ExpressionAttributeValues": {":invitation_id": str(invitation.get("invitation_id") or "")},
        }})
    else:
        transaction.extend([
            {"Put": {"TableName": IDENTITY_PROFILES_TABLE, "Item": profile, "ConditionExpression": "attribute_not_exists(profile_id)"}},
            {"Put": {"TableName": ENTITLEMENTS_TABLE, "Item": member_entitlement, "ConditionExpression": "attribute_not_exists(profile_id)"}},
            {"Update": {
                "TableName": PRINCIPALS_TABLE,
                "Key": {"principal_id": str(invitation["owner_principal_id"])},
                "UpdateExpression": "SET profile_ids = list_append(profile_ids, :profile)",
                "ConditionExpression": "contains(profile_ids, :owner_profile) AND NOT contains(profile_ids, :joined_profile)",
                "ExpressionAttributeValues": {
                    ":profile": [profile_id],
                    ":owner_profile": str(invitation["owner_profile_id"]),
                    ":joined_profile": profile_id,
                },
            }},
        ])
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError:
        return response(409, {"state": "invitation_already_used"})
    return response(201, {"state": "household_joined", "next": "authenticate_again"})


def list_owner_installations_v2(event):
    session, error_response = owner_bound_session(event)
    if error_response:
        return error_response
    records = installations_table.scan(
        FilterExpression=Attr("household_id").eq(str(session.get("household_id") or "")),
    ).get("Items", []) if installations_table else []
    devices = []
    for item in records:
        if not hmac.compare_digest(str(item.get("principal_id") or ""), str(session.get("principal_id") or "")):
            continue
        handle = str(item.get("management_handle") or "")
        if not handle:
            continue
        devices.append({
            "device_handle": handle,
            "device_label": str(item.get("device_label") or "Kaevo device"),
            "device_class": str(item.get("device_class") or "other"),
            "created_at": str(item.get("created_at") or ""),
            "last_seen_at": str(item.get("last_seen_at") or item.get("created_at") or ""),
            "is_current": hmac.compare_digest(str(item.get("installation_id") or ""), str(session.get("installation_id") or "")),
            "state": "revoked" if bool_value(item.get("revoked"), False) else "active",
        })
    devices.sort(key=lambda item: (not item["is_current"], item["device_label"], item["created_at"]))
    return response(200, {"state": "installations_listed", "devices": devices})


def revoke_installation_v2(event, path):
    device_handle = path.removeprefix("/v2/installations/").removesuffix("/revoke").strip("/")
    session, error_response = owner_bound_session(event)
    if error_response:
        return error_response
    records = installations_table.scan(
        FilterExpression=Attr("household_id").eq(str(session.get("household_id") or "")),
    ).get("Items", []) if installations_table else []
    installation = next((item for item in records if hmac.compare_digest(str(item.get("management_handle") or ""), device_handle)), None)
    if not installation or not hmac.compare_digest(str(installation.get("principal_id") or ""), str(session.get("principal_id") or "")):
        return response(404, {"state": "installation_not_found"})
    installation_id = str(installation.get("installation_id") or "")
    if bool_value(installation.get("revoked"), False):
        return response(200, {"state": "installation_revoked"})
    try:
        audit = prepare_security_audit(
            event, str(session.get("household_id") or ""), "installation_revoked", str(session.get("principal_id") or ""),
            target_id=installation_id, target_type="installation",
        )
    except AuditReferenceError:
        return audit_unavailable_response()
    installation["state"] = "revoked"
    installation["revoked"] = True
    installation["revoked_at"] = utc_now_iso()
    installations_table.put_item(Item=installation)
    records = app_sessions_table.query(
        IndexName="installation_id-created_at_epoch-index",
        KeyConditionExpression=Key("installation_id").eq(installation_id),
    ).get("Items", []) if app_sessions_table else []
    for family_id in {str(item.get("family_id") or "") for item in records}:
        revoke_session_family(family_id, "installation_revoked")
    commit_security_audit(audit)
    return response(200, {"state": "installation_revoked"})


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
    if not legacy_app_sessions_allowed():
        return response(410, {"state": "legacy_session_flow_disabled"})
    session = authenticated_app_session(event)
    if not session:
        return response(401, {"state": "unauthorized"})
    # DPoP-bound V2 access records own a separate rotating refresh token.
    # A legacy bearer refresh must never revoke or replace one.
    if session.get("record_type") == "access":
        return response(409, {"state": "bound_session_refresh_required"})
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
    session["state"] = "rotated"
    session["revoked"] = True
    session["expires_at"] = epoch_now()
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
    identity = None
    if not require_dev_key(event):
        try:
            identity, _ = authoritative_identity(event, "pair_connector")
        except IdentityError as error:
            return identity_error_response(error)
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})
    body = parse_json_body(event)
    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})
    if identity is None:
        if KAEVO_ENV not in {"dev", "development", "local", "test"}:
            return response(401, {"state": "not_authorized"})
        profile_id = str(body.get("profile_id") or "").strip()
        if not profile_id:
            return response(400, {"state": "bad_request"})
        connector_id, pairing_code, expires_at = create_pairing_record(profile_id, body.get("connector_name"))
        return response(201, {"state": "pairing_created", "connector_id": connector_id,
                              "pairing_code": pairing_code, "expires_at": expires_at})
    try:
        public_jwk = validate_public_jwk(body.get("public_jwk") or {})
        recovery_jwk = validate_public_jwk(body.get("recovery_public_jwk") or {})
        thumbprint = jwk_thumbprint(public_jwk)
        recovery_thumbprint = jwk_thumbprint(recovery_jwk)
        url = request_absolute_url(event)
        verify_dpop(str(header_value(event, "dpop") or ""), method=method_for(event), url=url,
                    expected_thumbprint=thumbprint, replay_guard=record_dpop_jti)
        verify_dpop(str(header_value(event, "dpop-recovery") or ""), method=method_for(event), url=url,
                    expected_thumbprint=recovery_thumbprint, replay_guard=record_dpop_jti)
        pairing_code = random_pairing_code()
        created = create_pairing_intent(
            client=dynamodb.meta.client, connectors=home_connectors_table,
            intents=app_sessions_table, audits=security_audit_table, identity=identity,
            environment=KAEVO_ENV, server_id=body.get("server_id"),
            local_nonce=body.get("local_nonce"),
            public_jwk_json=json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
            key_thumbprint=thumbprint,
            recovery_public_jwk_json=json.dumps(recovery_jwk, separators=(",", ":"), sort_keys=True),
            recovery_thumbprint=recovery_thumbprint,
            connector_name=str(body.get("connector_name") or "Kaevo Home Server"),
            pairing_code=pairing_code, request_id=request_correlation_id(event), now=epoch_now(),
        )
    except IdentityError as error:
        return identity_error_response(error)
    except LifecycleError as error:
        return response(error.status_code, {"state": error.reason})
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(201, {
        "state": "pairing_created",
        "connector_id": created["connector"]["connector_id"],
        "intent_id": created["intent"]["intent_id"],
        "pairing_code": pairing_code,
        "expires_at": created["intent"]["expires_at"],
        "credential_version": 1,
    })


def exchange_connector_pairing_v2(event):
    if home_connectors_table is None:
        return response(503, {"state": "connector_storage_unavailable"})
    body = parse_json_body(event)
    connector_id = str((body or {}).get("connector_id") or "").strip()
    intent_id = str((body or {}).get("intent_id") or "").strip()
    pairing_code = str((body or {}).get("pairing_code") or "").strip().upper()
    local_nonce = str((body or {}).get("local_nonce") or "").strip()
    if not connector_id or not intent_id or not pairing_code or not local_nonce:
        return response(400, {"state": "bad_request"})
    try:
        public_jwk = validate_public_jwk((body or {}).get("public_jwk") or {})
        thumbprint = jwk_thumbprint(public_jwk)
        verify_dpop(
            str(header_value(event, "dpop") or ""),
            method=method_for(event),
            url=request_absolute_url(event),
            expected_thumbprint=thumbprint,
            replay_guard=record_dpop_jti,
        )
    except IdentityError as error:
        return identity_error_response(error)
    candidate = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True
    ).get("Item")
    intent = opaque_intent(app_sessions_table, intent_id)
    pairing_valid = bool(candidate and intent) and all((
        candidate.get("state") == "pending_pairing",
        hmac.compare_digest(str(intent.get("pairing_code_hash") or ""), secret_hash(pairing_code)),
        int(intent.get("expires_at") or 0) >= epoch_now(), not candidate.get("key_thumbprint"),
    ))
    if not pairing_valid:
        return response(401, {"state": "pairing_invalid"})
    try:
        item = activate_intent(
            client=dynamodb.meta.client, connectors=home_connectors_table,
            intents=app_sessions_table, audits=security_audit_table, environment=KAEVO_ENV,
            intent=intent, connector=candidate, local_nonce=local_nonce,
            public_jwk_json=json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
            proposed_thumbprint=thumbprint, request_id=request_correlation_id(event), now=epoch_now(),
        )
    except LifecycleError as error:
        return response(error.status_code, {"state": "pairing_invalid"})
    return response(200, {
        "state": "paired",
        "connector_id": connector_id,
        "profile_id": item.get("profile_id"),
        "credential_type": "ES256_DPOP",
        "credential_version": item["credential_version"],
        "key_thumbprint": thumbprint,
        "server_id": item["server_id"],
    })


def start_connector_update_intent(event, path, operation):
    try:
        identity, _ = authoritative_identity(event, "pair_connector")
    except IdentityError as error:
        return identity_error_response(error)
    connector_id = path.split("/home-connectors/", 1)[-1].split("/", 1)[0]
    body = parse_json_body(event) or {}
    connector = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item") if home_connectors_table else None
    if not connector or not hmac.compare_digest(str(connector.get("server_id") or ""), str(body.get("server_id") or "")):
        return response(404, {"state": "connector_unavailable"})
    try:
        proposed_jwk = validate_public_jwk(body.get("public_jwk") or {})
        proposed_thumbprint = jwk_thumbprint(proposed_jwk)
        url = request_absolute_url(event)
        if operation == "rotate":
            if not require_connector_auth(event, connector_id):
                return response(401, {"state": "connector_unauthorized"})
        else:
            verify_dpop(str(header_value(event, "dpop-recovery") or ""), method=method_for(event), url=url,
                        expected_thumbprint=str(connector.get("recovery_key_thumbprint") or ""), replay_guard=record_dpop_jti)
        verify_dpop(str(header_value(event, "dpop-new") or ""), method=method_for(event), url=url,
                    expected_thumbprint=proposed_thumbprint, replay_guard=record_dpop_jti)
        intent = create_update_intent(
            operation=operation, client=dynamodb.meta.client, connectors=home_connectors_table,
            intents=app_sessions_table, audits=security_audit_table, identity=identity,
            environment=KAEVO_ENV, connector=connector, local_nonce=body.get("local_nonce"),
            proposed_public_jwk_json=json.dumps(proposed_jwk, separators=(",", ":"), sort_keys=True),
            proposed_thumbprint=proposed_thumbprint, request_id=request_correlation_id(event), now=epoch_now(),
        )
    except IdentityError as error:
        return identity_error_response(error)
    except LifecycleError as error:
        return response(error.status_code, {"state": error.reason})
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(201, {
        "state": f"{operation}_pending", "intent_id": intent["intent_id"],
        "connector_id": connector_id, "server_id": connector["server_id"],
        "current_version": intent["current_version"], "target_version": intent["target_version"],
        "expires_at": intent["expires_at"],
    })


def activate_connector_update_intent(event, path):
    intent_id = path.split("/lifecycle/intents/", 1)[-1].split("/", 1)[0]
    body = parse_json_body(event) or {}
    intent = opaque_intent(app_sessions_table, intent_id) if app_sessions_table else {}
    connector_id = str(intent.get("connector_id") or "")
    connector = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item") if home_connectors_table and connector_id else None
    if not intent or not connector or intent.get("operation") not in {"rotate", "recover"}:
        return response(401, {"state": "lifecycle_intent_invalid"})
    try:
        proposed_jwk = validate_public_jwk(body.get("public_jwk") or {})
        proposed_thumbprint = jwk_thumbprint(proposed_jwk)
        url = request_absolute_url(event)
        if intent["operation"] == "rotate":
            if not require_connector_auth(event, connector_id):
                return response(401, {"state": "connector_unauthorized"})
        else:
            verify_dpop(str(header_value(event, "dpop-recovery") or ""), method=method_for(event), url=url,
                        expected_thumbprint=str(connector.get("recovery_key_thumbprint") or ""), replay_guard=record_dpop_jti)
        verify_dpop(str(header_value(event, "dpop-new") or ""), method=method_for(event), url=url,
                    expected_thumbprint=proposed_thumbprint, replay_guard=record_dpop_jti)
        updated = activate_intent(
            client=dynamodb.meta.client, connectors=home_connectors_table, intents=app_sessions_table,
            audits=security_audit_table, environment=KAEVO_ENV, intent=intent, connector=connector,
            local_nonce=body.get("local_nonce"),
            public_jwk_json=json.dumps(proposed_jwk, separators=(",", ":"), sort_keys=True),
            proposed_thumbprint=proposed_thumbprint, request_id=request_correlation_id(event), now=epoch_now(),
        )
    except IdentityError as error:
        return identity_error_response(error)
    except LifecycleError as error:
        return response(error.status_code, {"state": "lifecycle_intent_invalid"})
    return response(200, {
        "state": "active", "operation": intent["operation"], "connector_id": connector_id,
        "server_id": updated["server_id"], "credential_version": updated["credential_version"],
        "key_thumbprint": updated["key_thumbprint"],
    })


def start_connector_unpair_intent(event, path):
    try:
        identity, _ = authoritative_identity(event, "revoke_connector")
    except IdentityError as error:
        return identity_error_response(error)
    connector_id = path.split("/home-connectors/", 1)[-1].split("/", 1)[0]
    body = parse_json_body(event) or {}
    connector = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item") if home_connectors_table else None
    if not connector or not hmac.compare_digest(str(connector.get("server_id") or ""), str(body.get("server_id") or "")):
        return response(404, {"state": "connector_unavailable"})
    try:
        intent = create_unpair_intent(
            client=dynamodb.meta.client, connectors=home_connectors_table, intents=app_sessions_table,
            audits=security_audit_table, identity=identity, environment=KAEVO_ENV, connector=connector,
            local_nonce=body.get("local_nonce"), request_id=request_correlation_id(event), now=epoch_now(),
        )
    except LifecycleError as error:
        return response(error.status_code, {"state": error.reason})
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(201, {
        "state": "unpair_pending", "intent_id": intent["intent_id"],
        "connector_id": connector_id, "server_id": connector["server_id"],
        "expires_at": intent["expires_at"],
    })


def activate_connector_unpair_intent(event, path):
    try:
        identity, _ = authoritative_identity(event, "revoke_connector")
    except IdentityError as error:
        return identity_error_response(error)
    intent_id = path.split("/lifecycle/intents/", 1)[-1].split("/", 1)[0]
    body = parse_json_body(event) or {}
    intent = opaque_intent(app_sessions_table, intent_id) if app_sessions_table else {}
    connector_id = str(intent.get("connector_id") or "")
    connector = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item") if home_connectors_table and connector_id else None
    if not intent or not connector or intent.get("operation") != "unpair":
        return response(401, {"state": "lifecycle_intent_invalid"})
    try:
        updated = activate_unpair_intent(
            client=dynamodb.meta.client, connectors=home_connectors_table, intents=app_sessions_table,
            audits=security_audit_table, identity=identity, environment=KAEVO_ENV,
            intent=intent, connector=connector, local_nonce=body.get("local_nonce"),
            request_id=request_correlation_id(event), now=epoch_now(),
        )
    except LifecycleError as error:
        return response(error.status_code, {"state": "lifecycle_intent_invalid"})
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(200, {
        "state": "unpaired", "connector_id": connector_id, "server_id": updated["server_id"]
    })


def cancel_connector_lifecycle_intent(event, path):
    try:
        identity, _ = authoritative_identity(event, "pair_connector")
    except IdentityError as error:
        return identity_error_response(error)
    intent_id = path.split("/lifecycle/intents/", 1)[-1].split("/", 1)[0]
    intent = opaque_intent(app_sessions_table, intent_id) if app_sessions_table else {}
    connector_id = str(intent.get("connector_id") or "")
    connector = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item") if home_connectors_table and connector_id else None
    if not intent or not connector:
        return response(404, {"state": "lifecycle_intent_unavailable"})
    try:
        cancel_intent(
            client=dynamodb.meta.client, connectors=home_connectors_table, intents=app_sessions_table,
            audits=security_audit_table, identity=identity, intent=intent, connector=connector,
            request_id=request_correlation_id(event), now=epoch_now(),
        )
    except LifecycleError as error:
        return response(error.status_code, {"state": error.reason})
    except AuditReferenceError:
        return audit_unavailable_response()
    return response(200, {"state": "canceled"})


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
    connector_token = secrets.token_urlsafe(32)
    playback_grant_key = secrets.token_urlsafe(32)
    now = utc_now_iso()
    try:
        item = home_connectors_table.update_item(
            Key={"connector_id": connector_id},
            ConditionExpression=(
                "auth_state = :pairing AND pairing_code_hash = :pairing_hash "
                "AND pairing_expires_at >= :now_epoch"
            ),
            UpdateExpression=(
                "SET auth_state = :active, connector_token_hash = :token_hash, "
                "playback_grant_key = :grant_key, paired_at = :now, updated_at = :now "
                "REMOVE pairing_code_hash, pairing_expires_at"
            ),
            ExpressionAttributeValues={
                ":pairing": "pairing",
                ":pairing_hash": secret_hash(pairing_code),
                ":now_epoch": epoch_now(),
                ":active": "active",
                ":token_hash": secret_hash(connector_token),
                ":grant_key": playback_grant_key,
                ":now": now,
            },
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(401, {"state": "pairing_invalid"})
        raise
    if not item:
        return response(401, {"state": "pairing_invalid"})
    return response(200, {
        "state": "paired",
        "connector_id": connector_id,
        "profile_id": item.get("profile_id"),
        "connector_token": connector_token,
        "playback_grant_key": playback_grant_key
    })


def revoke_home_connector(event, path):
    identity = None
    if not require_dev_key(event):
        try:
            identity, _ = authoritative_identity(event, "revoke_connector")
        except IdentityError as error:
            return identity_error_response(error)
    connector_id = path.removeprefix("/v1/home-connectors/").removesuffix("/revoke").strip("/")
    item = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item") if home_connectors_table else None
    if not item:
        return response(404, {"state": "not_found"})
    if identity and not hmac.compare_digest(str(item.get("profile_id") or ""), identity.profile_id):
        return response(404, {"state": "not_found"})
    if not item.get("server_id"):
        if KAEVO_ENV not in {"dev", "development", "local", "test"}:
            return response(409, {"state": "lifecycle_upgrade_required"})
        item["revoked"] = True
        item["auth_state"] = "revoked"
        item["updated_at"] = utc_now_iso()
        item.pop("connector_token_hash", None)
        home_connectors_table.put_item(Item=item)
        return response(200, {"state": "revoked", "connector_id": connector_id})
    current_revocation = int(item.get("revocation_version") or 0)
    updated = dict(item)
    updated.update({
        "revoked": True, "state": "revoked", "auth_state": "revoked",
        "revocation_version": current_revocation + 1, "revoked_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
    })
    for key in ("pending_intent_id", "pending_intent_expires_at", "proposed_public_jwk_json", "proposed_key_thumbprint"):
        updated.pop(key, None)
    binding = home_connectors_table.get_item(
        Key={"connector_id": binding_key(str(item["server_id"]))}, ConsistentRead=True,
    ).get("Item")
    if not binding or binding.get("active_connector_id") != connector_id:
        return response(409, {"state": "server_binding_invalid"})
    binding_updated = dict(binding)
    binding_updated.update({"state": "revoked", "updated_at": utc_now_iso()})
    try:
        audit = prepare_audit_item(
            scope_id=str(item.get("household_id") or ""), event_type="connector_revoked",
            actor_subject=identity.subject if identity else "development_owner",
            target_id=connector_id, target_type="connector", request_id=request_correlation_id(event), now=epoch_now(),
        )
    except AuditReferenceError:
        audit = fallback_audit_item(
            event_type="connector_revoked", result="success", reason_code="audit_key_unavailable", now=epoch_now(),
        )
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=[
            {"Put": {"TableName": home_connectors_table.name, "Item": updated,
                     "ConditionExpression": "revocation_version = :current AND attribute_exists(connector_id)",
                     "ExpressionAttributeValues": {":current": current_revocation}}},
            {"Put": {"TableName": home_connectors_table.name, "Item": binding_updated,
                     "ConditionExpression": "active_connector_id = :connector",
                     "ExpressionAttributeValues": {":connector": connector_id}}},
            {"Put": {"TableName": security_audit_table.name, "Item": audit,
                     "ConditionExpression": "attribute_not_exists(event_id)"}},
        ])
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "TransactionCanceledException":
            return response(409, {"state": "lifecycle_conflict"})
        raise
    return response(200, {"state": "revoked", "connector_id": connector_id})


def pairing_v3_profile_binding(connector, requested_profile_id):
    """Resolve an existing or safely backfilled V3 profile binding.

    New V3 redemptions persist the authoritative profile directly.  Connectors
    enrolled before that field existed may backfill exactly once, but only
    when the identity profile resolves to the same account and household
    hashes already bound by the Pairing Authorization.
    """
    bound_profile_id = str((connector or {}).get("profile_id") or "").strip()
    requested_profile_id = str(requested_profile_id or "").strip()
    if bound_profile_id:
        return bound_profile_id if not requested_profile_id or hmac.compare_digest(bound_profile_id, requested_profile_id) else ""
    if not requested_profile_id or identity_profiles_table is None:
        return ""
    profile = identity_profiles_table.get_item(Key={"profile_id": requested_profile_id}, ConsistentRead=True).get("Item")
    if not profile:
        return ""
    expected_account = pairing_v3_sha256_b64url(str(profile.get("account_id") or "").encode("utf-8"))
    expected_family = pairing_v3_sha256_b64url(str(profile.get("household_id") or "").encode("utf-8"))
    if not pairing_v3_constant_time_equal(str((connector or {}).get("account_binding") or ""), expected_account):
        return ""
    if not pairing_v3_constant_time_equal(str((connector or {}).get("family_binding") or ""), expected_family):
        return ""
    return requested_profile_id


def register_home_connector(event, *, pairing_v3=False):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    requested_profile_id = str(body.get("profile_id") or "").strip()

    if not pairing_v3 and not requested_profile_id:
        return response(400, {"state": "bad_request", "message": "profile_id is required"})

    connector_id = str(body.get("connector_id") or uuid.uuid4()).strip()
    authenticated = require_pairing_v3_connector_auth(event, connector_id, body) if pairing_v3 else require_connector_auth(event, connector_id)
    if not authenticated:
        return response(401, {"state": "connector_unauthorized"})
    now = utc_now_iso()
    now_epoch = epoch_now()

    existing = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")
    if not existing:
        return response(403, {"state": "connector_profile_mismatch"})
    profile_id = pairing_v3_profile_binding(existing, requested_profile_id) if pairing_v3 else str(existing.get("profile_id") or "")
    if not profile_id or (not pairing_v3 and not hmac.compare_digest(profile_id, requested_profile_id)):
        return response(403, {"state": "connector_profile_mismatch"})
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


def connector_id_from_heartbeat_path(path, *, pairing_v3=False):
    prefix = "/v3/home-connectors/" if pairing_v3 else "/v1/home-connectors/"
    suffix = "/heartbeat"

    if path.startswith(prefix) and path.endswith(suffix):
        return path[len(prefix):-len(suffix)].strip("/")

    return ""


def heartbeat_home_connector(event, path, *, pairing_v3=False):
    if home_connectors_table is None:
        return response(500, {"state": "server_error", "message": "home connectors table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    connector_id = connector_id_from_heartbeat_path(path, pairing_v3=pairing_v3) or str(body.get("connector_id") or "").strip()

    if not connector_id:
        return response(400, {"state": "bad_request", "message": "connector_id is required"})

    authenticated = require_pairing_v3_connector_auth(event, connector_id, body) if pairing_v3 else require_connector_auth(event, connector_id)
    if not authenticated:
        return response(401, {"state": "connector_unauthorized"})

    existing = home_connectors_table.get_item(Key={"connector_id": connector_id}).get("Item")

    requested_profile_id = str(body.get("profile_id") or "").strip()
    bound_profile_id = pairing_v3_profile_binding(existing, requested_profile_id) if pairing_v3 else str((existing or {}).get("profile_id") or "").strip()
    if not bound_profile_id or (not pairing_v3 and not hmac.compare_digest(bound_profile_id, requested_profile_id or bound_profile_id)):
        return response(403, {"state": "connector_profile_mismatch"})
    profile_id = bound_profile_id

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
    if not require_profile_switch_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    connectors = [
        public_connector_item(item, requesting_profile_id=profile_id)
        for item in _home_connectors_for_profile_access(profile_id)
    ]
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
    if not require_profile_switch_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    connectors = [
        public_connector_item(item, requesting_profile_id=profile_id)
        for item in _home_connectors_for_profile_access(profile_id)
    ]
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
REMOTE_REQUEST_IN_PROGRESS_LEASE_SECONDS = 120
REMOTE_REQUEST_COMPLETING_LEASE_SECONDS = 180
REMOTE_ARR_IDENTITY_BATCH_MAXIMUM = 32
REMOTE_COMMAND_ID_NAMESPACE = uuid.UUID("dd84f037-4c25-4b21-a393-6971989adddf")
SAFE_JELLYFIN_ITEM_ID = re.compile(r"^[0-9a-fA-F]{32}$")
SAFE_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
SAFE_APPROVAL_TOKEN = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
SAFE_DOWNLOAD_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
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
        media_segments_enabled = parameters.get("media_segments_enabled", False)
        if not isinstance(media_segments_enabled, bool):
            return None, "media_segments_enabled is invalid"
        playback_body = {
            "item_id": item_id.lower(),
            "device_id": device_id,
            "max_bitrate": max_bitrate,
        }
        if compatibility_player:
            playback_body["compatibility_player"] = True
        if media_segments_enabled:
            playback_body["media_segments_enabled"] = True
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

    if operation == "downloaders.set_queue_state":
        arr_kind = str(parameters.get("arr_kind") or "").strip().lower()
        arr_queue_id = positive_int(parameters.get("arr_queue_id"))
        arr_download_client_id = positive_int(parameters.get("arr_download_client_id"))
        download_id = str(parameters.get("download_id") or "").strip()
        target_state = str(parameters.get("target_state") or "").strip().lower()
        if arr_kind not in {"sonarr", "radarr"}:
            return None, "arr_kind must be sonarr or radarr"
        if arr_queue_id is None:
            return None, "arr_queue_id must be a positive integer"
        if arr_download_client_id is None:
            return None, "arr_download_client_id must be a positive integer"
        if not SAFE_DOWNLOAD_IDENTIFIER.fullmatch(download_id):
            return None, "download_id is invalid"
        if target_state not in {"paused", "running"}:
            return None, "target_state must be paused or running"
        return {
            "provider": "home_server",
            "method": "COMMAND",
            "path": "/commands/downloaders.set_queue_state",
            "query": {},
            "body": {
                "arr_kind": arr_kind,
                "arr_queue_id": arr_queue_id,
                "arr_download_client_id": arr_download_client_id,
                "download_id": download_id,
                "target_state": target_state,
            },
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

    synthetic_keys = {"tmdbIds", "tvdbIds"}
    supplied_synthetic_keys = synthetic_keys.intersection((query or {}).keys())
    if supplied_synthetic_keys:
        expected = {
            ("radarr", "/api/v3/movie"): "tmdbIds",
            ("sonarr", "/api/v3/series"): "tvdbIds",
        }.get((provider, path))
        if supplied_synthetic_keys != {expected} or len(query or {}) != 1:
            return False, "invalid Arr identity batch"
        raw_values = str((query or {}).get(expected) or "")
        parts = raw_values.split(",")
        if not (1 <= len(parts) <= REMOTE_ARR_IDENTITY_BATCH_MAXIMUM):
            return False, "Arr identity batch exceeds limit"
        if any(not re.fullmatch(r"[1-9]\d*", part) for part in parts):
            return False, "Arr identity batch must contain positive integers"
        if len(set(parts)) != len(parts):
            return False, "Arr identity batch contains duplicates"

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
    prefix = "/v3/remote-requests/" if path.startswith("/v3/remote-requests/") else "/v1/remote-requests/"

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
    if method == "COMMAND" and path == "/commands/downloaders.set_queue_state":
        # A user explicitly pressed Start or Pause. Keep it ahead of ordinary
        # provider work, while preserving playback preparation as the top
        # priority.
        return 1
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


def connector_remote_request_item(item):
    """Project one claimed request plus its connector-confined provider edge."""
    result = public_remote_request_item(item, include_payload=False)
    profile_id = str(item.get("profile_id") or "")
    connector_id = str(item.get("connector_id") or "")
    binding = _profile_jellyfin_binding_for_connector(profile_id, connector_id)
    if binding is not None:
        result["profile_provider_binding"] = binding
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

    for item in _home_connectors_for_profile_access(profile_id):
        if connector_online_from_item(item):
            return item

    return None


def _authorized_seerr_request_query(profile_id, query):
    """Return the least-privileged Seerr request-list query for this profile.

    Remote metadata is credentialless on iOS.  The Household Owner may read
    the household's request/download status; Admins and Members may read only
    the requests associated with their own plugin-proven immutable Seerr user
    id.  The client never chooses that scope, so a forged ``requestedBy``
    query cannot enumerate another household member's requests.
    """
    if identity_profiles_table is None:
        return None, "profile_identity_unavailable"
    try:
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True
        ).get("Item")
    except ClientError:
        return None, "profile_identity_unavailable"

    if (
        not isinstance(profile, dict)
        or str(profile.get("profile_id") or "") != profile_id
        or str(profile.get("state") or "") != "active"
    ):
        return None, "profile_seerr_binding_required"

    scoped = dict(query or {})

    # The household membership is the canonical authority for an Owner's
    # household-wide *read*.  Identity profiles deliberately do not duplicate
    # every provider edge, so requiring an Owner's personal Seerr binding here
    # made a valid Owner receive an empty dashboard.  We still require the
    # exact Seerr binding below for every non-Owner scope and for all commands.
    # This is an exact household/account membership read; display names and
    # provider aliases are never consulted.
    membership_role = ""
    membership_found = False
    household_id = str(profile.get("household_id") or "")
    account_id = str(profile.get("account_id") or "")
    if household_memberships_table is not None and household_id and account_id:
        try:
            membership = household_memberships_table.get_item(Key={
                "household_id": household_id,
                "membership_id": household_membership_id(account_id, household_id),
            }, ConsistentRead=True).get("Item")
        except ClientError:
            membership = None
        if (
            isinstance(membership, dict)
            and membership.get("entity_type") == "HouseholdMembership"
            and membership.get("status") == "active"
            and str(membership.get("household_id") or "") == household_id
            and str(membership.get("account_id") or "") == account_id
            and str(membership.get("profile_id") or "") == profile_id
        ):
            membership_found = True
            membership_role = str(membership.get("household_access_role") or "").lower()

    # Keep the legacy profile projection as a compatibility fallback only when
    # a canonical membership record is unavailable.  It never overrides an
    # exact membership record.
    effective_role = (
        membership_role
        if membership_found
        else str(profile.get("household_access_role") or "").lower()
    )
    if effective_role == HouseholdAccessRole.OWNER.value:
        scoped.pop("requestedBy", None)
        return scoped, ""

    if str(profile.get("seerr_binding_state") or "") != "active":
        return None, "profile_seerr_binding_required"

    seerr_user_id = _normalized_seerr_user_id(profile.get("seerr_user_id"))
    if not seerr_user_id:
        return None, "profile_seerr_binding_required"

    supplied = str(scoped.get("requestedBy") or "").strip()
    if supplied and not hmac.compare_digest(supplied, seerr_user_id):
        return None, "profile_seerr_request_scope_conflict"

    scoped["requestedBy"] = seerr_user_id
    return scoped, ""


def _profile_scoped_seerr_response(profile_id, request_payload, response_payload):
    """Remove other members' request records from one Seerr response.

    Request-list queries are already scoped before they reach the connector,
    but Seerr media-detail responses can embed ``mediaInfo.requests`` for
    multiple users.  Those records also drive the iOS download projection, so
    the Cloud boundary must apply the same canonical Owner-or-exact-user rule
    before storing or returning a connector completion.  Provider display
    names and client-supplied ids are never used for this decision.
    """
    if not isinstance(request_payload, dict):
        return response_payload
    if str(request_payload.get("provider") or "").lower() != "seerr":
        return response_payload
    if not isinstance(response_payload, (dict, list)):
        return response_payload

    scoped_query, _reason = _authorized_seerr_request_query(profile_id, {})
    if scoped_query is None:
        exact_seerr_user_id = None
        fail_closed = True
    else:
        exact_seerr_user_id = str(scoped_query.get("requestedBy") or "").strip()
        # No requestedBy constraint is the exact canonical Owner scope.
        if not exact_seerr_user_id:
            return response_payload
        fail_closed = False

    def request_belongs_to_profile(record):
        if fail_closed or not isinstance(record, dict):
            return False
        requester = record.get("requestedBy")
        if not isinstance(requester, dict):
            return False
        requester_id = _normalized_seerr_user_id(requester.get("id"))
        return bool(requester_id) and hmac.compare_digest(
            requester_id, exact_seerr_user_id,
        )

    def sanitize(value):
        if isinstance(value, list):
            return [sanitize(entry) for entry in value]
        if not isinstance(value, dict):
            return value

        sanitized = {key: sanitize(entry) for key, entry in value.items()}
        media_info = sanitized.get("mediaInfo")
        if isinstance(media_info, dict) and isinstance(media_info.get("requests"), list):
            media_info["requests"] = [
                record for record in media_info["requests"]
                if request_belongs_to_profile(record)
            ]

        # Defensively preserve the same scope if a Seerr request-list payload
        # reaches completion without the provider honoring requestedBy.
        if (
            str(request_payload.get("path") or "") == "/api/v1/request"
            and isinstance(sanitized.get("results"), list)
        ):
            sanitized["results"] = [
                record for record in sanitized["results"]
                if request_belongs_to_profile(record)
            ]
        return sanitized

    return sanitize(response_payload)


def _authorized_seerr_requester_for_command(profile_id, connector_id):
    """Return the exact bound Seerr user for one protected create command.

    A device may prove only its Cloud profile session.  It must never be able
    to choose a Seerr requester id itself: that would let a forged command
    impersonate another household member.  Resolve the requester from the
    canonical profile record and require the same connector that will execute
    the command.
    """
    if identity_profiles_table is None:
        return None, "profile_identity_unavailable"
    try:
        profile = identity_profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
    except Exception:
        return None, "profile_identity_unavailable"

    if (
        not isinstance(profile, dict)
        or str(profile.get("profile_id") or "") != profile_id
        or str(profile.get("state") or "") != "active"
        or str(profile.get("seerr_binding_state") or "") != "active"
        or not hmac.compare_digest(
            str(profile.get("seerr_connector_id") or ""), str(connector_id or ""),
        )
    ):
        return None, "profile_seerr_binding_required"

    is_owner = str(profile.get("household_access_role") or "").lower() == HouseholdAccessRole.OWNER.value
    if not is_owner and not bool_value(profile.get("request_access_enabled"), False):
        return None, "profile_request_access_required"

    seerr_user_id = _normalized_seerr_user_id(profile.get("seerr_user_id"))
    if not seerr_user_id:
        return None, "profile_seerr_binding_required"
    return seerr_user_id, ""


def _authorized_jellyfin_metadata_request(profile_id, connector_id, path, query):
    """Bind remote Jellyfin metadata reads to the caller's exact profile edge.

    A joined iOS device deliberately has no other household member's Jellyfin
    user ID.  Cloud therefore owns the final identity injection for the small
    set of user-scoped metadata routes.  Never honour a client-supplied
    ``userId`` or ``/Users/<id>`` segment for these reads.
    """
    binding = _profile_jellyfin_binding_for_connector(profile_id, connector_id)
    if binding is None:
        return None, None, "profile_jellyfin_binding_required"

    user_id = binding["provider_user_id"]
    rewritten_path = str(path or "")
    rewritten_query = {
        key: value
        for key, value in dict(query or {}).items()
        if str(key).lower() != "userid"
    }

    if re.fullmatch(r"/Users/[0-9a-fA-F]{32}/Views", rewritten_path):
        rewritten_path = f"/Users/{user_id}/Views"
    elif re.fullmatch(r"/Users/[0-9a-fA-F]{32}/Items", rewritten_path):
        rewritten_path = f"/Users/{user_id}/Items"
    elif re.fullmatch(r"/Users/[0-9a-fA-F]{32}/Items/[0-9a-fA-F]{32}", rewritten_path):
        item_id = rewritten_path.rsplit("/", 1)[-1]
        rewritten_path = f"/Users/{user_id}/Items/{item_id}"

    if re.fullmatch(r"/Shows/[0-9a-fA-F]{32}/(Seasons|Episodes)", rewritten_path):
        rewritten_query["userId"] = user_id

    return rewritten_path, rewritten_query, ""


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
    if not require_profile_switch_auth(event, profile_id):
        return response(401, {"state": "unauthorized"})

    if method != "GET":
        return response(400, {"state": "bad_request", "message": "only GET is supported in remote metadata v0"})

    allowed, reason = is_safe_remote_path(provider, path, query)
    if not allowed:
        return response(400, {"state": "bad_request", "message": reason})

    if provider == "seerr" and path == "/api/v1/request":
        query, reason = _authorized_seerr_request_query(profile_id, query)
        if query is None:
            return response(409, {"state": reason})

    connector = latest_online_connector_for_profile(profile_id)

    if not connector:
        return response(409, {
            "state": "connector_unavailable",
            "message": "No online Kaevo Jellyfin Plugin is available for this profile."
        })

    now = utc_now_iso()
    request_id = str(uuid.uuid4())
    connector_id = connector.get("connector_id")

    if provider == "jellyfin":
        path, query, reason = _authorized_jellyfin_metadata_request(
            profile_id,
            connector_id,
            path,
            query,
        )
        if path is None:
            return response(409, {"state": reason})

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
        "jellyfin.mark_played",
        "jellyfin.mark_unplayed",
        "jellyfin.prepare_playback",
        "jellyfin.playback_started",
        "jellyfin.playback_progress",
        "jellyfin.playback_stopped",
        "provider.health",
        "optimizer.scan",
        "optimizer.plan_remux",
        "optimizer.job_status",
        "optimizer.jobs",
        "seerr.create_request",
        "sonarr.episode_inventory",
    }
    owner_authorized_operations = {
        "downloaders.set_queue_state",
        "sonarr.search_episodes",
    }
    switch_authorized_operations = {
        "jellyfin.mark_played",
        "jellyfin.mark_unplayed",
        "jellyfin.prepare_playback",
        "jellyfin.playback_started",
        "jellyfin.playback_progress",
        "jellyfin.playback_stopped",
        "seerr.create_request",
        "sonarr.episode_inventory",
    }
    protected_profile_session = None
    if operation in owner_authorized_operations:
        owner_error = authorize_protected_owner_download_command(event, profile_id)
        if owner_error:
            return owner_error
    elif not require_dev_key(event):
        if operation not in profile_authorized_operations:
            return response(401, {"state": "unauthorized"})
        if operation in switch_authorized_operations:
            authorized, protected_profile_session = authorize_profile_switch_session(
                event, profile_id,
            )
            if not authorized:
                return response(401, {"state": "unauthorized"})
        elif not require_profile_auth(event, profile_id):
            return response(401, {"state": "unauthorized"})
    if not SAFE_IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        return response(400, {"state": "bad_request", "message": "idempotency_key must be 8-128 safe characters"})

    request_payload, error = normalize_remote_command(operation, parameters)
    if request_payload is None:
        return response(400, {"state": "bad_request", "message": error})
    if (
        operation == "jellyfin.prepare_playback"
        and protected_profile_session
        and protected_profile_session.get("record_type") == "access"
        and not hmac.compare_digest(
            str(protected_profile_session.get("device_id") or ""),
            str(request_payload.get("body", {}).get("device_id") or ""),
        )
    ):
        # Deliberately opaque: the caller must never learn whether another
        # installation exists, and a connector-prepared grant must remain
        # bound to the DPoP session's exact device.
        return response(404, {"state": "target_not_found"})

    connector = latest_online_connector_for_profile(profile_id)
    if not connector:
        return response(409, {
            "state": "connector_unavailable",
            "message": "No online Kaevo Jellyfin Plugin is available for this profile."
        })

    if operation == "seerr.create_request":
        requester_user_id, requester_error = _authorized_seerr_requester_for_command(
            profile_id, connector.get("connector_id"),
        )
        if not requester_user_id:
            return response(409, {"state": requester_error})
        # `normalize_remote_command` deliberately discards client-supplied
        # identity fields. Add only the canonical, connector-bound Seerr id
        # derived above so the plugin can submit as the requested profile.
        command_body = dict(request_payload["body"])
        command_body["requester_user_id"] = int(requester_user_id)
        request_payload = {**request_payload, "body": command_body}

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


def _bounded_trickplay_metadata(value):
    """Return only the exact bounded sprite geometry safe for a relay grant."""
    if not isinstance(value, dict):
        return None
    bounds = {
        "width": 8192,
        "height": 8192,
        "tile_width": 100,
        "tile_height": 100,
        "thumbnail_count": 1_000_000,
        "interval": 3_600_000,
    }
    normalized = {}
    for field, maximum in bounds.items():
        candidate = value.get(field)
        if isinstance(candidate, bool) or not isinstance(candidate, int) or not 1 <= candidate <= maximum:
            return None
        normalized[field] = candidate
    return normalized


def _bounded_media_segments(value, expected_item_id):
    if not isinstance(value, list):
        return []
    normalized = []
    for candidate in value[:32]:
        if not isinstance(candidate, dict):
            continue
        item_id = str(candidate.get("item_id") or "").strip().lower()
        segment_id = str(candidate.get("id") or "").strip()
        segment_type = str(candidate.get("type") or "").strip().title()
        start_ticks = candidate.get("start_ticks")
        end_ticks = candidate.get("end_ticks")
        if not (
            hmac.compare_digest(item_id, expected_item_id)
            and segment_type in {"Intro", "Recap"}
            and 0 < len(segment_id) <= 128
            and not isinstance(start_ticks, bool)
            and isinstance(start_ticks, int)
            and not isinstance(end_ticks, bool)
            and isinstance(end_ticks, int)
            and 0 <= start_ticks < end_ticks <= 6_048_000_000_000
            and end_ticks - start_ticks <= 18_000_000_000
        ):
            continue
        normalized.append({
            "id": segment_id,
            "item_id": item_id,
            "type": segment_type,
            "start_ticks": start_ticks,
            "end_ticks": end_ticks,
        })
    return normalized


def _issued_playback_grant(
    *, profile_id, device_id, item_id, media_source_id,
    playback_session_id, mode, max_bitrate, connector, trickplay=None,
    expires_at_cap=None, active_until=None,
):
    """Mint one exact, short-lived relay capability after caller validation."""
    pairing_v3_connector = pairing_v3_connector_can_issue_playback_grants(connector)
    if not pairing_v3_connector and (
        connector.get("auth_state") != "active" or not connector.get("playback_grant_key")
    ):
        return None
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
        "exp": min(
            now + PLAYBACK_GRANT_TTL_SECONDS,
            int(expires_at_cap),
        ) if expires_at_cap else now + PLAYBACK_GRANT_TTL_SECONDS,
    }
    if expires_at_cap:
        # Unlike the short issuance window in ``exp``, this bound is enforced
        # by the relay after a grant has activated. It is what makes a Guest
        # Pass hard stop remain authoritative during an already-open stream.
        payload["active_until"] = int(expires_at_cap)
    elif active_until:
        # A finish-current-video Guest Pass is allowed to outlive the pass
        # window only for this exact prepared title. Bound that exception to
        # the trusted runtime (plus a small startup buffer), never the relay's
        # general activated-grant lifetime.
        payload["active_until"] = int(active_until)
    normalized_trickplay = _bounded_trickplay_metadata(trickplay)
    if normalized_trickplay is not None:
        payload["trickplay"] = normalized_trickplay
    try:
        payload = (
            pairing_v3_playback_grant_payload(payload)
            if pairing_v3_connector
            else add_home_connector_signature(payload, connector["playback_grant_key"])
        )
    except PairingV3CryptoError:
        return None
    token = sign_playback_grant(payload)
    if token is None:
        return None
    return {
        "state": "issued",
        "grant": token,
        "grant_id": payload["grant_id"],
        "expires_at": payload["exp"],
        "connector_id": payload["connector_id"],
        "relay_base_url": (
            f"{PLAYBACK_RELAY_PUBLIC_URL}/v1/playback/{avfoundation_safe_grant_path(token)}"
            if PLAYBACK_RELAY_PUBLIC_URL else ""
        ),
    }


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
    authorized, app_session = authorize_profile_switch_session(event, profile_id)
    if not authorized:
        return response(401, {"state": "unauthorized"})
    if not device_id or not SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id):
        return response(400, {"state": "bad_request", "message": "invalid device_id"})
    if (
        app_session
        and app_session.get("record_type") == "access"
        and not hmac.compare_digest(str(app_session.get("device_id") or ""), device_id)
    ):
        # Deliberately opaque: do not reveal whether another installation exists.
        return response(404, {"state": "target_not_found"})
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
    if not connector:
        return response(409, {"state": "connector_unavailable"})
    max_bitrate = positive_int(body.get("max_bitrate") or 40_000_000, maximum=100_000_000)
    if max_bitrate is None:
        return response(400, {"state": "bad_request", "message": "invalid max_bitrate"})
    issued = _issued_playback_grant(
        profile_id=profile_id,
        device_id=device_id,
        item_id=item_id,
        media_source_id=media_source_id,
        playback_session_id=playback_session_id,
        mode=mode,
        max_bitrate=max_bitrate,
        connector=connector,
        trickplay=body.get("trickplay"),
    )
    if issued is None:
        return response(409, {"state": "connector_unavailable"})
    return response(201, issued)


def _completion_with_embedded_playback_grant(item, response_payload):
    """Attach a grant to one authenticated prepare-playback completion.

    The connector completion and the original protected command jointly own
    every claim. Invalid or stale context fails closed to the existing
    separately-authorized grant endpoint; it never blocks recording the
    connector's completion.
    """
    if not isinstance(response_payload, dict) or home_connectors_table is None:
        return response_payload
    request_payload = parse_json_field(item.get("request_json"), {})
    request_body = request_payload.get("body") if isinstance(request_payload, dict) else None
    result = response_payload.get("result")
    if not (
        request_payload.get("method") == "COMMAND"
        and request_payload.get("path") == "/commands/jellyfin.prepare_playback"
        and isinstance(request_body, dict)
        and isinstance(result, dict)
    ):
        return response_payload

    profile_id = str(item.get("profile_id") or "").strip()
    connector_id = str(item.get("connector_id") or "").strip()
    device_id = str(request_body.get("device_id") or "").strip()
    requested_item_id = str(request_body.get("item_id") or "").strip().lower()
    item_id = str(result.get("item_id") or "").strip().lower()
    media_source_id = str(result.get("media_source_id") or "").strip()
    playback_session_id = str(result.get("playback_session_id") or "").strip()
    mode = str(result.get("mode") or "").strip().lower()
    requested_max_bitrate = positive_int(
        request_body.get("max_bitrate") or 40_000_000,
        maximum=100_000_000,
    )
    max_bitrate = positive_int(
        result.get("max_bitrate") or requested_max_bitrate,
        maximum=100_000_000,
    )
    guest_expires_at_cap = None
    guest_active_until = None
    guest_pass_id = str(item.get("guest_pass_id") or "").strip()
    if not (
        SAFE_PLAYBACK_IDENTIFIER.fullmatch(profile_id)
        and SAFE_PLAYBACK_IDENTIFIER.fullmatch(device_id)
        and SAFE_JELLYFIN_ITEM_ID.fullmatch(item_id)
        and hmac.compare_digest(item_id, requested_item_id)
        and SAFE_PLAYBACK_IDENTIFIER.fullmatch(media_source_id)
        and SAFE_PLAYBACK_IDENTIFIER.fullmatch(playback_session_id)
        and mode in {"direct_play", "remux", "transcode"}
        and requested_max_bitrate is not None
        and max_bitrate is not None
        and max_bitrate <= requested_max_bitrate
    ):
        return response_payload

    entitlements, _ = load_entitlements_for_profile(profile_id)
    if not (
        bool_value(entitlements.get("cloud_enabled"), False)
        and str(entitlements.get("subscription_state") or "").lower()
        in {"active", "trialing", "grace_period"}
    ):
        return response_payload
    connector = home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(connector, dict):
        return response_payload
    if guest_pass_id:
        if guest_passes_table is None:
            return {**response_payload, "result": {"state": "guest_pass_unavailable"}}
        candidate = guest_passes_table.get_item(
            Key={"pass_id": guest_pass_id}, ConsistentRead=True,
        ).get("Item")
        ancestry = {
            "show": str(result.get("series_id") or "").strip().lower(),
            "season": str(result.get("season_id") or "").strip().lower(),
        }
        if not (
            isinstance(candidate, dict)
            and hmac.compare_digest(str(candidate.get("source_profile_id") or ""), profile_id)
            and guest_pass_scope_authorizes(
                candidate.get("scope") or {},
                item_id=item_id,
                item_kind=str(result.get("item_kind") or "").strip().lower(),
                ancestor_ids=ancestry,
            )
        ):
            return {**response_payload, "result": {"state": "guest_scope_denied"}}
        active_guest_pass = _activate_guest_pass_for_playback(candidate, item_id)
        if active_guest_pass is None:
            return {**response_payload, "result": {"state": "guest_pass_unavailable"}}
        runtime_ticks = positive_int(
            result.get("runtime_ticks"), maximum=6_048_000_000_000,
        ) or 0
        try:
            guest_passes_table.update_item(
                Key={"pass_id": guest_pass_id},
                UpdateExpression="SET active_playback = :active_playback",
                ConditionExpression="#state = :active",
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":active": "active",
                    ":active_playback": {
                        "item_id": item_id,
                        "playback_session_id": playback_session_id,
                        "runtime_ticks": runtime_ticks,
                        "prepared_at": utc_now_iso(),
                    },
                },
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return {**response_payload, "result": {"state": "guest_pass_unavailable"}}
            raise
        if str(active_guest_pass.get("expiration_behavior") or "") == "hard_stop":
            guest_expires_at_cap = int(active_guest_pass.get("access_expires_at") or 0) or None
        else:
            runtime_seconds = min(max(runtime_ticks // 10_000_000, 0), 43_200)
            guest_active_until = epoch_now() + max(runtime_seconds + 600, 900)
    issued = _issued_playback_grant(
        profile_id=profile_id,
        device_id=device_id,
        item_id=item_id,
        media_source_id=media_source_id,
        playback_session_id=playback_session_id,
        mode=mode,
        max_bitrate=max_bitrate,
        connector=connector,
        trickplay=result.get("trickplay"),
        expires_at_cap=guest_expires_at_cap,
        active_until=guest_active_until,
    )
    if issued is None or not issued.get("relay_base_url"):
        return response_payload
    embedded = dict(issued)
    embedded.pop("grant", None)
    updated_result = dict(result)
    if request_body.get("media_segments_enabled") is True:
        updated_result["media_segments"] = _bounded_media_segments(
            result.get("media_segments"), item_id,
        )
    else:
        updated_result.pop("media_segments", None)
    updated_result["playback_grant"] = embedded
    return {**response_payload, "result": updated_result}


def get_remote_request(event, path):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    request_id = remote_request_path_id(path)

    if not request_id or request_id == "claim":
        return response(404, {"state": "not_found"})

    item = remote_requests_table.get_item(Key={"request_id": request_id}).get("Item")

    if not item:
        return response(404, {"state": "not_found", "request_id": request_id})
    profile_id = str(item.get("profile_id") or "")
    try:
        request_payload = json.loads(str(item.get("request_json") or "{}"))
    except json.JSONDecodeError:
        request_payload = {}
    owner_download_command_paths = {
        "/commands/downloaders.set_queue_state",
        "/commands/sonarr.search_episodes",
    }
    is_owner_download_command = (
        isinstance(request_payload, dict)
        and request_payload.get("method") == "COMMAND"
        and request_payload.get("path") in owner_download_command_paths
    )
    if is_owner_download_command:
        owner_error = authorize_protected_owner_download_command(event, profile_id)
        if owner_error:
            return owner_error
    else:
        switch_authorized_paths = {
            "/commands/jellyfin.mark_played",
            "/commands/jellyfin.mark_unplayed",
            "/commands/jellyfin.prepare_playback",
            "/commands/jellyfin.playback_started",
            "/commands/jellyfin.playback_progress",
            "/commands/jellyfin.playback_stopped",
            "/commands/seerr.create_request",
            "/commands/sonarr.episode_inventory",
        }
        permits_switch = (
            isinstance(request_payload, dict)
            and (
                request_payload.get("method") == "GET"
                or request_payload.get("path") in switch_authorized_paths
            )
        )
        authorized = (
            require_profile_switch_auth(event, profile_id)
            if permits_switch
            else require_profile_auth(event, profile_id)
        )
        if not authorized:
            return response(401, {"state": "unauthorized"})

    item = terminalize_stale_remote_request(item)
    return response(200, public_remote_request_item(item, include_payload=True))


def terminalize_stale_remote_request(item):
    """Fail one exact abandoned connector lease instead of waiting for its TTL."""
    status = str(item.get("status") or "")
    lease_seconds = {
        "in_progress": REMOTE_REQUEST_IN_PROGRESS_LEASE_SECONDS,
        "completing": REMOTE_REQUEST_COMPLETING_LEASE_SECONDS,
    }.get(status)
    if lease_seconds is None:
        return item
    observed_updated_at = str(item.get("updated_at") or "")
    observed_claimed_at = str(item.get("claimed_at") or "")
    lease_marker = observed_updated_at or observed_claimed_at
    try:
        updated = datetime.fromisoformat(lease_marker.replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - updated).total_seconds()
    except (TypeError, ValueError):
        age_seconds = lease_seconds + 1
    if age_seconds <= lease_seconds:
        return item

    now = utc_now_iso()
    error_json = json.dumps({
        "message": "The home connector did not finish this request before its lease expired.",
        "details": {"code": "remoteRequestLeaseExpired", "previous_status": status},
    }, separators=(",", ":"))
    condition = "#status = :expected"
    expression_values = {
        ":expected": status,
        ":failed": "failed",
        ":now": now,
        ":status_created_at": status_sort_key("failed", now, item["request_id"]),
        ":error_json": error_json,
    }
    if observed_updated_at:
        condition += " AND updated_at = :expected_updated_at"
        expression_values[":expected_updated_at"] = observed_updated_at
    elif observed_claimed_at:
        condition += " AND attribute_not_exists(updated_at) AND claimed_at = :expected_claimed_at"
        expression_values[":expected_claimed_at"] = observed_claimed_at
    else:
        condition += " AND attribute_not_exists(updated_at) AND attribute_not_exists(claimed_at)"
    try:
        return remote_requests_table.update_item(
            Key={"request_id": item["request_id"]},
            ConditionExpression=condition,
            UpdateExpression=(
                "SET #status = :failed, failed_at = :now, updated_at = :now, "
                "status_created_at = :status_created_at, error_json = :error_json"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=expression_values,
            ReturnValues="ALL_NEW",
        ).get("Attributes", item)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return remote_requests_table.get_item(Key={"request_id": item["request_id"]}).get("Item") or item
        raise


def claim_remote_request(event, *, pairing_v3=False):
    if remote_requests_table is None:
        return response(500, {"state": "server_error", "message": "remote requests table is not configured"})

    body = parse_json_body(event)

    if body is None:
        return response(400, {"state": "bad_request", "message": "invalid JSON body"})

    connector_id = str(body.get("connector_id") or "").strip()

    if not connector_id:
        return response(400, {"state": "bad_request", "message": "connector_id is required"})

    authenticated = require_pairing_v3_connector_auth(event, connector_id, body) if pairing_v3 else require_connector_auth(event, connector_id)
    if not authenticated:
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
        if int(candidate.get("expires_at") or 0) < epoch_now():
            continue
        now = utc_now_iso()
        try:
            claimed = remote_requests_table.update_item(
                Key={"request_id": candidate["request_id"]},
                ConditionExpression="#status = :pending AND expires_at >= :now_epoch",
                UpdateExpression=(
                    "SET #status = :in_progress, claimed_at = :now, updated_at = :now, "
                    "status_created_at = :status_created_at"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":pending": "pending",
                    ":in_progress": "in_progress",
                    ":now": now,
                    ":now_epoch": epoch_now(),
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
                "request": connector_remote_request_item(claimed)
            })

    return response(200, {"state": "empty"})


def complete_remote_request(event, path, *, pairing_v3=False):
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

    connector_id = str(item.get("connector_id") or "")
    authenticated = require_pairing_v3_connector_auth(event, connector_id, body) if pairing_v3 else require_connector_auth(event, connector_id)
    if not authenticated:
        return response(401, {"state": "connector_unauthorized"})

    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and body_connector_id != item.get("connector_id"):
        return response(403, {"state": "forbidden", "message": "connector_id mismatch"})

    now = utc_now_iso()
    try:
        item = remote_requests_table.update_item(
            Key={"request_id": request_id},
            ConditionExpression="#status = :in_progress",
            UpdateExpression=(
                "SET #status = :completing, updated_at = :now, "
                "status_created_at = :status_created_at"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":in_progress": "in_progress",
                ":completing": "completing",
                ":now": now,
                ":status_created_at": status_sort_key("completing", now, request_id),
            },
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, {"state": "request_not_in_progress", "request_id": request_id})
        raise

    item["status"] = "completed"
    item["completed_at"] = now
    item["updated_at"] = now
    item["status_created_at"] = status_sort_key("completed", now, request_id)
    item["http_status"] = int(body.get("http_status") or 200)
    item["truncated"] = bool_value(body.get("truncated"), False)

    response_payload = body.get("response")
    if response_payload is None:
        response_payload = {}
    response_payload = _profile_scoped_seerr_response(
        str(item.get("profile_id") or ""),
        parse_json_field(item.get("request_json"), {}),
        response_payload,
    )
    response_payload = _completion_with_embedded_playback_grant(
        item, response_payload,
    )

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

    try:
        remote_requests_table.put_item(
            Item=item,
            ConditionExpression="#status = :completing",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":completing": "completing"},
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, {"state": "request_not_completing", "request_id": request_id})
        raise

    return response(200, {
        "state": "completed",
        "request": public_remote_request_item(item, include_payload=False)
    })


def fail_remote_request(event, path, *, pairing_v3=False):
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

    connector_id = str(item.get("connector_id") or "")
    authenticated = require_pairing_v3_connector_auth(event, connector_id, body) if pairing_v3 else require_connector_auth(event, connector_id)
    if not authenticated:
        return response(401, {"state": "connector_unauthorized"})

    body_connector_id = str(body.get("connector_id") or "").strip()
    if body_connector_id and body_connector_id != item.get("connector_id"):
        return response(403, {"state": "forbidden", "message": "connector_id mismatch"})

    now = utc_now_iso()
    error_json = json.dumps({
        "message": str(body.get("message") or "remote request failed"),
        "details": body.get("details") if isinstance(body.get("details"), dict) else {}
    }, separators=(",", ":"))
    try:
        item = remote_requests_table.update_item(
            Key={"request_id": request_id},
            ConditionExpression="#status = :in_progress",
            UpdateExpression=(
                "SET #status = :failed, failed_at = :now, updated_at = :now, "
                "status_created_at = :status_created_at, error_json = :error_json"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":in_progress": "in_progress",
                ":failed": "failed",
                ":now": now,
                ":status_created_at": status_sort_key("failed", now, request_id),
                ":error_json": error_json,
            },
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return response(409, {"state": "request_not_in_progress", "request_id": request_id})
        raise

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
    if not require_profile_switch_auth(event, profile_id):
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
    if isinstance(event, dict):
        # Retain only a one-way request correlation marker for bounded server
        # diagnostics. It is deliberately never an AWS request ID in logs.
        event = dict(event)
        event["_kaevo_lambda_request_fingerprint"] = _protected_identity_fingerprint(
            getattr(context, "aws_request_id", "")
        )
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
                "/v1/bug-reports",
                "/v1/household-progress",
                "/v1/household-progress/live-ticket",
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
                "/v2/installations",
                "/v2/installations/{installationId}/revoke",
                "/v2/app-sessions",
                "/v2/app-sessions/refresh",
                "/v2/household/invitations",
                "/v2/household/invitations/{invitationId}/revoke",
                "/v1/guest-passes",
                "/v1/guest-passes/claim",
                "/v1/guest-passes/{passId}/revoke",
                "/v1/guest-pass/session",
                "/v1/guest-pass/content",
                "/v1/guest-pass/playback",
                "/v1/guest-pass/activity",
                "/v1/guest-pass/remote-requests/{requestId}",
                "/v2/identity/join-household",
                "/v3/identity/household-joins/begin",
                "/v3/identity/household-joins/route-auth",
                "/v2/identity/social-links",
                "/v2/identity/social-links/callback",
                "/v3/identity/me",
                "/v3/identity/migrate-existing-account",
                "/v3/identity/migrate-household-membership",
                "/v3/identity/households/ownership-transfer/candidates",
                "/v3/identity/households/ownership-transfer",
                "/v3/identity/profiles",
                "/v3/identity/profiles/{profileId}/bindings",
                "/v3/identity/profiles/{profileId}/jellyfin-binding",
                "/v3/identity/profiles/{profileId}/jellyfin-binding-operations",
                "/v3/identity/jellyfin-binding-operations/{operationId}",
                "/v3/identity/profiles/{profileId}/deletion",
                "/v3/identity/account-deletion",
                "/v3/identity/account-deletions/{deletionAttemptId}",
                "/v3/identity/profile-mappings",
                "/v3/identity/profile-mappings/preview",
                "/v3/identity/profile-mappings/confirm",
                "/v3/identity/profile-mappings/create-and-confirm",
                "/v3/home-connectors/pairing/authorizations",
                "/v3/home-connectors/pairing/redemptions",
                "/v3/home-connectors/pairing/attempts/{pairingAttemptId}",
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
        if app_bearer_token(event) and not legacy_app_sessions_allowed():
            return list_owner_installations_v2(event)
        return get_app_session_status(event)

    if method == "POST" and path == "/v1/app-sessions/revoke":
        body = parse_json_body(event) or {}
        if body.get("device_handle") and not legacy_app_sessions_allowed():
            return revoke_installation_v2(event, f"/v2/installations/{body['device_handle']}/revoke")
        return revoke_app_session(event)

    if method == "POST" and path == "/v2/installations":
        registration = register_installation_v2(event)
        # Keep physical-device recovery evidence non-identifying: the route
        # result is sufficient to distinguish policy, DPoP, and storage
        # failures without logging request bodies or authority identifiers.
        try:
            registration_body = json.loads(str(registration.get("body") or "{}"))
            registration_state = str(registration_body.get("state") or "unknown")[:80]
        except (TypeError, ValueError, json.JSONDecodeError):
            registration_state = "unparseable"
        LOGGER.warning(
            "installation_registration_result status=%s state=%s",
            registration.get("statusCode"),
            registration_state,
        )
        return registration

    if method == "POST" and path.startswith("/v2/installations/") and path.endswith("/revoke"):
        return revoke_installation_v2(event, path)

    if method == "POST" and path == "/v2/app-sessions":
        return issue_bound_session_v2(event)

    if method == "POST" and path == "/v2/app-sessions/refresh":
        return refresh_bound_session_v2(event)

    if path == "/v2/household/invitations":
        if method == "POST":
            return create_household_invitation(event)
        if method == "PUT":
            return refresh_household_invitation(event)
        if method == "GET":
            return list_household_invitations(event)

    if method == "POST" and path.startswith("/v2/household/invitations/") and path.endswith("/revoke"):
        return revoke_household_invitation(event, path)
    if method == "DELETE" and re.fullmatch(r"/v2/household/invitations/[^/]+", path):
        return delete_household_invitation(event, path)

    if path == "/v1/guest-passes":
        if method == "POST":
            return create_guest_pass(event)
        if method == "GET":
            return list_guest_passes(event)
    if method == "POST" and path == "/v1/guest-passes/claim":
        return claim_guest_pass(event)
    if method == "POST" and re.fullmatch(r"/v1/guest-passes/[^/]+/revoke", path):
        return revoke_guest_pass(event, path)
    if method == "GET" and path == "/v1/guest-pass/session":
        return guest_pass_session(event)
    if method == "POST" and path == "/v1/guest-pass/content":
        return create_guest_content_request(event)
    if method == "POST" and path == "/v1/guest-pass/playback":
        return create_guest_playback_request(event)
    if method == "POST" and path == "/v1/guest-pass/activity":
        return record_guest_playback_activity(event)
    if method == "GET" and re.fullmatch(r"/v1/guest-pass/remote-requests/[^/]+", path):
        return get_guest_remote_request(event, path)

    if method == "POST" and path == "/v2/identity/join-household":
        return join_household(event)

    if method == "POST" and path == "/v3/identity/household-joins/begin":
        return begin_household_join(event)

    if method == "POST" and path == "/v3/identity/household-joins/route-auth":
        return route_household_join_auth(event)

    if path == "/v2/identity/social-links":
        if method == "GET":
            return linked_social_providers(event)
        if method == "POST":
            return start_social_identity_link(event)

    if path == "/v2/identity/social-links/callback" and method in {"GET", "POST"}:
        return social_identity_link_callback(event)

    if method == "GET" and path == "/v3/identity/me":
        return identity_me_v3(event)

    if method == "POST" and path == "/v3/identity/migrate-existing-account":
        return migrate_existing_account_v3(event)

    if method == "POST" and path == "/v3/identity/migrate-household-membership":
        return migrate_household_membership_v3(event)

    if method == "GET" and path == "/v3/identity/households/ownership-transfer/candidates":
        return list_ownership_transfer_candidates_v3(event)

    if method == "GET" and path == "/v3/identity/households/profiles":
        return list_household_profiles_v3(event)

    if method == "POST" and path == "/v3/identity/households/ownership-transfer":
        return transfer_household_ownership_v3(event)

    if method == "GET" and path == "/v3/identity/home-connector-binding":
        return get_home_connector_binding_v3(event)

    if method == "POST" and path == "/v3/identity/bind-home-connector":
        return bind_home_connector_v3(event)

    if method == "POST" and path == "/v3/identity/profiles":
        return create_profile_v3(event)

    if method == "PUT" and profile_switch_pin_path_id(path):
        return set_profile_switch_pin_v3(event, path)

    if method == "POST" and profile_switch_pin_verification_path_id(path):
        return verify_profile_switch_pin_v3(event, path)

    if method == "PUT" and profile_switch_targets_path_id(path):
        return update_profile_switch_targets_v3(event, path)

    if method == "PUT" and profile_watching_targets_path_id(path):
        return update_profile_watching_targets_v3(event, path)

    if method == "POST" and profile_binding_path_id(path):
        return create_profile_binding_v3(event, path)

    if method == "PUT" and profile_jellyfin_binding_path_id(path):
        return save_profile_jellyfin_binding_v3(event, path)

    if method == "PUT" and profile_seerr_binding_path_id(path):
        return save_profile_seerr_binding_v3(event, path)

    if method == "POST" and profile_pending_provider_cleanup_path_id(path):
        return cleanup_pending_profile_providers_v3(event, path)

    if method == "POST" and path == "/v3/identity/provider-orphans/seerr/repair":
        return repair_exact_seerr_orphan_v3(event)

    if method == "POST" and profile_jellyfin_binding_preflight_path_id(path):
        return preflight_profile_jellyfin_binding_v3(event, path)

    if method == "GET" and path.startswith("/v3/identity/jellyfin-binding-operations/"):
        return get_profile_jellyfin_binding_operation_v3(event, path)

    if method == "POST" and profile_deletion_path_id(path):
        return delete_profile_v3(event, path)

    if method == "POST" and path == "/v3/identity/account-deletion":
        return delete_account_v3(event)

    if method == "GET" and path.startswith("/v3/identity/account-deletions/"):
        return account_deletion_status_v3(event, path)

    if method == "GET" and path == "/v3/identity/profile-mappings":
        return list_profile_mappings_v3(event)

    if method == "POST" and path == "/v3/identity/profile-mappings/preview":
        return preview_profile_mapping_v3(event)

    if method == "POST" and path == "/v3/identity/profile-mappings/confirm":
        return confirm_profile_mapping_v3(event)

    if method == "POST" and path == "/v3/identity/profile-mappings/create-and-confirm":
        return create_and_confirm_profile_mapping_v3(event)

    if method == "POST" and path == "/v3/home-connectors/pairing/authorizations":
        return issue_home_connector_pairing_authorization_v3(event)

    if method == "POST" and path == "/v3/home-connectors/pairing/redemptions":
        return redeem_home_connector_pairing_v3(event)

    if method == "POST" and path.startswith("/v3/home-connectors/pairing/attempts/"):
        return pairing_attempt_status_v3(event, path)

    if method == "POST" and path == "/v1/events":
        return save_event(event)

    if method == "POST" and path == "/v1/events/batch":
        return save_event_batch(event)

    if method == "GET" and path == "/v1/events/recent":
        return recent_events(event)

    if method == "GET" and path == "/v1/bug-reports":
        return bug_report_events(event)

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

    if method == "POST" and path == "/v2/home-connectors/pairing/exchange":
        return exchange_connector_pairing_v2(event)

    if method == "POST" and path.startswith("/v2/home-connectors/") and path.endswith("/rotation-intents"):
        return start_connector_update_intent(event, path, "rotate")

    if method == "POST" and path.startswith("/v2/home-connectors/") and path.endswith("/recovery-intents"):
        return start_connector_update_intent(event, path, "recover")

    if method == "POST" and path.startswith("/v2/home-connectors/") and path.endswith("/unpair-intents"):
        return start_connector_unpair_intent(event, path)

    if method == "POST" and path.startswith("/v2/home-connectors/lifecycle/intents/") and path.endswith("/unpair"):
        return activate_connector_unpair_intent(event, path)

    if method == "POST" and path.startswith("/v2/home-connectors/lifecycle/intents/") and path.endswith("/activate"):
        return activate_connector_update_intent(event, path)

    if method == "POST" and path.startswith("/v2/home-connectors/lifecycle/intents/") and path.endswith("/cancel"):
        return cancel_connector_lifecycle_intent(event, path)

    if method == "POST" and path.startswith("/v1/home-connectors/") and path.endswith("/revoke"):
        return revoke_home_connector(event, path)

    if method == "POST" and path.startswith("/v3/home-connectors/") and path.endswith("/relay-ticket"):
        return create_connector_relay_ticket(event, path, pairing_v3=True)

    if method == "POST" and path == "/v3/home-connectors/register":
        return register_home_connector(event, pairing_v3=True)

    if method == "POST" and path.startswith("/v3/home-connectors/") and path.endswith("/heartbeat"):
        return heartbeat_home_connector(event, path, pairing_v3=True)

    if method == "POST" and path == "/v3/remote-requests/claim":
        return claim_remote_request(event, pairing_v3=True)

    if method == "POST" and path.startswith("/v3/remote-requests/") and path.endswith("/complete"):
        return complete_remote_request(event, path, pairing_v3=True)

    if method == "POST" and path.startswith("/v3/remote-requests/") and path.endswith("/fail"):
        return fail_remote_request(event, path, pairing_v3=True)

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

    if method == "POST" and path == "/v1/household-progress":
        return save_household_progress(event)

    if method == "GET" and path == "/v1/household-progress":
        return get_household_progress(event)

    if method == "POST" and path == "/v1/household-progress/live-ticket":
        return create_family_sync_live_ticket(event)

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
