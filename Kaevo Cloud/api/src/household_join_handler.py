"""Isolated, intent-first household join Lambda.

This module deliberately owns only the V3 invitation claim lifecycle.  It is
packaged behind a dedicated role and never dispatches social identity,
connector, media, or legacy V2 routes.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from account_foundation import (
    AccountFoundationError,
    canonical_role,
    household_access_role,
    assert_auth_identity_binding,
    build_account_record,
    build_auth_identity_record,
    provider_subject_key,
)
from household_membership import household_membership_id
from profile_binding import build_profile_creation, validate_binding, validate_profile
from profile_mapping import build_confirmed_mapping, local_profile_source_id

from handler import (  # Pure protocol helpers; this module never invokes handler.lambda_handler.
    _gateway_jwt_claims,
    _normalized_jellyfin_user_id,
    _normalized_seerr_user_id,
    epoch_now,
    household_invitation_code_expiration,
    parse_json_body,
    response,
    utc_now_iso,
)
from identity_authority import AuthorityError, validate_access_token_claims
from security_identity import IdentityError, verify_dpop


JOIN_TABLE = os.environ.get("HOUSEHOLD_JOIN_TRANSACTIONS_TABLE", "")
INVITATIONS_TABLE = os.environ.get("HOUSEHOLD_INVITATIONS_TABLE", "")
PRINCIPALS_TABLE = os.environ.get("PRINCIPALS_TABLE", "")
MEMBERSHIPS_TABLE = os.environ.get("IDENTITY_MEMBERSHIPS_TABLE", "")
PROFILES_TABLE = os.environ.get("IDENTITY_PROFILES_TABLE", "")
ENTITLEMENTS_TABLE = os.environ.get("ENTITLEMENTS_TABLE", "")
ACCOUNTS_TABLE = os.environ.get("ACCOUNTS_TABLE", "")
AUTH_IDENTITIES_TABLE = os.environ.get("AUTH_IDENTITIES_TABLE", "")
HOUSEHOLD_MEMBERSHIPS_TABLE = os.environ.get("HOUSEHOLD_MEMBERSHIPS_TABLE", "")
PROFILE_BINDINGS_TABLE = os.environ.get("PROFILE_BINDINGS_TABLE", "")
PROFILE_MAPPINGS_TABLE = os.environ.get("PROFILE_MAPPINGS_TABLE", "")
CLOUD_PROFILES_TABLE = os.environ.get("CLOUD_PROFILES_TABLE", "")
HOUSEHOLDS_TABLE = os.environ.get("IDENTITY_HOUSEHOLDS_TABLE", "")
USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
EXPECTED_ISSUER = os.environ.get("EXPECTED_COGNITO_ISSUER", "")
EXPECTED_CLIENT_ID = os.environ.get("EXPECTED_NATIVE_CLIENT_ID", "")
AUTHORIZE_BASE_URL = os.environ.get("HOUSEHOLD_JOIN_AUTHORIZE_BASE_URL", "").rstrip("/")
PUBLIC_API_BASE_URL = os.environ.get("PUBLIC_API_BASE_URL", "").rstrip("/")
NATIVE_CALLBACK_URI = os.environ.get("EXPECTED_NATIVE_CALLBACK_URI", "")
NATIVE_AUTHORIZE_ENDPOINT = os.environ.get("NATIVE_OIDC_AUTHORIZATION_ENDPOINT", "").rstrip("/")
# A Join starts with a short server-controlled pre-auth window.  Once a valid
# /route-auth request binds OAuth state, PKCE, nonce, installation, and DPoP
# thumbprint, it receives one bounded completion window for Cognito managed
# login.  The absolute limit is immutable from /begin, so neither a client nor
# a replay can keep a Join alive indefinitely.
JOIN_PREAUTH_TTL_SECONDS = 15 * 60
JOIN_AUTH_COMPLETION_TTL_SECONDS = 6 * 60
JOIN_ABSOLUTE_MAX_TTL_SECONDS = JOIN_PREAUTH_TTL_SECONDS + JOIN_AUTH_COMPLETION_TTL_SECONDS
RETENTION_SECONDS = 24 * 60 * 60
DPOP_REPLAY_SAFETY_SECONDS = 60
RATE_WINDOW_SECONDS = 10 * 60
RATE_MAXIMUM = 8
TRANSACTION_ROUTE_MAXIMUM = 3
TRANSACTION_COMPLETE_MAXIMUM = 5

dynamodb = boto3.resource("dynamodb")
joins = dynamodb.Table(JOIN_TABLE) if JOIN_TABLE else None
invitations = dynamodb.Table(INVITATIONS_TABLE) if INVITATIONS_TABLE else None
principals = dynamodb.Table(PRINCIPALS_TABLE) if PRINCIPALS_TABLE else None
memberships = dynamodb.Table(MEMBERSHIPS_TABLE) if MEMBERSHIPS_TABLE else None
profiles = dynamodb.Table(PROFILES_TABLE) if PROFILES_TABLE else None
entitlements = dynamodb.Table(ENTITLEMENTS_TABLE) if ENTITLEMENTS_TABLE else None
accounts = dynamodb.Table(ACCOUNTS_TABLE) if ACCOUNTS_TABLE else None
auth_identities = dynamodb.Table(AUTH_IDENTITIES_TABLE) if AUTH_IDENTITIES_TABLE else None
household_memberships = dynamodb.Table(HOUSEHOLD_MEMBERSHIPS_TABLE) if HOUSEHOLD_MEMBERSHIPS_TABLE else None
profile_bindings = dynamodb.Table(PROFILE_BINDINGS_TABLE) if PROFILE_BINDINGS_TABLE else None
profile_mappings = dynamodb.Table(PROFILE_MAPPINGS_TABLE) if PROFILE_MAPPINGS_TABLE else None
cloud_profiles = dynamodb.Table(CLOUD_PROFILES_TABLE) if CLOUD_PROFILES_TABLE else None
households = dynamodb.Table(HOUSEHOLDS_TABLE) if HOUSEHOLDS_TABLE else None
cognito = boto3.client("cognito-idp")
LOGGER = logging.getLogger(__name__)

ONBOARDING_STATUS_DIAGNOSTIC_EVENT = "household_join_onboarding_status_auth_rejection"
ONBOARDING_STATUS_DIAGNOSTIC_ROUTE = "household_join_onboarding_status"
ONBOARDING_STATUS_REASON_FALLBACK = "ONBOARDING_STATUS_AUTH_REJECTED_UNCLASSIFIED"
ONBOARDING_STATUS_REASON_CATEGORIES = frozenset({
    "JWT_SUBJECT_MISSING",
    "INSTALLATION_BINDING_MISSING",
    "ACCOUNT_SUBJECT_MISMATCH",
    "DPOP_HEADER_MISSING",
    "DPOP_PROOF_MALFORMED",
    "DPOP_SIGNATURE_INVALID",
    "DPOP_HTM_MISMATCH",
    "DPOP_HTU_MISMATCH",
    "DPOP_IAT_INVALID",
    "DPOP_JTI_REPLAY",
    "DPOP_KEY_BINDING_MISMATCH",
    "DPOP_ACCESS_TOKEN_MISMATCH",
    ONBOARDING_STATUS_REASON_FALLBACK,
})


def _sha(value):
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _safe_fingerprint(value):
    """Return a short, domain-separated digest suitable for diagnostic correlation."""
    return _sha(f"household-join-diagnostic-v1:{value}")[:24] if value else ""


def _active_cloud_seat_profile_ids(household_id):
    """Return exact active, device-linked profile IDs for one household.

    The household membership table is partitioned by its canonical household
    ID, so this is a strongly consistent partition query rather than a Scan.
    Parent-managed profiles do not create a membership and therefore never
    consume a Cloud seat.
    """
    if household_memberships is None or not household_id:
        raise AccountFoundationError("household_seat_storage_unavailable")
    profile_ids = set()
    query = {
        "KeyConditionExpression": Key("household_id").eq(household_id),
        "ConsistentRead": True,
    }
    while True:
        page = household_memberships.query(**query)
        for membership in page.get("Items", []):
            if not isinstance(membership, dict):
                continue
            if (
                membership.get("entity_type") != "HouseholdMembership"
                or membership.get("status") != "active"
            ):
                continue
            cloud_access = membership.get("cloud_access_enabled", True)
            if not isinstance(cloud_access, bool):
                raise AccountFoundationError("household_seat_membership_invalid")
            profile_id = str(membership.get("profile_id") or "")
            if cloud_access and profile_id:
                profile_ids.add(profile_id)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return profile_ids
        query["ExclusiveStartKey"] = last_key


def _family_seat_limit(entitlement_item):
    """Read the owner-issued Family capacity without accepting client input."""
    try:
        entitlement = json.loads(str((entitlement_item or {}).get("entitlements_json") or "{}"))
        if not isinstance(entitlement, dict):
            raise AccountFoundationError("household_seat_entitlement_invalid")
        limit = int(entitlement.get("family_seats"))
    except (TypeError, ValueError, json.JSONDecodeError, AttributeError):
        raise AccountFoundationError("household_seat_entitlement_invalid")
    if (
        entitlement.get("family_enabled") is not True
        or entitlement.get("cloud_enabled") is not True
        or not 1 <= limit <= 100
    ):
        raise AccountFoundationError("household_seat_entitlement_invalid")
    return limit


def _household_cloud_seat_authority(household_id):
    """Return the household owner's account and exact seat ledger, if present.

    A joining member owns the new profile but never owns the household seat
    ledger. The canonical household record is the sole authority for the
    account ID used by the guarded ledger update.
    """
    if households is None or not household_id:
        raise AccountFoundationError("household_seat_storage_unavailable")
    household = households.get_item(
        Key={"household_id": household_id}, ConsistentRead=True,
    ).get("Item")
    owner_account_id = str((household or {}).get("account_id") or "")
    if (
        not isinstance(household, dict)
        or household.get("state") != "active"
        or not owner_account_id
    ):
        raise AccountFoundationError("household_seat_household_invalid")
    stored = household.get("cloud_seat_profile_ids")
    if stored is None:
        return owner_account_id, None
    if not isinstance(stored, (set, list, tuple)):
        raise AccountFoundationError("household_seat_ledger_invalid")
    profile_ids = {str(profile_id or "") for profile_id in stored}
    if not profile_ids or "" in profile_ids:
        raise AccountFoundationError("household_seat_ledger_invalid")
    return owner_account_id, profile_ids


def _household_seat_reservation_operation(
    *, household_id, account_id, profile_id, seat_limit, existing_profile_ids,
    stored_profile_ids, now_iso,
):
    """Atomically reserve one exact Cloud seat during Profile Setup.

    Existing households have no ledger yet. Their first reservation seeds an
    exact set from the strongly read active membership partition. If an older
    ledger ever differs from that source of truth, this same guarded write
    repairs it; no stale release can over-allocate a household.
    """
    if households is None or not household_id or not account_id or not profile_id:
        raise AccountFoundationError("household_seat_storage_unavailable")
    seeded_ids = set(existing_profile_ids)
    if profile_id in seeded_ids or len(seeded_ids) >= seat_limit:
        raise AccountFoundationError("family_seat_limit_reached")
    seeded_ids.add(profile_id)
    conditions = (
        "account_id = :account_id AND #state = :active AND "
    )
    values = {
        ":account_id": account_id,
        ":active": "active",
        ":seat_limit": seat_limit,
        ":updated_at": now_iso,
    }
    if stored_profile_ids is None:
        conditions += "attribute_not_exists(cloud_seat_profile_ids) AND :baseline_count < :seat_limit"
        update_expression = "ADD cloud_seat_profile_ids :reservation SET updated_at = :updated_at"
        values.update({
            ":baseline_count": len(existing_profile_ids),
            ":reservation": seeded_ids,
        })
    elif stored_profile_ids == set(existing_profile_ids):
        conditions += "size(cloud_seat_profile_ids) < :seat_limit"
        update_expression = "ADD cloud_seat_profile_ids :reservation SET updated_at = :updated_at"
        values[":reservation"] = {profile_id}
    else:
        conditions += "cloud_seat_profile_ids = :stored_ledger AND :baseline_count < :seat_limit"
        update_expression = "SET cloud_seat_profile_ids = :reservation, updated_at = :updated_at"
        values.update({
            ":stored_ledger": set(stored_profile_ids),
            ":baseline_count": len(existing_profile_ids),
            ":reservation": seeded_ids,
        })
    return {
        "label": "household_seat_reservation",
        "transaction": {"Update": {
            "TableName": HOUSEHOLDS_TABLE,
            "Key": {"household_id": household_id},
            "ConditionExpression": conditions,
            "UpdateExpression": update_expression,
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": values,
        }},
    }


def _onboarding_status_rejection(event, reason, *, subject="", installation_hash="", item=None):
    """Emit bounded, non-secret diagnosis without affecting authorization."""
    try:
        category = reason if reason in ONBOARDING_STATUS_REASON_CATEGORIES else ONBOARDING_STATUS_REASON_FALLBACK
        item = item if isinstance(item, dict) else {}
        record = {
            "event": ONBOARDING_STATUS_DIAGNOSTIC_EVENT,
            "reason_category": category,
            "route": ONBOARDING_STATUS_DIAGNOSTIC_ROUTE,
            "method": "GET",
            "subject_fingerprint": _safe_fingerprint(subject),
            "installation_fingerprint": _safe_fingerprint(installation_hash),
            "dpop_key_fingerprint": _safe_fingerprint(item.get("dpop_thumbprint")),
            "continuation_fingerprint": _safe_fingerprint(item.get("join_resume_hash")),
            "lambda_request_fingerprint": str((event or {}).get("_kaevo_lambda_request_fingerprint") or ""),
            "timestamp": utc_now_iso(),
        }
        LOGGER.warning(json.dumps(record, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Diagnostics must never make a failed authorization succeed or fail
        # differently. The existing fail-closed decision remains authoritative.
        pass


def _auth_result_outcome(event, category, *, item=None):
    """Emit one bounded managed-login failure category for live attribution."""
    try:
        item = item if isinstance(item, dict) else {}
        record = {
            "event": "HOUSEHOLD_JOIN_AUTH_RESULT",
            "category": category if category in AUTH_RESULT_CATEGORIES else "unknown",
            "transaction_fingerprint": _safe_fingerprint(item.get("join_resume_hash")),
            "invitation_fingerprint": _safe_fingerprint(item.get("invitation_code_hash")),
            "lambda_request_fingerprint": str(
                (event or {}).get("_kaevo_lambda_request_fingerprint") or ""
            ),
            "timestamp": utc_now_iso(),
        }
        LOGGER.warning(json.dumps(record, sort_keys=True, separators=(",", ":")))
    except Exception:
        # Telemetry is evidence only and must not alter the fail-closed Join
        # authorization decision or its public response.
        pass


def _dpop_rejection_category(error):
    return {
        "invalid_dpop": "DPOP_PROOF_MALFORMED",
        "installation_key_mismatch": "DPOP_KEY_BINDING_MISMATCH",
        "dpop_method_mismatch": "DPOP_HTM_MISMATCH",
        "dpop_url_mismatch": "DPOP_HTU_MISMATCH",
        "stale_dpop": "DPOP_IAT_INVALID",
        "dpop_replay": "DPOP_JTI_REPLAY",
        "dpop_access_token_mismatch": "DPOP_ACCESS_TOKEN_MISMATCH",
    }.get(str(getattr(error, "reason", "")), ONBOARDING_STATUS_REASON_FALLBACK)


def _valid(value, pattern):
    value = str(value or "").strip()
    return value if re.fullmatch(pattern, value) else ""


def _handle_hash(value):
    value = _valid(value, r"jr_[A-Za-z0-9_-]{32,128}")
    return _sha(value) if value else ""


def _installation_hash(value):
    value = _valid(value, r"[A-Za-z0-9._:-]{8,256}")
    return _sha(value) if value else ""


def _thumbprint(value):
    return _valid(value, r"[A-Za-z0-9_-]{32,128}")


def _email(value):
    value = str(value or "").strip().casefold()
    return value if re.fullmatch(r"[^\s@]{1,64}@[^\s@]{1,255}", value) else ""


def _join_code(value):
    value = str(value or "").strip()
    if value.lower().startswith("kaevo://"):
        parts = urlsplit(value)
        if parts.scheme != "kaevo" or parts.netloc != "join":
            return ""
        value = parse_qs(parts.query, keep_blank_values=True).get("code", [""])[0]
    return value


def _join_code_hash(value):
    """Hash Join codes exactly as invitation creation and refresh do.

    Invitation codes are displayed as ``ABCDE-12345`` and QR payloads carry
    that same value. The invitations table deliberately keys them by the
    separator-free, uppercase form so presentation formatting cannot change
    the lookup key.
    """
    normalized = re.sub(r"[^A-Z0-9]", "", _join_code(value).upper())
    return _sha(normalized) if normalized else ""


def _network_bucket(event):
    source = str(((event.get("requestContext") or {}).get("http") or {}).get("sourceIp") or "")
    # Retain only a coarse, irreversible network bucket; never retain a raw IP.
    if "." in source:
        source = ".".join(source.split(".")[:3])
    elif ":" in source:
        source = ":".join(source.split(":")[:4])
    return _sha(source) if source else ""


def _error(state, status=400, retryable=False):
    return response(status, {"state": state, "retryable": retryable})


def _begin_outcome(event, outcome, status, *, installation_hash="", invitation_hash=""):
    """Emit one bounded record so a failed physical Join is attributable.

    Only domain-separated fingerprints are logged. Invitation values, raw
    table keys, IP addresses, account identities, and transaction handles are
    intentionally excluded.
    """
    try:
        record = {
            "event": "HOUSEHOLD_JOIN_BEGIN_OUTCOME",
            "outcome": str(outcome or "unknown"),
            "status": int(status),
            "installation_fingerprint": _safe_fingerprint(installation_hash),
            "invitation_fingerprint": _safe_fingerprint(invitation_hash),
            "network_fingerprint": _safe_fingerprint(_network_bucket(event)),
            "lambda_request_fingerprint": str(
                (event or {}).get("_kaevo_lambda_request_fingerprint") or ""
            ),
            "timestamp": utc_now_iso(),
        }
        # Lambda's managed Python logger may retain WARNING as its effective
        # level, so use warning for this sparse outcome record. Otherwise the
        # exact physical Join failure boundary disappears from CloudWatch.
        LOGGER.warning(json.dumps(record, sort_keys=True, separators=(",", ":")))
    except Exception:
        pass


def _completion_outcome(
    event,
    outcome,
    status,
    *,
    item=None,
    subject="",
    installation_hash="",
):
    """Emit one bounded completion verdict without identity or Join material."""
    try:
        item = item or {}
        record = {
            "event": "HOUSEHOLD_JOIN_COMPLETION_OUTCOME",
            "outcome": str(outcome or "unknown"),
            "status": int(status),
            "subject_fingerprint": _safe_fingerprint(_sha(subject)),
            "installation_fingerprint": _safe_fingerprint(installation_hash),
            "transaction_fingerprint": _safe_fingerprint(
                str(item.get("join_resume_hash") or "")
            ),
            "network_fingerprint": _safe_fingerprint(_network_bucket(event)),
            "lambda_request_fingerprint": str(
                (event or {}).get("_kaevo_lambda_request_fingerprint") or ""
            ),
            "timestamp": utc_now_iso(),
        }
        LOGGER.warning(json.dumps(record, sort_keys=True, separators=(",", ":")))
    except Exception:
        pass


def _completion_rejection(
    event,
    state,
    status,
    *,
    outcome,
    item=None,
    subject="",
    installation_hash="",
    retryable=False,
):
    """Return a public-safe rejection while retaining one bounded verdict.

    The response state remains the established mobile contract.  The outcome
    is deliberately a coarse diagnostic category: it contains no invitation,
    OAuth, account, or device material, but makes the first rejected boundary
    observable in CloudWatch.
    """
    _completion_outcome(
        event,
        outcome,
        status,
        item=item,
        subject=subject,
        installation_hash=installation_hash,
    )
    return _error(state, status, retryable)


def _completion_validation_probe(operations):
    """Return a bounded operation label for one rejected transaction shape.

    DynamoDB's ValidationException text is deliberately not logged: it can
    reflect request details.  This DEV-safe probe instead replays each already
    constructed operation with an impossible ConditionCheck on a distinct,
    derived join-table key.  DynamoDB validates the operation, but the
    contradictory condition guarantees that no record can be written.
    """
    if not isinstance(operations, list) or not JOIN_TABLE:
        return "probe_unavailable"
    for operation in operations:
        label = str(operation.get("label") or "") if isinstance(operation, dict) else ""
        transaction = operation.get("transaction") if isinstance(operation, dict) else None
        if not label or not isinstance(transaction, dict):
            return "probe_unavailable"
        probe_key = "validation_probe_" + _sha(label + ":" + _sha(transaction))
        condition = {
            "ConditionCheck": {
                "TableName": JOIN_TABLE,
                "Key": {"join_resume_hash": probe_key},
                "ConditionExpression": "attribute_exists(#probe) AND attribute_not_exists(#probe)",
                "ExpressionAttributeNames": {"#probe": "fixture_validation_probe"},
            },
        }
        try:
            dynamodb.meta.client.transact_write_items(
                TransactItems=[transaction, condition],
            )
            return "probe_unavailable"
        except ClientError as probe_error:
            code = str(((probe_error.response or {}).get("Error") or {}).get("Code") or "")
            if code == "ValidationException":
                return label
            if code != "TransactionCanceledException":
                return "probe_unavailable"
        except (AttributeError, TypeError, ValueError):
            return "probe_unavailable"
    # The original full request failed validation while each isolated operation
    # passed request validation, so the defect is in their combined shape.
    return "cross_operation_validation"


def _safe_access_denied_details(details):
    """Reduce one AccessDenied message to bounded service and target labels."""
    message = str(((details or {}).get("Error") or {}).get("Message") or "").casefold()
    if "dynamodb:transactwriteitems" in message or "transactwriteitems" in message:
        action_category = "dynamodb_transact_write_items"
    elif "kms:decrypt" in message:
        action_category = "kms_decrypt"
    elif "kms:generatedatakey" in message or "kms:generatedatakeywithoutplaintext" in message:
        action_category = "kms_generate_data_key"
    else:
        action_category = "unclassified_action"

    target_category = "unclassified_target"
    known_targets = (
        (ACCOUNTS_TABLE, "account"),
        (AUTH_IDENTITIES_TABLE, "auth_identity"),
        (HOUSEHOLD_MEMBERSHIPS_TABLE, "normalized_membership"),
        (JOIN_TABLE, "join_transaction"),
        (INVITATIONS_TABLE, "invitation"),
    )
    for table_name, category in known_targets:
        normalized_table = str(table_name or "").casefold()
        if normalized_table and normalized_table in message:
            target_category = category
            break

    if "explicit deny" in message:
        policy_category = "explicit_deny"
    elif "service control policy" in message:
        policy_category = "service_control_policy"
    elif "permissions boundary" in message:
        policy_category = "permissions_boundary"
    elif "no identity-based policy allows" in message:
        policy_category = "identity_policy_missing"
    elif "no resource-based policy allows" in message:
        policy_category = "resource_policy_missing"
    elif action_category.startswith("kms_"):
        policy_category = "kms_authorization"
    else:
        policy_category = "unclassified_policy"
    return {
        "denied_action_category": action_category,
        "denied_target_category": target_category,
        "denied_policy_category": policy_category,
    }


def _completion_transaction_conflict(error, operations, now):
    """Classify one completion transaction cancellation without exposing DynamoDB data.

    DynamoDB returns cancellation reasons in the TransactionCanceledException
    response for TransactWriteItems.  The pinned boto3 operation model has no
    request-side ReturnCancellationReasons argument, so this function reads
    only that supported response field and never parses exception text.
    """
    details = getattr(error, "response", {})
    error_code = str((details.get("Error") or {}).get("Code") or "")
    if error_code != "TransactionCanceledException":
        # A deployment/runtime failure must remain diagnosable without copying
        # a service message, DynamoDB item, request identifier, or subject
        # into logs. The bounded error class is sufficient to distinguish a
        # server defect from an expected conditional conflict.
        safe_categories = {
            "AccessDeniedException", "InternalServerError", "ProvisionedThroughputExceededException",
            "RequestLimitExceeded", "ResourceNotFoundException", "TransactionInProgressException",
            "ValidationException",
        }
        if error_code == "ValidationException":
            # DynamoDB's validation text can include request details.  Classify
            # only a small, known set of request-shape failures for the
            # isolated Lambda's privacy-safe operational diagnostic.
            message = str((details.get("Error") or {}).get("Message") or "").casefold()
            validation_categories = (
                ("reserved keyword", "reserved_attribute_name"),
                ("multiple operations on one item", "duplicate_transaction_target"),
                ("provided key element does not match", "transaction_key_schema_mismatch"),
                ("expressionattributenames", "expression_attribute_names_invalid"),
                ("expressionattributevalues", "expression_attribute_values_invalid"),
                ("empty string", "empty_string_attribute_value"),
                ("empty attribute value", "empty_string_attribute_value"),
            )
            safe_error_category = next(
                (category for marker, category in validation_categories if marker in message),
                "dynamodb_transaction_validation",
            )
            validation_probe = _completion_validation_probe(operations)
        else:
            safe_error_category = error_code if error_code in safe_categories else "other_client_error"
            validation_probe = None
        diagnostic = {
            "event": "household_join_complete_transaction_failure",
            "safe_error_category": safe_error_category,
            "operation_count": len(operations),
        }
        if error_code == "AccessDeniedException":
            diagnostic.update(_safe_access_denied_details(details))
        if validation_probe is not None:
            diagnostic["failed_transaction_operation"] = validation_probe
        print(json.dumps(diagnostic, separators=(",", ":")))
        return _error("server_error", 500)
    reasons = details.get("CancellationReasons")
    if not isinstance(reasons, list) or len(reasons) != len(operations):
        print(json.dumps({
            "event": "household_join_complete_transaction_conflict",
            "safe_error_category": "transaction_canceled_unclassified",
        }, separators=(",", ":")))
        return _error("transaction_wrong_state", 409)
    failed = []
    for index, reason in enumerate(reasons):
        if not isinstance(reason, dict) or not isinstance(reason.get("Code"), str):
            print(json.dumps({
                "event": "household_join_complete_transaction_conflict",
                "safe_error_category": "transaction_canceled_unclassified",
            }, separators=(",", ":")))
            return _error("transaction_wrong_state", 409)
        if reason["Code"] != "None":
            failed.append(index)
    if len(failed) != 1:
        print(json.dumps({
            "event": "household_join_complete_transaction_conflict",
            "safe_error_category": "transaction_canceled_multiple",
        }, separators=(",", ":")))
        return _error("transaction_wrong_state", 409)
    index = failed[0]
    if reasons[index]["Code"] != "ConditionalCheckFailed" or index >= len(operations):
        print(json.dumps({
            "event": "household_join_complete_transaction_conflict",
            "safe_error_category": "transaction_canceled_unclassified",
        }, separators=(",", ":")))
        return _error("transaction_wrong_state", 409)
    operation = operations[index]
    if not isinstance(operation, dict) or operation.get("label") not in {
        "account", "auth_identity", "normalized_membership", "pending_lookup", "invitation", "join_transaction",
    }:
        print(json.dumps({
            "event": "household_join_complete_transaction_conflict",
            "safe_error_category": "transaction_canceled_unclassified",
        }, separators=(",", ":")))
        return _error("transaction_wrong_state", 409)
    try:
        result = operation["table"].get_item(Key=operation["key"], ConsistentRead=True)
    except ClientError:
        return _error("server_error", 500)
    except (AttributeError, KeyError, TypeError):
        return _error("transaction_wrong_state", 409)
    record = result.get("Item") if isinstance(result, dict) else None
    label = operation["label"]
    print(json.dumps({
        "event": "household_join_complete_transaction_conflict",
        "safe_error_category": "conditional_conflict",
        "failed_transaction_operation": label,
    }, separators=(",", ":")))
    if label == "invitation":
        if record is None:
            return _error("invitation_invalid", 409)
        if not isinstance(record, dict):
            return _error("transaction_wrong_state", 409)
        if str(record.get("state") or "") == "consumed":
            return _error("invitation_already_used", 409)
        if household_invitation_code_expiration(record) <= now:
            return _error("invitation_expired", 410)
        return _error("transaction_wrong_state", 409)
    if label == "join_transaction":
        if not isinstance(record, dict):
            return _error("transaction_wrong_state", 409)
        if int(record.get("expires_at") or 0) <= now:
            return _error("transaction_expired", 410)
        if str(record.get("state") or "") == "membership_accepted":
            return _error("transaction_wrong_state", 409)
        return _error("transaction_wrong_state", 409)
    if label == "normalized_membership" and isinstance(record, dict):
        expected = operation.get("expected") or {}
        if (
            record.get("entity_type") == "HouseholdMembership"
            and hmac.compare_digest(str(record.get("account_id") or ""), str(expected.get("account_id") or ""))
            and str(record.get("status") or "") in {"pending_profile", "active"}
        ):
            return _error("already_member", 409)
        if not hmac.compare_digest(
            str(record.get("account_id") or ""), str(expected.get("account_id") or ""),
        ):
            membership_category = "different_account"
        elif record.get("entity_type") != "HouseholdMembership":
            membership_category = "same_account_malformed"
        else:
            safe_status = str(record.get("status") or "")
            membership_category = (
                f"same_account_{safe_status}"
                if safe_status in {"revoked", "deletion_pending", "deleting"}
                else "same_account_malformed"
            )
        print(json.dumps({
            "event": "household_join_normalized_membership_conflict",
            "safe_membership_category": membership_category,
        }, separators=(",", ":")))
    return _error("manual_review_required", 409)


def _profile_setup_transaction_failure(error, operations):
    """Emit one bounded diagnostic for an atomic Profile Setup failure.

    Profile Setup must never expose a DynamoDB cancellation reason, item,
    subject, request identifier, or service message to a device or the log.
    The transaction is all-or-nothing, so the only diagnostic retained here is
    a fixed operation label when DynamoDB identifies one conditional failure.
    """
    details = getattr(error, "response", {}) or {}
    error_code = str((details.get("Error") or {}).get("Code") or "")
    diagnostic = {
        "event": "household_join_profile_setup_transaction_failure",
        "operation_count": len(operations) if isinstance(operations, list) else 0,
    }
    if error_code == "TransactionCanceledException":
        reasons = details.get("CancellationReasons")
        if not isinstance(reasons, list) or not isinstance(operations, list) or len(reasons) != len(operations):
            diagnostic["safe_error_category"] = "transaction_canceled_unclassified"
        else:
            failed = [
                index for index, reason in enumerate(reasons)
                if isinstance(reason, dict) and reason.get("Code") != "None"
            ]
            if (
                len(failed) == 1
                and reasons[failed[0]].get("Code") == "ConditionalCheckFailed"
                and isinstance(operations[failed[0]], dict)
                and str(operations[failed[0]].get("label") or "") == "household_seat_reservation"
            ):
                diagnostic["safe_error_category"] = "family_seat_limit_reached"
                diagnostic["failed_transaction_operation"] = "household_seat_reservation"
                print(json.dumps(diagnostic, separators=(",", ":")))
                return _error("family_seat_limit_reached", 409)
            if (
                len(failed) == 1
                and reasons[failed[0]].get("Code") == "ConditionalCheckFailed"
                and isinstance(operations[failed[0]], dict)
                and str(operations[failed[0]].get("label") or "") in {
                    "legacy_profile", "cloud_profile", "profile_binding", "profile_mapping",
                    "copied_entitlement", "principal", "identity_membership",
                    "normalized_membership", "join_transaction", "pending_lookup",
                }
            ):
                diagnostic["safe_error_category"] = "conditional_conflict"
                diagnostic["failed_transaction_operation"] = operations[failed[0]]["label"]
            else:
                diagnostic["safe_error_category"] = "transaction_canceled_unclassified"
        print(json.dumps(diagnostic, separators=(",", ":")))
        return _error("manual_review_required", 409)

    # A non-cancellation client error is an operational defect, not a user
    # conflict.  Do not collapse it to 409 or copy its service message.
    diagnostic["safe_error_category"] = {
        "AccessDeniedException": "access_denied",
        "InternalServerError": "internal_server_error",
        "ProvisionedThroughputExceededException": "provisioned_throughput",
        "RequestLimitExceeded": "request_limit",
        "ResourceNotFoundException": "resource_not_found",
        "TransactionInProgressException": "transaction_in_progress",
        "ValidationException": "transaction_validation",
    }.get(error_code, "other_client_error")
    print(json.dumps(diagnostic, separators=(",", ":")))
    return _error("server_error", 500)


def _safe_event(item, category, result, retryable=False, network_hash=""):
    """Persist bounded privacy-safe lifecycle evidence with the transaction."""
    if joins is None or not item:
        return
    event = {
        "category": category,
        "timestamp": utc_now_iso(),
        "transaction_hash": str(item.get("join_resume_hash") or ""),
        "invitation_hash": str(item.get("invitation_code_hash") or ""),
        "device_hash": str(item.get("device_binding_hash") or ""),
        "network_bucket_hash": network_hash,
        "result": result,
        "retryable": bool(retryable),
    }
    try:
        joins.update_item(
            Key={"join_resume_hash": item["join_resume_hash"]},
            UpdateExpression="SET audit_events = list_append(if_not_exists(audit_events, :empty), :event)",
            ExpressionAttributeValues={":empty": [], ":event": [event]},
        )
    except ClientError:
        # Audit must not make a valid invitation become consumed without a membership.
        pass


def _limit(scope, value, maximum, now):
    if joins is None or not value:
        return False
    window = now // RATE_WINDOW_SECONDS
    key = "rate_" + _sha(f"{scope}:{value}:{window}")
    try:
        joins.update_item(
            Key={"join_resume_hash": key},
            UpdateExpression="SET attempts = if_not_exists(attempts, :zero) + :one, expires_at = :expires, cleanup_at = :cleanup, entity_type = :kind",
            ConditionExpression="attribute_not_exists(attempts) OR attempts < :maximum",
            ExpressionAttributeValues={
                ":zero": 0, ":one": 1, ":maximum": maximum,
                ":expires": (window + 1) * RATE_WINDOW_SECONDS,
                ":cleanup": now + RETENTION_SECONDS, ":kind": "HouseholdJoinRateLimit",
            },
        )
        return True
    except ClientError:
        return False


def _rate_ok(
    event,
    *,
    phase,
    installation_hash="",
    invitation_hash="",
    transaction_hash="",
    email_hash="",
    maximum=RATE_MAXIMUM,
):
    """Consume rate limits for exactly one Join phase.

    A normal Join advances through begin, route, and complete. Those phases
    must not charge the same IP, device, or invitation counter repeatedly or
    a few legitimate/cancelled attempts can block every fresh invitation.
    Each phase retains the same per-scope ceiling while remaining isolated
    from the other phases.
    """
    phase = _valid(phase, r"(begin|route|complete)")
    if not phase:
        return False
    now = epoch_now()
    keys = [
        (f"{phase}-ip", _network_bucket(event), RATE_MAXIMUM),
        (f"{phase}-device", installation_hash, RATE_MAXIMUM),
        (f"{phase}-invitation", invitation_hash, RATE_MAXIMUM),
        (f"{phase}-transaction", transaction_hash, maximum),
        (f"{phase}-email-invitation", f"{invitation_hash}:{email_hash}" if invitation_hash and email_hash else "", RATE_MAXIMUM),
    ]
    return all(_limit(scope, value, limit, now) for scope, value, limit in keys if value)


def _consume_dpop_replay(item, jti, expires_at, *, method="POST", url=None):
    """Atomically consume a validated proof before business validation."""
    jti = str(jti or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", jti) or joins is None:
        return False
    identity = _sha(f"{item.get('dpop_thumbprint') or ''}:{jti}:{method}:{url or _completion_url()}")
    try:
        joins.put_item(
            Item={"join_resume_hash": f"replay_{identity}", "entity_type": "HouseholdJoinDpopReplay", "expires_at": int(expires_at) + DPOP_REPLAY_SAFETY_SECONDS, "cleanup_at": int(expires_at) + RETENTION_SECONDS},
            ConditionExpression="attribute_not_exists(join_resume_hash)",
        )
        return True
    except ClientError:
        return False


def _record_from_begin(handle, code_hash, invitation, installation_hash, thumbprint, correlation_hash, now):
    preauth_expires_at = now + JOIN_PREAUTH_TTL_SECONDS
    return {
        "join_resume_hash": _sha(handle), "entity_type": "HouseholdJoinResume",
        "invitation_code_hash": code_hash, "invitation_id": str(invitation.get("invitation_id") or ""),
        "device_binding_hash": installation_hash, "dpop_thumbprint": thumbprint,
        "correlation_hash": correlation_hash, "state": "initiated", "route_attempts": 0,
        "complete_attempts": 0, "created_at": utc_now_iso(), "created_at_epoch": now,
        "preauth_expires_at": preauth_expires_at,
        "absolute_expires_at": now + JOIN_ABSOLUTE_MAX_TTL_SECONDS,
        "expires_at": preauth_expires_at,
        "cleanup_at": now + RETENTION_SECONDS, "schema_version": 2,
    }


def begin(event):
    if joins is None or invitations is None:
        return _error("household_join_unavailable", 503, True)
    body = parse_json_body(event) or {}
    code_hash = _join_code_hash(body.get("invitation") or body.get("join_code"))
    installation_hash = _installation_hash(body.get("installation_id"))
    thumbprint = _thumbprint(body.get("dpop_thumbprint"))
    correlation_hash = _sha(_valid(body.get("correlation_nonce"), r"[A-Za-z0-9_-]{16,128}"))
    if not code_hash or not installation_hash or not thumbprint or not correlation_hash:
        _begin_outcome(
            event, "invalid_request", 400,
            installation_hash=installation_hash, invitation_hash=code_hash,
        )
        return _error("transaction_invalid")
    now = epoch_now()
    if not _rate_ok(event, phase="begin", installation_hash=installation_hash, invitation_hash=code_hash):
        _begin_outcome(
            event, "rate_limited", 429,
            installation_hash=installation_hash, invitation_hash=code_hash,
        )
        return _error("household_join_retry_later", 429, True)
    invitation = invitations.get_item(Key={"code_hash": code_hash}, ConsistentRead=True).get("Item")
    if not invitation or invitation.get("state") != "pending" or household_invitation_code_expiration(invitation) <= now:
        _begin_outcome(
            event, "invitation_invalid_or_expired", 410,
            installation_hash=installation_hash, invitation_hash=code_hash,
        )
        return _error("invitation_invalid_or_expired", 410)
    handle = "jr_" + secrets.token_urlsafe(32)
    item = _record_from_begin(handle, code_hash, invitation, installation_hash, thumbprint, correlation_hash, now)
    try:
        joins.put_item(Item=item, ConditionExpression="attribute_not_exists(join_resume_hash)")
    except ClientError:
        _begin_outcome(
            event, "transaction_create_failed", 503,
            installation_hash=installation_hash, invitation_hash=code_hash,
        )
        return _error("household_join_unavailable", 503, True)
    _safe_event(item, "transaction_created", "accepted", network_hash=_network_bucket(event))
    _begin_outcome(
        event, "accepted", 201,
        installation_hash=installation_hash, invitation_hash=code_hash,
    )
    return response(201, {"state": "household_join_ready", "join_resume_handle": handle, "expires_at": item["expires_at"], "next": "collect_email"})


def _user_exists(email):
    escaped = email.replace("\\", "\\\\").replace('"', '\\"')
    result = cognito.list_users(UserPoolId=USER_POOL_ID, Filter=f'email = "{escaped}"', Limit=2)
    return bool(result.get("Users") or [])


def resolve_email(event):
    """Choose the next native account form for one invitation-bound email.

    This lookup is available only while a valid, device-bound invitation is
    untouched. It returns no account or profile data and never changes the
    transaction state, leaving native completion independently bound to the
    original DPoP transaction.
    """
    if joins is None or not USER_POOL_ID:
        return _error("household_join_unavailable", 503, True)
    body = parse_json_body(event) or {}
    handle_hash = _handle_hash(body.get("join_resume_handle"))
    installation_hash = _installation_hash(body.get("installation_id"))
    email = _email(body.get("email"))
    if not all((handle_hash, installation_hash, email)):
        return _error("transaction_invalid")
    item = joins.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    now = epoch_now()
    if not item or int(item.get("expires_at") or 0) <= now:
        return _error("transaction_expired", 410)
    if (
        not hmac.compare_digest(str(item.get("device_binding_hash") or ""), installation_hash)
        or str(item.get("state") or "") != "initiated"
    ):
        return _error("transaction_wrong_state", 409)
    if not _rate_ok(
        event,
        phase="route",
        installation_hash=installation_hash,
        invitation_hash=str(item.get("invitation_code_hash") or ""),
        transaction_hash=handle_hash,
        email_hash=_sha(email),
        maximum=TRANSACTION_ROUTE_MAXIMUM,
    ):
        _safe_event(item, "resolve_email_throttled", "throttled", True, _network_bucket(event))
        return _error("household_join_retry_later", 429, True)
    try:
        next_step = "sign_in" if _user_exists(email) else "create_account"
    except ClientError:
        return _error("household_join_unavailable", 503, True)
    _safe_event(item, "resolve_email", "accepted", network_hash=_network_bucket(event))
    return response(200, {"state": "household_join_email_resolved", "next": next_step})


def route_auth(event):
    if joins is None or not all((USER_POOL_ID, AUTHORIZE_BASE_URL, NATIVE_CALLBACK_URI, NATIVE_AUTHORIZE_ENDPOINT, EXPECTED_CLIENT_ID)):
        return _error("household_join_unavailable", 503, True)
    body = parse_json_body(event) or {}
    handle = str(body.get("join_resume_handle") or "")
    handle_hash = _handle_hash(handle)
    installation_hash = _installation_hash(body.get("installation_id"))
    email = _email(body.get("email"))
    state = _valid(body.get("oauth_state"), r"[A-Za-z0-9_-]{16,256}")
    challenge = _valid(body.get("code_challenge"), r"[A-Za-z0-9_-]{43,128}")
    # This is the client-generated OIDC nonce. It is deliberately retained
    # only by this isolated, encrypted-at-rest transaction so authorize can
    # bind Cognito's ID token to the transaction that supplied the PKCE state.
    nonce = _valid(body.get("nonce"), r"[A-Za-z0-9_-]{16,128}")
    provider = str(body.get("provider") or "emailSignIn")
    if not all((handle_hash, installation_hash, email, state, challenge, nonce)) or provider not in {"emailSignIn", "apple", "google"}:
        return _error("transaction_invalid")
    item = joins.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    now = epoch_now()
    if not item or int(item.get("expires_at") or 0) <= now:
        return _error("transaction_expired", 410)
    if not hmac.compare_digest(str(item.get("device_binding_hash") or ""), installation_hash):
        return _error("transaction_invalid")
    email_hash = _sha(email)
    if str(item.get("state") or "") == "awaiting_authorization":
        # A transport retry may repeat precisely the same client-bound
        # authorization request. Any change, including a replacement nonce,
        # is a state conflict rather than an opportunity to rewrite it.
        if all((
            hmac.compare_digest(str(item.get("auth_state_hash") or ""), _sha(state)),
            hmac.compare_digest(str(item.get("code_challenge") or ""), challenge),
            hmac.compare_digest(str(item.get("oidc_nonce") or ""), nonce),
            hmac.compare_digest(str(item.get("email_hash") or ""), email_hash),
            hmac.compare_digest(str(item.get("cognito_route") or ""), provider),
        )):
            continuation = f"{AUTHORIZE_BASE_URL}?{urlencode({'resume': handle, 'state': state})}"
            return response(200, {"state": "household_join_auth_ready", "authorization_continuation_url": continuation, "expires_at": int(item["expires_at"])})
        return _error("transaction_wrong_state", 409)
    if str(item.get("state") or "") != "initiated":
        return _error("transaction_wrong_state", 409)
    if not _rate_ok(
        event,
        phase="route",
        installation_hash=installation_hash,
        invitation_hash=str(item.get("invitation_code_hash") or ""),
        transaction_hash=handle_hash,
        email_hash=email_hash,
        maximum=TRANSACTION_ROUTE_MAXIMUM,
    ):
        _safe_event(item, "route_auth_throttled", "throttled", True, _network_bucket(event))
        return _error("household_join_retry_later", 429, True)
    try:
        # Every Cognito managed-login session must originate at the OAuth
        # authorization endpoint.  Sending a new email directly to /signup
        # breaks the hosted federation lifecycle: an external provider may
        # accept consent without Cognito returning an authorization code to
        # Kaevo.  Keep one opaque route value for transaction compatibility,
        # but do not perform an account-existence lookup or select /signup.
        absolute_expires_at = int(item.get("absolute_expires_at") or 0)
        auth_expires_at = min(now + JOIN_AUTH_COMPLETION_TTL_SECONDS, absolute_expires_at)
        if auth_expires_at <= now:
            return _error("transaction_expired", 410)
        joins.update_item(
            Key={"join_resume_hash": handle_hash},
            UpdateExpression="SET #state = :state, auth_state_hash = :state_hash, code_challenge = :challenge, oidc_nonce = :nonce, email_hash = :email_hash, cognito_route = :route, auth_expires_at = :auth_expires, expires_at = :auth_expires, routed_at = :updated, route_attempts = route_attempts + :one, updated_at = :updated",
            ConditionExpression="#state = :initiated AND expires_at > :now AND absolute_expires_at > :now",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":state": "awaiting_authorization", ":state_hash": _sha(state), ":challenge": challenge, ":nonce": nonce, ":email_hash": email_hash, ":route": provider, ":auth_expires": auth_expires_at, ":one": 1, ":updated": utc_now_iso(), ":initiated": "initiated", ":now": now},
        )
    except ClientError:
        return _error("transaction_wrong_state", 409)
    _safe_event(item, "route_auth_attempted", "accepted", network_hash=_network_bucket(event))
    # This shape is identical for both routes. The app never receives Cognito's target URL.
    continuation = f"{AUTHORIZE_BASE_URL}?{urlencode({'resume': handle, 'state': state})}"
    return response(200, {"state": "household_join_auth_ready", "authorization_continuation_url": continuation, "expires_at": auth_expires_at})


def authorize(event):
    query = (event.get("queryStringParameters") or {})
    handle = str(query.get("resume") or "")
    state = str(query.get("state") or "")
    handle_hash = _handle_hash(handle)
    if not handle_hash or not _valid(state, r"[A-Za-z0-9_-]{16,256}") or joins is None:
        return {"statusCode": 400, "body": "Unable to continue securely."}
    item = joins.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    if not item or int(item.get("expires_at") or 0) <= epoch_now() or str(item.get("state") or "") != "awaiting_authorization" or not hmac.compare_digest(str(item.get("auth_state_hash") or ""), _sha(state)):
        return {"statusCode": 400, "body": "Unable to continue securely."}
    nonce = _valid(item.get("oidc_nonce"), r"[A-Za-z0-9_-]{16,128}")
    if not nonce:
        return {"statusCode": 400, "body": "Unable to continue securely."}
    query = {"client_id": EXPECTED_CLIENT_ID, "response_type": "code", "scope": "openid", "redirect_uri": NATIVE_CALLBACK_URI, "code_challenge": str(item.get("code_challenge") or ""), "code_challenge_method": "S256", "state": state, "nonce": nonce}
    provider = str(item.get("cognito_route") or "emailSignIn")
    if provider == "apple":
        query["identity_provider"] = "SignInWithApple"
    elif provider == "google":
        query["identity_provider"] = "Google"
    location = NATIVE_AUTHORIZE_ENDPOINT + "?" + urlencode(query)
    return {"statusCode": 302, "headers": {"Location": location, "Cache-Control": "no-store"}, "body": ""}


def _jwt_subject(event):
    claims = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or _gateway_jwt_claims(event)
    try:
        return validate_access_token_claims(claims, expected_issuer=EXPECTED_ISSUER, expected_client_id=EXPECTED_CLIENT_ID, now=epoch_now())["sub"]
    except AuthorityError:
        return ""


def _completion_url(*, native_password=False):
    suffix = "complete-native" if native_password else "complete"
    return f"{PUBLIC_API_BASE_URL}/v3/identity/household-joins/{suffix}"


def _is_terminal_rejoin_principal(principal, membership):
    """Recognize only the revoked principal shell left by immediate deletion."""
    return (
        isinstance(principal, dict)
        and str(principal.get("state") or "") == "revoked"
        and principal.get("revoked") is True
        and list(principal.get("profile_ids") or []) == []
        and membership is None
    )


def _is_terminal_deleting_membership(membership, *, account_id, household_id):
    """Recognize the exact non-authoritative membership left by deletion.

    The caller has already proved a terminal principal shell: no active legacy
    membership and no active profile IDs remain. A new Owner invitation can
    therefore replace only this same-account, same-household ``deleting`` row.
    The old profile identifier is retained solely as a deletion tombstone; it
    is not authorization and must not be parsed as one. Earlier profile-ID
    formats can be present on an otherwise exact terminal record, so requiring
    a current-format identifier here would strand a completed deletion.
    """
    if not isinstance(membership, dict):
        return False
    if not (
        membership.get("entity_type") == "HouseholdMembership"
        and membership.get("status") == "deleting"
        and hmac.compare_digest(str(membership.get("account_id") or ""), account_id)
        and hmac.compare_digest(str(membership.get("household_id") or ""), household_id)
    ):
        return False
    return True


def _terminal_deleting_membership_has_no_live_profile(membership):
    """Confirm that the retained membership row is only a deletion tombstone.

    This is intentionally a direct-key check, never a name lookup or table
    scan. A stale normalized membership can be released for a new invitation
    only when its prior profile is absent from both canonical profile stores.
    """
    if profiles is None or cloud_profiles is None or not isinstance(membership, dict):
        return False
    profile_id = str(membership.get("profile_id") or "").strip()
    # Profile identifiers written by older Kaevo releases may not have the
    # current `profile_` prefix. This bounds a DynamoDB key without treating
    # the identifier as an authorization claim.
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", profile_id):
        return False
    identity_profile = profiles.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    cloud_profile = cloud_profiles.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    return identity_profile is None and cloud_profile is None


def _auth_result_url():
    return f"{PUBLIC_API_BASE_URL}/v3/identity/household-joins/auth-result"


def _onboarding_status_url():
    return f"{PUBLIC_API_BASE_URL}/v3/identity/household-joins/onboarding-status"


def _profile_setup_url():
    return f"{PUBLIC_API_BASE_URL}/v3/identity/household-joins/profile-setup"


def _request_token(event):
    return str((event.get("headers") or {}).get("authorization") or (event.get("headers") or {}).get("Authorization") or "").removeprefix("Bearer ")


def _request_proof(event):
    return str((event.get("headers") or {}).get("dpop") or (event.get("headers") or {}).get("DPoP") or "")


def _pending_lookup_key(subject, installation_hash):
    """One direct recovery pointer per authenticated subject and installation."""
    return "pending_" + _sha(f"{subject}:{installation_hash}")


def _invitation_switch_profile_ids(value):
    """Validate exact server-issued profile-switch grants.

    Join never expands grants from display names or other mutable metadata.
    """
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise AccountFoundationError("invalid_switch_profile_grants")
    resolved = []
    for candidate in value:
        profile_id = str(candidate or "").strip()
        if (
            not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
            or profile_id in resolved
        ):
            raise AccountFoundationError("invalid_switch_profile_grants")
        resolved.append(profile_id)
    return resolved


def _invitation_watching_profile_ids(value):
    """Validate Who's Watching grants without treating them as switch grants."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 64:
        raise AccountFoundationError("invalid_watching_profile_grants")
    resolved = []
    for candidate in value:
        profile_id = str(candidate or "").strip()
        if (
            not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", profile_id)
            or profile_id in resolved
        ):
            raise AccountFoundationError("invalid_watching_profile_grants")
        resolved.append(profile_id)
    return resolved


def _normalized_invitation_parental_controls(value, *, require_child_safe=False):
    """Retain the invitation's exact viewing policy across device Join."""
    if value is None:
        if require_child_safe:
            raise AccountFoundationError("missing_child_viewing_level")
        return None
    if not isinstance(value, dict):
        raise AccountFoundationError("invalid_parental_controls")
    if type(value.get("version", 1)) is not int or value.get("version", 1) != 1:
        raise AccountFoundationError("invalid_parental_controls")
    preset = str(value.get("preset") or "").strip()
    enabled = value.get("is_enabled")
    hide_unrated = value.get("hide_unrated_content")
    if (
        preset not in {"littleKids", "olderKids", "teens", "unrestricted"}
        or not isinstance(enabled, bool)
        or not isinstance(hide_unrated, bool)
        or (require_child_safe and (not enabled or preset == "unrestricted"))
    ):
        raise AccountFoundationError("invalid_parental_controls")

    def string_values(key, maximum):
        raw = value.get(key) or []
        if not isinstance(raw, list) or len(raw) > maximum:
            raise AccountFoundationError("invalid_parental_controls")
        cleaned = []
        for candidate in raw:
            if not isinstance(candidate, str):
                raise AccountFoundationError("invalid_parental_controls")
            text = str(candidate or "").strip()
            if not text or len(text) > 120 or text in cleaned:
                raise AccountFoundationError("invalid_parental_controls")
            cleaned.append(text)
        return cleaned

    exceptions = value.get("exceptions") or []
    if not isinstance(exceptions, list) or len(exceptions) > 64:
        raise AccountFoundationError("invalid_parental_controls")
    normalized_exceptions = []
    for exception in exceptions:
        if not isinstance(exception, dict):
            raise AccountFoundationError("invalid_parental_controls")
        if not all(isinstance(exception.get(key), str) for key in ("id", "title", "scope")):
            raise AccountFoundationError("invalid_parental_controls")
        identifier = exception["id"].strip()
        if not identifier or len(identifier) > 160:
            raise AccountFoundationError("invalid_parental_controls")
        scope = str(exception.get("scope") or "").strip()
        provider_item_ids = exception.get("provider_item_ids") or []
        if scope not in {"title", "collection"} or not isinstance(provider_item_ids, list):
            raise AccountFoundationError("invalid_parental_controls")
        cleaned_item_ids = []
        for provider_item_id in provider_item_ids:
            if not isinstance(provider_item_id, str):
                raise AccountFoundationError("invalid_parental_controls")
            item_id = str(provider_item_id or "").strip()
            if not item_id or len(item_id) > 160 or item_id in cleaned_item_ids:
                raise AccountFoundationError("invalid_parental_controls")
            cleaned_item_ids.append(item_id)
        if not cleaned_item_ids:
            raise AccountFoundationError("invalid_parental_controls")
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


def _stored_policy_bool(value, *, default, field):
    """Read only booleans written by the trusted invitation service.

    Python's ``bool("false")`` is true, so coercing stored policy values would
    permit malformed data to silently change authority.  Join fails closed
    instead.
    """
    if value is None:
        return bool(default)
    if not isinstance(value, bool):
        raise AccountFoundationError(f"invalid_{field}")
    return value


def _pending_membership(item):
    """Read only the normalized pending membership owned by this transaction.

    A pending membership deliberately has no legacy principal, identity
    membership, or profile authority.  Existing shared authority evaluation
    therefore continues to fail closed until profile setup atomically creates
    the active graph.
    """
    if household_memberships is None or not isinstance(item, dict):
        return None
    account_id = str(item.get("account_id") or "")
    household_id = str(item.get("household_id") or "")
    if not account_id or not household_id:
        return None
    record = household_memberships.get_item(
        Key={"household_id": household_id, "membership_id": household_membership_id(account_id, household_id)},
        ConsistentRead=True,
    ).get("Item")
    if not isinstance(record, dict):
        return None
    if (
        record.get("entity_type") != "HouseholdMembership"
        or record.get("status") != "pending_profile"
        or record.get("profile_id")
        or not hmac.compare_digest(str(record.get("account_id") or ""), account_id)
        or not hmac.compare_digest(str(record.get("household_id") or ""), household_id)
    ):
        return None
    return record


def _verify_join_proof(event, item, *, method, url, on_rejected=None):
    try:
        verify_dpop(
            _request_proof(event), method=method, url=url,
            expected_thumbprint=str(item.get("dpop_thumbprint") or ""), access_token=_request_token(event),
            replay_guard=lambda jti, expires_at: _consume_dpop_replay(item, jti, expires_at, method=method, url=url),
        )
    except IdentityError as error:
        if on_rejected is not None:
            try:
                on_rejected(_dpop_rejection_category(error))
            except Exception:
                pass
        return False
    return True


# This is deliberately a finite protocol vocabulary.  It is sent only after
# the managed-login browser returns and never carries a token, authorization
# code, callback URL, provider message, email, invitation, or account ID.
AUTH_RESULT_CATEGORIES = frozenset({
    "callback_invalid",
    "callback_missing",
    "provider_callback_access_denied",
    "provider_callback_client_rejected",
    "provider_callback_invalid_request",
    "provider_callback_invalid_scope",
    "provider_callback_server_error",
    "provider_callback_unavailable",
    "provider_callback_other",
    "provider_rejected",
    "managed_login_session_failed",
    "token_exchange_failed",
    "token_contract_rejected",
    "complete_failed",
})


def auth_result(event):
    """Record one privacy-safe post-login failure observation.

    This route intentionally has no API Gateway JWT authorizer because the
    diagnostic is needed precisely when the code exchange or token contract
    has failed.  Its authorization is instead the exact, short-lived Join
    transaction binding: opaque handle, installation, stored OAuth state, and
    the device DPoP key retained by ``begin``.  It never changes invitation,
    membership, account, profile, installation, or transaction state.
    """
    if joins is None or not PUBLIC_API_BASE_URL:
        return _error("household_join_unavailable", 503, True)
    body = parse_json_body(event) or {}
    handle_hash = _handle_hash(body.get("join_resume_handle"))
    installation_hash = _installation_hash(body.get("installation_id"))
    state = _valid(body.get("oauth_state"), r"[A-Za-z0-9_-]{16,256}")
    category = str(body.get("category") or "")
    if not handle_hash or not installation_hash or not state or category not in AUTH_RESULT_CATEGORIES:
        return _error("transaction_invalid")
    item = joins.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    if not item or int(item.get("expires_at") or 0) <= epoch_now():
        return _error("transaction_expired", 410)
    if not all((
        str(item.get("state") or "") == "awaiting_authorization",
        hmac.compare_digest(str(item.get("device_binding_hash") or ""), installation_hash),
        hmac.compare_digest(str(item.get("auth_state_hash") or ""), _sha(state)),
    )):
        return _error("transaction_invalid", 401)
    try:
        verify_dpop(
            _request_proof(event), method="POST", url=_auth_result_url(),
            expected_thumbprint=str(item.get("dpop_thumbprint") or ""), access_token=None,
            replay_guard=lambda jti, expires_at: _consume_dpop_replay(
                item, jti, expires_at, method="POST", url=_auth_result_url()
            ),
        )
    except IdentityError:
        return _error("transaction_invalid", 401)
    _safe_event(item, f"auth_result_{category}", "observed", network_hash=_network_bucket(event))
    _auth_result_outcome(event, category, item=item)
    return response(204, {})


def _resume_context(event, *, method, url, onboarding_status_diagnostic=False):
    """Return the DPoP-bound, opaque onboarding continuation or a safe error."""
    if not all((joins, household_memberships, PUBLIC_API_BASE_URL)):
        return None, None, None, _error("household_join_unavailable", 503, True)
    subject = _jwt_subject(event)
    source = parse_json_body(event) or {} if method == "POST" else (event.get("queryStringParameters") or {})
    handle_hash = _handle_hash(source.get("join_resume_handle") or source.get("resume"))
    installation_hash = _installation_hash(source.get("installation_id"))
    if not subject or not installation_hash:
        if onboarding_status_diagnostic:
            _onboarding_status_rejection(
                event,
                "JWT_SUBJECT_MISSING" if not subject else "INSTALLATION_BINDING_MISSING",
                subject=subject,
                installation_hash=installation_hash,
            )
        return None, None, None, _error("transaction_invalid", 401)
    if not handle_hash:
        pointer = joins.get_item(
            Key={"join_resume_hash": _pending_lookup_key(subject, installation_hash)}, ConsistentRead=True
        ).get("Item")
        if not pointer:
            return subject, None, source, None
        target = str(pointer.get("target_join_resume_hash") or "")
        if (
            pointer.get("entity_type") != "HouseholdJoinPendingLookup"
            or int(pointer.get("expires_at") or 0) <= epoch_now()
            or not target
            or not hmac.compare_digest(str(pointer.get("member_principal_id") or ""), subject)
            or not hmac.compare_digest(str(pointer.get("device_binding_hash") or ""), installation_hash)
        ):
            return None, None, None, _error("manual_review_required", 409)
        handle_hash = target
    item = joins.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    if not item or not hmac.compare_digest(str(item.get("device_binding_hash") or ""), installation_hash):
        return None, None, None, _error("transaction_invalid", 404)
    if not hmac.compare_digest(str(item.get("member_principal_id") or ""), subject):
        if onboarding_status_diagnostic:
            _onboarding_status_rejection(
                event, "ACCOUNT_SUBJECT_MISMATCH", subject=subject,
                installation_hash=installation_hash, item=item,
            )
        return None, None, None, _error("authentication_mismatch", 401)
    if not _verify_join_proof(
        event, item, method=method, url=url,
        on_rejected=(
            lambda reason: _onboarding_status_rejection(
                event, reason, subject=subject, installation_hash=installation_hash, item=item,
            )
        ) if onboarding_status_diagnostic else None,
    ):
        return None, None, None, _error("authentication_mismatch", 401)
    return subject, item, source, None


def complete(event, *, native_password=False):
    if not all((
        joins, invitations, principals, accounts, auth_identities,
        household_memberships, memberships, USER_POOL_ID, PUBLIC_API_BASE_URL,
    )):
        return _completion_rejection(
            event, "household_join_unavailable", 503,
            outcome="configuration_unavailable", retryable=True,
        )
    subject = _jwt_subject(event)
    body = parse_json_body(event) or {}
    handle_hash = _handle_hash(body.get("join_resume_handle"))
    installation_hash = _installation_hash(body.get("installation_id"))
    state = None if native_password else _valid(body.get("oauth_state"), r"[A-Za-z0-9_-]{16,256}")
    if not subject or not handle_hash or not installation_hash or (not native_password and not state):
        return _completion_rejection(
            event, "transaction_invalid", 401,
            outcome="missing_completion_binding", subject=subject,
            installation_hash=installation_hash,
        )
    item = joins.get_item(Key={"join_resume_hash": handle_hash}, ConsistentRead=True).get("Item")
    now = epoch_now()
    if not item:
        return _completion_rejection(
            event, "transaction_invalid", 404,
            outcome="transaction_not_found", subject=subject,
            installation_hash=installation_hash,
        )
    if int(item.get("expires_at") or 0) <= now:
        return _completion_rejection(
            event, "transaction_expired", 410,
            outcome="transaction_expired", item=item, subject=subject,
            installation_hash=installation_hash,
        )
    if not hmac.compare_digest(str(item.get("device_binding_hash") or ""), installation_hash):
        return _completion_rejection(
            event, "device_binding_mismatch", 409,
            outcome="device_binding_mismatch", item=item, subject=subject,
            installation_hash=installation_hash,
        )
    if not native_password and not hmac.compare_digest(str(item.get("auth_state_hash") or ""), _sha(state)):
        return _completion_rejection(
            event, "callback_mismatch", 409,
            outcome="callback_state_mismatch", item=item, subject=subject,
            installation_hash=installation_hash,
        )
    expected_state = "initiated" if native_password else "awaiting_authorization"
    completion_mode = "native_password" if native_password else "managed_login"
    if str(item.get("state") or "") not in {expected_state, "membership_accepted"}:
        return _completion_rejection(
            event, "transaction_wrong_state", 409,
            outcome="transaction_wrong_state", item=item, subject=subject,
            installation_hash=installation_hash,
        )
    if not _rate_ok(
        event,
        phase="complete",
        installation_hash=installation_hash,
        transaction_hash=handle_hash,
        maximum=TRANSACTION_COMPLETE_MAXIMUM,
    ):
        _safe_event(item, "completion_throttled", "throttled", True, _network_bucket(event))
        return _completion_rejection(
            event, "household_join_retry_later", 429,
            outcome="completion_rate_limited", item=item, subject=subject,
            installation_hash=installation_hash, retryable=True,
        )
    if not _verify_join_proof(
        event,
        item,
        method="POST",
        url=_completion_url(native_password=native_password),
    ):
        _safe_event(item, "completion_mismatch", "denied", network_hash=_network_bucket(event))
        _completion_outcome(
            event, "proof_binding_mismatch", 401, item=item,
            subject=subject, installation_hash=installation_hash,
        )
        return _error("authentication_mismatch", 401)
    if str(item.get("state") or "") == "membership_accepted":
        accepted_mode = str(item.get("auth_completion_mode") or "managed_login")
        if not hmac.compare_digest(accepted_mode, completion_mode):
            _completion_outcome(
                event, "accepted_authentication_mode_mismatch", 409, item=item,
                subject=subject, installation_hash=installation_hash,
            )
            return _error("transaction_wrong_state", 409)
        if not hmac.compare_digest(str(item.get("member_principal_id") or ""), subject):
            _completion_outcome(
                event, "accepted_subject_mismatch", 401, item=item,
                subject=subject, installation_hash=installation_hash,
            )
            return _error("authentication_mismatch", 401)
        pending = _pending_membership(item)
        if pending:
            _completion_outcome(
                event, "already_completed_profile_setup", 200, item=item,
                subject=subject, installation_hash=installation_hash,
            )
            return _profile_setup_required_response(
                state="already_completed",
                membership=pending,
            )
        _completion_outcome(
            event, "already_completed_installation_setup", 200, item=item,
            subject=subject, installation_hash=installation_hash,
        )
        return response(200, {"state": "already_completed", "next": "installation_setup_required"})
    try:
        # The authenticated subject is the authority.  The e-mail typed before
        # hosted login is only route metadata and may legitimately differ for
        # Apple relay, Google account choice, or a new e-mail/password account.
        user = cognito.list_users(UserPoolId=USER_POOL_ID, Filter=f'sub = "{subject}"', Limit=2).get("Users") or []
        attributes = {entry.get("Name"): entry.get("Value") for entry in (user[0].get("Attributes") if user else [])}
        if len(user) != 1 or not _email(attributes.get("email")):
            return _completion_rejection(
                event, "authentication_mismatch", 401,
                outcome="authenticated_subject_lookup_invalid", item=item,
                subject=subject, installation_hash=installation_hash,
            )
    except ClientError:
        return _completion_rejection(
            event, "household_join_unavailable", 503,
            outcome="authenticated_subject_lookup_unavailable", item=item,
            subject=subject, installation_hash=installation_hash, retryable=True,
        )
    invitation = invitations.get_item(Key={"code_hash": str(item.get("invitation_code_hash") or "")}, ConsistentRead=True).get("Item")
    if not invitation or invitation.get("state") != "pending" or household_invitation_code_expiration(invitation) <= now:
        return _completion_rejection(
            event, "invitation_expired", 410,
            outcome="invitation_unavailable_or_expired", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    household_id = str(invitation.get("household_id") or "")
    existing = principals.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    existing_membership = memberships.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
    terminal_rejoin_principal = _is_terminal_rejoin_principal(existing, existing_membership)
    if existing and not terminal_rejoin_principal:
        if hmac.compare_digest(str(existing.get("household_id") or ""), household_id):
            return response(200, {"state": "already_member", "next": "installation_setup_required"})
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="existing_principal_other_household", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    created = utc_now_iso()
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
    except AccountFoundationError:
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="invitation_role_policy_invalid", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    if not household_id:
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="invitation_household_missing", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    role = age_role.value
    household_access = access_role.value
    reserved_profile_id = str(invitation.get("profile_id") or "").strip()
    reserved_display_name = str(invitation.get("display_name") or "").strip()
    reserved_profile_type = str(invitation.get("profile_type") or "").strip().lower()
    if (
        not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", reserved_profile_id)
        or not reserved_display_name
        or len(reserved_display_name) > 80
        or reserved_profile_type not in {"adult", "kid"}
        or (reserved_profile_type == "kid") != (role in {"teen", "child"})
    ):
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="invitation_profile_reservation_invalid", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    try:
        cloud_access_enabled = _stored_policy_bool(
            invitation.get("cloud_access_enabled"),
            default=True,
            field="cloud_access_policy",
        )
        request_access_enabled = _stored_policy_bool(
            invitation.get("request_access_enabled"),
            default=False,
            field="request_access_policy",
        )
        parental_controls = _normalized_invitation_parental_controls(
            invitation.get("parental_controls"),
            require_child_safe=(
                reserved_profile_type == "kid"
                and "parental_controls" in invitation
            ),
        )
        watching_profile_ids = _invitation_watching_profile_ids(
            invitation.get("watching_profile_ids")
        )
    except AccountFoundationError:
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="invitation_access_policy_invalid", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    try:
        identity_key = provider_subject_key("cognito", subject)
        auth_identity = auth_identities.get_item(Key={"auth_identity_key": identity_key}, ConsistentRead=True).get("Item")
        auth_identity_existing = bool(auth_identity)
        account_id = ""
        account = None
        if auth_identity:
            account_id = str(auth_identity.get("account_id") or "")
            assert_auth_identity_binding(auth_identity, account_id=account_id, provider="cognito", provider_subject=subject)
            account = accounts.get_item(Key={"account_id": account_id}, ConsistentRead=True).get("Item")
            if not isinstance(account, dict) or account.get("entity_type") != "Account" or account.get("status") != "active":
                return _completion_rejection(
                    event, "manual_review_required", 409,
                    outcome="auth_identity_account_inactive", item=item,
                    subject=subject, installation_hash=installation_hash,
                )
        else:
            account_id = "acct_" + secrets.token_urlsafe(24)
            account = build_account_record(account_id, now_iso=created, now_epoch=now)
            auth_identity = build_auth_identity_record(
                account_id=account_id, provider="cognito", provider_subject=subject,
                now_iso=created, now_epoch=now,
                email=attributes.get("email"), email_verified=str(attributes.get("email_verified") or "").lower() == "true",
            )
        if terminal_rejoin_principal and not hmac.compare_digest(
            str(existing.get("account_id") or ""), account_id,
        ):
            return _completion_rejection(
                event, "manual_review_required", 409,
                outcome="terminal_rejoin_account_mismatch", item=item,
                subject=subject, installation_hash=installation_hash,
            )
    except AccountFoundationError:
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="auth_identity_binding_invalid", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    membership_id = household_membership_id(account_id, household_id)
    existing_normalized_membership = household_memberships.get_item(
        Key={"household_id": household_id, "membership_id": membership_id},
        ConsistentRead=True,
    ).get("Item")
    terminal_deleting_membership = (
        terminal_rejoin_principal
        and _is_terminal_deleting_membership(
            existing_normalized_membership,
            account_id=account_id,
            household_id=household_id,
        )
        and _terminal_deleting_membership_has_no_live_profile(
            existing_normalized_membership,
        )
    )
    permitted_membership_status_expression = "= :revoked"
    normalized_membership_expression_values = {
        ":entity_type": "HouseholdMembership",
        ":account_id": account_id,
        ":household_id": household_id,
        ":revoked": "revoked",
    }
    if terminal_deleting_membership:
        permitted_membership_status_expression = "IN (:revoked, :deleting)"
        normalized_membership_expression_values[":deleting"] = "deleting"
    pending_lookup_key = _pending_lookup_key(subject, installation_hash)
    existing_lookup = joins.get_item(Key={"join_resume_hash": pending_lookup_key}, ConsistentRead=True).get("Item")
    if existing_lookup:
        # Never choose among multiple or stale pending continuations.  The
        # caller receives a safe manual-review result instead of a lookup.
        return _completion_rejection(
            event, "manual_review_required", 409,
            outcome="pending_lookup_already_exists", item=item,
            subject=subject, installation_hash=installation_hash,
        )
    normalized_membership = {
        "household_id": household_id,
        "membership_id": membership_id,
        "entity_type": "HouseholdMembership",
        "account_id": account_id,
        "canonical_role": role,
        "household_access_role": household_access,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
        "reserved_profile_id": reserved_profile_id,
        "reserved_display_name": reserved_display_name,
        "reserved_profile_type": reserved_profile_type,
        "status": "pending_profile",
        "joined_at": created,
        "updated_at": created,
        "updated_at_epoch": now,
        "schema_version": 1,
        "profile_access_policy_ref": "profile-binding-required-v1",
    }
    pending_lookup = {
        "join_resume_hash": pending_lookup_key,
        "entity_type": "HouseholdJoinPendingLookup",
        "target_join_resume_hash": handle_hash,
        "member_principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        "canonical_role": role,
        "household_access_role": household_access,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
        "reserved_profile_id": reserved_profile_id,
        "reserved_display_name": reserved_display_name,
        "reserved_profile_type": reserved_profile_type,
        "device_binding_hash": installation_hash,
        "state": "profile_setup_required",
        "expires_at": now + RETENTION_SECONDS,
        "cleanup_at": now + RETENTION_SECONDS,
    }
    consumed = {**invitation, "state": "consumed", "consumed_at": created, "member_principal_id": subject}
    transaction_operations = [
        {
            "label": "account", "table": accounts, "key": {"account_id": account_id},
            "transaction": {"Put": {"TableName": ACCOUNTS_TABLE, "Item": account, "ConditionExpression": "attribute_not_exists(account_id)"}},
        } if not auth_identity_existing else None,
        {
            "label": "auth_identity", "table": auth_identities, "key": {"auth_identity_key": identity_key},
            "transaction": {"Put": {"TableName": AUTH_IDENTITIES_TABLE, "Item": auth_identity, "ConditionExpression": "attribute_not_exists(auth_identity_key)"}},
        } if not auth_identity_existing else None,
        {
            "label": "normalized_membership", "table": household_memberships,
            "key": {"household_id": household_id, "membership_id": membership_id},
            "expected": {"account_id": account_id},
            # Immediate profile deletion retains a revoked membership row so
            # canonical history and external cleanup remain attributable. A
            # fresh, proof-bound invitation may replace only that exact row
            # for the same account and household; it can never take over an
            # active, pending, malformed, or differently owned membership.
            "transaction": {"Put": {
                "TableName": HOUSEHOLD_MEMBERSHIPS_TABLE,
                "Item": normalized_membership,
                "ConditionExpression": (
                    "(attribute_not_exists(household_id) AND attribute_not_exists(membership_id)) OR "
                    "(entity_type = :entity_type AND account_id = :account_id "
                    "AND household_id = :household_id AND #status "
                    + permitted_membership_status_expression
                    + ")"
                ),
                "ExpressionAttributeNames": {"#status": "status"},
                "ExpressionAttributeValues": normalized_membership_expression_values,
            }},
        },
        {
            "label": "pending_lookup", "table": joins, "key": {"join_resume_hash": pending_lookup_key},
            "transaction": {"Put": {"TableName": JOIN_TABLE, "Item": pending_lookup, "ConditionExpression": "attribute_not_exists(join_resume_hash)"}},
        },
        {
            "label": "invitation", "table": invitations, "key": {"code_hash": str(item.get("invitation_code_hash") or "")},
            "transaction": {"Put": {"TableName": INVITATIONS_TABLE, "Item": consumed, "ConditionExpression": "#state = :pending", "ExpressionAttributeNames": {"#state": "state"}, "ExpressionAttributeValues": {":pending": "pending"}}},
        },
        {
            "label": "join_transaction", "table": joins, "key": {"join_resume_hash": handle_hash},
            "transaction": {"Update": {
                "TableName": JOIN_TABLE,
                "Key": {"join_resume_hash": handle_hash},
                "UpdateExpression": (
                    "SET #state = :accepted, completed_at = :completed, "
                    "member_principal_id = :subject, account_id = :account, "
                    "household_id = :household, canonical_role = :role, "
                    "household_access_role = :access_role, "
                    "cloud_access_enabled = :cloud_access, "
                    "request_access_enabled = :request_access, "
                    "parental_controls = :parental_controls, "
                    "switch_profile_ids = :switch_profiles, "
                    "watching_profile_ids = :watching_profiles, "
                    "auth_completion_mode = :auth_completion_mode, "
                    "owner_profile_id = :owner_profile, "
                    "reserved_profile_id = :reserved_profile, "
                    "reserved_display_name = :reserved_name, "
                    "reserved_profile_type = :reserved_type, "
                    "expires_at = :expires"
                ),
                "ConditionExpression": "#state = :awaiting AND expires_at > :now",
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {
                    ":accepted": "membership_accepted",
                    ":awaiting": expected_state,
                    ":auth_completion_mode": completion_mode,
                    ":completed": created,
                    ":subject": subject,
                    ":account": account_id,
                    ":household": household_id,
                    ":role": role,
                    ":access_role": household_access,
                    ":cloud_access": cloud_access_enabled,
                    ":request_access": request_access_enabled,
                    ":parental_controls": parental_controls,
                    ":switch_profiles": switch_profile_ids,
                    ":watching_profiles": watching_profile_ids,
                    ":owner_profile": str(invitation.get("owner_profile_id") or ""),
                    ":reserved_profile": reserved_profile_id,
                    ":reserved_name": reserved_display_name,
                    ":reserved_type": reserved_profile_type,
                    ":expires": now + RETENTION_SECONDS,
                    ":now": now,
                },
            }},
        },
    ]
    transaction_operations = [operation for operation in transaction_operations if operation is not None]
    transaction = [operation["transaction"] for operation in transaction_operations]
    try:
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError as error:
        return _completion_transaction_conflict(error, transaction_operations, now)
    _safe_event(item, "membership_created", "success", network_hash=_network_bucket(event))
    return response(201, {
        "state": "membership_created",
        "next": "profile_setup_required",
        "profile_id": reserved_profile_id,
        "display_name": reserved_display_name,
        "profile_type": reserved_profile_type,
    })


def complete_native(event):
    """Complete only an untouched QR transaction using native credentials.

    This route never accepts an OAuth state and only permits the transaction's
    initial state. A transaction already routed to managed login must complete
    on the PKCE route it was bound to; it cannot be switched into native auth.
    """
    return complete(event, native_password=True)


def _profile_setup_required_response(*, state, membership):
    payload = {"state": state, "next": "profile_setup_required"}
    reserved = {
        "profile_id": str(membership.get("reserved_profile_id") or "").strip(),
        "display_name": str(membership.get("reserved_display_name") or "").strip(),
        "profile_type": str(membership.get("reserved_profile_type") or "").strip().lower(),
    }
    # Older pending records predate canonical invitation-profile propagation.
    # Preserve their public response shape rather than emitting empty identity
    # fields. New joins always persist all three fields atomically.
    if all(reserved.values()):
        payload.update(reserved)
    return response(200, payload)


def onboarding_status(event):
    subject, item, _source, failure = _resume_context(
        event, method="GET", url=_onboarding_status_url(), onboarding_status_diagnostic=True,
    )
    if failure:
        return failure
    if item is None:
        return response(200, {"state": "no_pending_onboarding", "next": "completed"})
    membership = _pending_membership(item)
    if membership:
        return _profile_setup_required_response(
            state="membership_created",
            membership=membership,
        )
    if str(item.get("state") or "") == "completed":
        return response(200, {"state": "completed", "next": "installation_setup_required"})
    return _error("manual_review_required", 409)


def _consumed_invitation_jellyfin_binding(
    invitation, *, household_id, profile_id, member_principal_id,
):
    """Return one exact active provider edge owned by the consumed invitation.

    Profile Setup may promote only the reservation consumed by this exact
    authenticated member.  Missing/deferred media access stays absent; any
    malformed or cross-identity active edge fails closed for manual review.
    """
    if not isinstance(invitation, dict) or invitation.get("state") != "consumed":
        raise AccountFoundationError("profile_jellyfin_binding_source_missing")
    if not (
        hmac.compare_digest(str(invitation.get("household_id") or ""), household_id)
        and hmac.compare_digest(str(invitation.get("profile_id") or ""), profile_id)
        and hmac.compare_digest(
            str(invitation.get("member_principal_id") or ""), member_principal_id,
        )
    ):
        raise AccountFoundationError("profile_jellyfin_binding_source_conflict")

    binding_state = str(invitation.get("jellyfin_binding_state") or "").strip().lower()
    if not binding_state:
        return {}
    if binding_state != "active":
        raise AccountFoundationError("profile_jellyfin_binding_source_invalid")
    connector_id = str(invitation.get("jellyfin_connector_id") or "").strip()
    compact_user_id = str(invitation.get("jellyfin_user_id") or "").strip().replace("-", "")
    if (
        not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", connector_id)
        or not re.fullmatch(r"[0-9a-fA-F]{32}", compact_user_id)
    ):
        raise AccountFoundationError("profile_jellyfin_binding_source_invalid")
    return {
        "jellyfin_connector_id": connector_id,
        "jellyfin_user_id": compact_user_id.lower(),
        "jellyfin_binding_state": "active",
        "jellyfin_binding_updated_at": str(
            invitation.get("jellyfin_binding_updated_at") or utc_now_iso()
        ),
    }


def _consumed_invitation_provider_bindings(
    invitation, *, household_id, profile_id, member_principal_id,
):
    """Return only the exact, internally consistent provider tuple on claim."""
    binding = _consumed_invitation_jellyfin_binding(
        invitation,
        household_id=household_id,
        profile_id=profile_id,
        member_principal_id=member_principal_id,
    )
    seerr_state = str(invitation.get("seerr_binding_state") or "").strip().lower()
    if not seerr_state:
        return binding
    if seerr_state != "active" or not binding:
        raise AccountFoundationError("profile_seerr_binding_source_invalid")

    seerr_connector_id = str(invitation.get("seerr_connector_id") or "").strip()
    seerr_jellyfin_user_id = _normalized_jellyfin_user_id(
        invitation.get("seerr_jellyfin_user_id"),
    )
    seerr_user_id = _normalized_seerr_user_id(invitation.get("seerr_user_id"))
    if not (
        seerr_connector_id
        and seerr_jellyfin_user_id
        and seerr_user_id
        and invitation.get("request_access_enabled") is True
        and hmac.compare_digest(
            seerr_connector_id, str(binding.get("jellyfin_connector_id") or ""),
        )
        and hmac.compare_digest(
            seerr_jellyfin_user_id, str(binding.get("jellyfin_user_id") or ""),
        )
    ):
        raise AccountFoundationError("profile_seerr_binding_source_invalid")

    binding.update({
        "seerr_connector_id": seerr_connector_id,
        "seerr_jellyfin_user_id": seerr_jellyfin_user_id,
        "seerr_user_id": seerr_user_id,
        "seerr_binding_state": "active",
        "seerr_binding_updated_at": str(
            invitation.get("seerr_binding_updated_at") or utc_now_iso()
        ),
        "request_access_enabled": True,
    })
    return binding


def profile_setup(event):
    required = (joins, invitations, principals, memberships, profiles, cloud_profiles, entitlements, household_memberships, profile_bindings, profile_mappings)
    if households is None or any(table is None for table in required):
        return _error("household_join_unavailable", 503, True)
    subject, item, body, failure = _resume_context(event, method="POST", url=_profile_setup_url())
    if failure:
        return failure
    if item is None:
        return _error("no_pending_onboarding", 404)
    membership = _pending_membership(item)
    if not membership:
        existing_principal = principals.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
        existing_membership = memberships.get_item(Key={"principal_id": subject}, ConsistentRead=True).get("Item")
        if (
            str(item.get("state") or "") == "completed"
            and isinstance(existing_principal, dict)
            and isinstance(existing_membership, dict)
            and existing_principal.get("state") == "active"
            and existing_membership.get("state") == "active"
            and str(existing_membership.get("profile_id") or "")
        ):
            return response(200, {"state": "completed", "next": "installation_setup_required"})
        return _error("manual_review_required", 409)
    action = str(body.get("action") or "")
    installation_id = str(body.get("installation_id") or "")
    if not hmac.compare_digest(_installation_hash(installation_id), str(item.get("device_binding_hash") or "")):
        return _error("device_binding_mismatch", 409)
    try:
        source_id = local_profile_source_id(body.get("local_profile_source_id"))
    except AccountFoundationError:
        return _error("transaction_invalid")
    now = epoch_now()
    created = utc_now_iso()
    account_id = str(membership.get("account_id") or "")
    household_id = str(membership.get("household_id") or "")
    try:
        age_role = canonical_role(membership.get("canonical_role"))
        access_role = household_access_role(
            membership.get("household_access_role"),
            canonical=age_role,
        )
        switch_profile_ids = _invitation_switch_profile_ids(
            membership.get("switch_profile_ids")
        )
        cloud_access_enabled = _stored_policy_bool(
            membership.get("cloud_access_enabled"),
            default=True,
            field="cloud_access_policy",
        )
        request_access_enabled = _stored_policy_bool(
            membership.get("request_access_enabled"),
            default=False,
            field="request_access_policy",
        )
        parental_controls = _normalized_invitation_parental_controls(
            membership.get("parental_controls"),
            require_child_safe=(
                age_role.value in {"teen", "child"}
                and "parental_controls" in membership
            ),
        )
        watching_profile_ids = _invitation_watching_profile_ids(
            membership.get("watching_profile_ids")
        )
    except AccountFoundationError:
        return _error("manual_review_required", 409)
    role = age_role.value
    household_access = access_role.value
    try:
        if action == "create_profile":
            reserved_profile_id = str(membership.get("reserved_profile_id") or "").strip()
            reserved_display_name = str(membership.get("reserved_display_name") or "").strip()
            reserved_profile_type = str(membership.get("reserved_profile_type") or "").strip().lower()
            if (
                not re.fullmatch(r"profile_[A-Za-z0-9_-]{16,128}", reserved_profile_id)
                or not reserved_display_name
                or reserved_profile_type not in {"adult", "kid"}
            ):
                return _error("manual_review_required", 409)
            creation = build_profile_creation(
                household_id=household_id, account_id=account_id,
                display_name=reserved_display_name,
                # The pending membership, not the device request body, owns age
                # and household authority for this transition. The invitation
                # also owns the canonical profile ID and display name because
                # provider identities may already be bound to that reservation.
                profile_type=role, age_classification=role,
                now_iso=created, now_epoch=now,
                reserved_profile_id=reserved_profile_id,
            )
            profile_id = str(creation.profile["profile_id"])
            invitation_code_hash = str(item.get("invitation_code_hash") or "").strip()
            if not invitation_code_hash:
                return _error("manual_review_required", 409)
            consumed_invitation = invitations.get_item(
                Key={"code_hash": invitation_code_hash}, ConsistentRead=True,
            ).get("Item")
            try:
                provider_bindings = _consumed_invitation_provider_bindings(
                    consumed_invitation,
                    household_id=household_id,
                    profile_id=profile_id,
                    member_principal_id=subject,
                )
            except AccountFoundationError:
                return _error("manual_review_required", 409)
            authority = {
                "role": role,
                "canonical_role": role,
                "household_access_role": household_access,
                "cloud_access_enabled": cloud_access_enabled,
                "request_access_enabled": request_access_enabled,
                "parental_controls": parental_controls,
                "switch_profile_ids": switch_profile_ids,
                "watching_profile_ids": watching_profile_ids,
            }
            legacy_profile = {
                "profile_id": profile_id,
                "account_id": account_id,
                "household_id": household_id,
                "member_principal_id": subject,
                "display_name": str(creation.profile["display_name"]),
                "profile_type": str(creation.profile["profile_type"]),
                **authority,
                "state": "active",
                "created_at": created,
                "device_access_enabled": True,
                **provider_bindings,
            }
            normal_profile = {**creation.profile, **authority}
            binding = creation.binding
            outcome = "profile_created"
        elif action == "map_existing_profile":
            profile_id = str(body.get("cloud_profile_id") or "")
            legacy_profile = profiles.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item")
            normal_profile = cloud_profiles.get_item(Key={"profile_id": profile_id}, ConsistentRead=True).get("Item")
            binding = None
            if not isinstance(legacy_profile, dict) or str(legacy_profile.get("account_id") or "") != account_id or str(legacy_profile.get("household_id") or "") != household_id:
                return _error("manual_review_required", 409)
            try:
                validate_profile(normal_profile, household_id=household_id)
                if not hmac.compare_digest(
                    str(normal_profile.get("age_classification") or ""),
                    role,
                ):
                    raise AccountFoundationError("profile_classification_conflict")
                existing_binding = profile_bindings.get_item(Key={"account_id": account_id, "profile_id": profile_id}, ConsistentRead=True).get("Item")
                validate_binding(existing_binding, account_id=account_id, profile=normal_profile, household_id=household_id)
            except AccountFoundationError:
                return _error("manual_review_required", 409)
            outcome = "profile_mapped"
        else:
            return _error("transaction_invalid")
        mapping = build_confirmed_mapping(installation_id=installation_id, local_source_id=source_id, account_id=account_id, household_id=household_id, cloud_profile_id=profile_id, now_iso=created, now_epoch=now)
    except AccountFoundationError:
        return _error("transaction_invalid")
    entitlement = None
    seat_reservation = None
    if action == "create_profile":
        owner_entitlement = entitlements.get_item(Key={"profile_id": str(item.get("owner_profile_id") or "")}, ConsistentRead=True).get("Item")
        if not owner_entitlement:
            return _error("manual_review_required", 409)
        entitlement = {"profile_id": profile_id, "entitlements_json": str(owner_entitlement.get("entitlements_json") or "{}"), "created_at": created, "updated_at": created}
        if cloud_access_enabled:
            try:
                household_owner_account_id, stored_seat_profile_ids = (
                    _household_cloud_seat_authority(household_id)
                )
                seat_reservation = _household_seat_reservation_operation(
                    household_id=household_id,
                    account_id=household_owner_account_id,
                    profile_id=profile_id,
                    seat_limit=_family_seat_limit(owner_entitlement),
                    existing_profile_ids=_active_cloud_seat_profile_ids(household_id),
                    stored_profile_ids=stored_seat_profile_ids,
                    now_iso=created,
                )
            except AccountFoundationError as error:
                return _error(error.reason, 409)
    normalized_key = {"household_id": household_id, "membership_id": household_membership_id(account_id, household_id)}
    active_authority = {
        "role": role,
        "canonical_role": role,
        "household_access_role": household_access,
        "cloud_access_enabled": cloud_access_enabled,
        "request_access_enabled": request_access_enabled,
        "parental_controls": parental_controls,
        "switch_profile_ids": switch_profile_ids,
        "watching_profile_ids": watching_profile_ids,
    }
    active_principal = {
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        **active_authority,
        "authz_version": 1,
        "profile_ids": [profile_id],
        "state": "active",
        "revoked": False,
        "created_at": created,
    }
    active_membership = {
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        **active_authority,
        "authz_version": 1,
        "profile_id": profile_id,
        "state": "active",
        "created_at": created,
    }
    transaction_operations = [
        {"label": "legacy_profile", "transaction": {"Put": {"TableName": PROFILES_TABLE, "Item": legacy_profile, "ConditionExpression": "attribute_not_exists(profile_id)"}}} if action == "create_profile" else None,
        {"label": "cloud_profile", "transaction": {"Put": {"TableName": CLOUD_PROFILES_TABLE, "Item": normal_profile, "ConditionExpression": "attribute_not_exists(profile_id)"}}} if action == "create_profile" else None,
        {"label": "profile_binding", "transaction": {"Put": {"TableName": PROFILE_BINDINGS_TABLE, "Item": binding, "ConditionExpression": "attribute_not_exists(account_id) AND attribute_not_exists(profile_id)"}}} if binding else None,
        {"label": "profile_mapping", "transaction": {"Put": {"TableName": PROFILE_MAPPINGS_TABLE, "Item": mapping, "ConditionExpression": "attribute_not_exists(installation_id) AND attribute_not_exists(local_profile_source_id)"}}},
        {"label": "copied_entitlement", "transaction": {"Put": {"TableName": ENTITLEMENTS_TABLE, "Item": entitlement, "ConditionExpression": "attribute_not_exists(profile_id)"}}} if entitlement else None,
        seat_reservation,
        {"label": "principal", "transaction": {"Put": {
            "TableName": PRINCIPALS_TABLE,
            "Item": active_principal,
            "ConditionExpression": (
                "attribute_not_exists(principal_id) OR "
                "(#state = :revoked AND revoked = :revoked_flag "
                "AND account_id = :account_id AND profile_ids = :empty_profile_ids)"
            ),
            "ExpressionAttributeNames": {"#state": "state"},
            "ExpressionAttributeValues": {
                ":revoked": "revoked",
                ":revoked_flag": True,
                ":account_id": account_id,
                ":empty_profile_ids": [],
            },
        }}},
        {"label": "identity_membership", "transaction": {"Put": {"TableName": MEMBERSHIPS_TABLE, "Item": active_membership, "ConditionExpression": "attribute_not_exists(principal_id)"}}},
        {"label": "normalized_membership", "transaction": {"Update": {
            "TableName": HOUSEHOLD_MEMBERSHIPS_TABLE,
            "Key": normalized_key,
            "UpdateExpression": (
                "SET #status = :active, profile_id = :profile, "
                "updated_at = :updated, updated_at_epoch = :epoch"
            ),
            "ConditionExpression": (
                "#status = :pending AND canonical_role = :role "
                "AND household_access_role = :access_role "
                "AND cloud_access_enabled = :cloud_access "
                "AND request_access_enabled = :request_access "
                "AND parental_controls = :parental_controls "
                "AND switch_profile_ids = :switch_profiles "
                "AND watching_profile_ids = :watching_profiles"
            ),
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {
                ":active": "active",
                ":pending": "pending_profile",
                ":profile": profile_id,
                ":role": role,
                ":access_role": household_access,
                ":cloud_access": cloud_access_enabled,
                ":request_access": request_access_enabled,
                ":parental_controls": parental_controls,
                ":switch_profiles": switch_profile_ids,
                ":watching_profiles": watching_profile_ids,
                ":updated": created,
                ":epoch": now,
            },
        }}},
        {"label": "join_transaction", "transaction": {"Update": {"TableName": JOIN_TABLE, "Key": {"join_resume_hash": str(item["join_resume_hash"])}, "UpdateExpression": "SET #state = :completed, profile_id = :profile, updated_at = :updated", "ConditionExpression": "#state = :accepted", "ExpressionAttributeNames": {"#state": "state"}, "ExpressionAttributeValues": {":completed": "completed", ":accepted": "membership_accepted", ":profile": profile_id, ":updated": created}}}},
        {"label": "pending_lookup", "transaction": {"Update": {"TableName": JOIN_TABLE, "Key": {"join_resume_hash": _pending_lookup_key(subject, str(item.get("device_binding_hash") or ""))}, "UpdateExpression": "SET #state = :completed, profile_id = :profile, updated_at = :updated", "ConditionExpression": "#state = :pending", "ExpressionAttributeNames": {"#state": "state"}, "ExpressionAttributeValues": {":completed": "completed", ":pending": "profile_setup_required", ":profile": profile_id, ":updated": created}}}},
    ]
    transaction_operations = [entry for entry in transaction_operations if entry is not None]
    transaction = [entry["transaction"] for entry in transaction_operations]
    try:
        # This resource client's attached DynamoDB transformer owns the sole
        # native-to-wire conversion for the follow-on profile transition too.
        dynamodb.meta.client.transact_write_items(TransactItems=transaction)
    except ClientError as error:
        return _profile_setup_transaction_failure(error, transaction_operations)
    return response(200, {"state": outcome, "next": "installation_setup_required"})


def _canonical_route_path(event):
    """Normalize the HTTP API stage prefix without accepting arbitrary paths."""
    path = str(event.get("rawPath") or event.get("path") or "")
    stage = str((event.get("requestContext") or {}).get("stage") or "").strip("/")
    if stage and stage != "$default":
        prefix = f"/{stage}"
        if path == prefix:
            return "/"
        if path.startswith(prefix + "/"):
            return path[len(prefix):]
    return path


def lambda_handler(event, _context):
    if isinstance(event, dict):
        event = dict(event)
        request_id = str(getattr(_context, "aws_request_id", "") or "")
        event["_kaevo_lambda_request_fingerprint"] = _safe_fingerprint(request_id)
    method = str((event.get("requestContext") or {}).get("http", {}).get("method") or event.get("requestContext", {}).get("httpMethod") or event.get("httpMethod") or "").upper()
    path = _canonical_route_path(event)
    if method == "POST" and path == "/v3/identity/household-joins/begin":
        return begin(event)
    if method == "POST" and path == "/v3/identity/household-joins/route-auth":
        return route_auth(event)
    if method == "POST" and path == "/v3/identity/household-joins/resolve-email":
        return resolve_email(event)
    if method == "GET" and path == "/v3/identity/household-joins/authorize":
        return authorize(event)
    if method == "POST" and path == "/v3/identity/household-joins/auth-result":
        return auth_result(event)
    if method == "POST" and path == "/v3/identity/household-joins/complete":
        return complete(event)
    if method == "POST" and path == "/v3/identity/household-joins/complete-native":
        return complete_native(event)
    if method == "GET" and path == "/v3/identity/household-joins/onboarding-status":
        return onboarding_status(event)
    if method == "POST" and path == "/v3/identity/household-joins/profile-setup":
        return profile_setup(event)
    return _error("not_found", 404)
