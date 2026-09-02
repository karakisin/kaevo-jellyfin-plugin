"""Verified App Store subscription projection for Kaevo Cloud.

Only Apple's signed JWS objects may reach the policy projection in this
module. Client JSON is routing input, never subscription authority.
"""

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone

from apple_root_certificates import (
    APPLE_ROOT_CERTIFICATE_SHA256,
    APPLE_ROOT_CERTIFICATES_BASE64,
)
from subscription_policy import entitlements_for_verified_subscription


BUNDLE_ID = "com.sumagang.kaevo"
APP_APPLE_ID = 6791814568
SUPPORTED_ENVIRONMENTS = frozenset({"Production", "Sandbox"})
STATUS_STATES = {
    1: "active",
    2: "expired",
    3: "billing_retry",
    4: "grace_period",
    5: "revoked",
}


class AppStoreSubscriptionError(Exception):
    """Base class for bounded route failures."""


class AppStoreConfigurationError(AppStoreSubscriptionError):
    pass


class AppStoreVerificationError(AppStoreSubscriptionError):
    def __init__(self, reason="verification_failed", *, retryable=False):
        super().__init__(reason)
        self.reason = reason
        self.retryable = retryable


class AppStoreBindingConflict(AppStoreSubscriptionError):
    pass


class AppStoreBindingMissing(AppStoreSubscriptionError):
    pass


def _environment_name(value):
    normalized = str(value or "").strip().lower()
    if normalized == "production":
        return "Production"
    if normalized == "sandbox":
        return "Sandbox"
    raise AppStoreVerificationError("unsupported_environment")


def load_root_certificates(encoded_value=None):
    """Load the pinned Apple PKI roots or an explicit test-only override."""
    raw = str(encoded_value or "").strip()
    if raw:
        try:
            values = json.loads(raw) if raw.startswith("[") else raw.split(",")
        except json.JSONDecodeError as error:
            raise AppStoreConfigurationError("apple_root_certificates_invalid") from error
        expected_fingerprints = None
    else:
        values = APPLE_ROOT_CERTIFICATES_BASE64
        expected_fingerprints = APPLE_ROOT_CERTIFICATE_SHA256
    if not isinstance(values, (list, tuple)) or not values:
        raise AppStoreConfigurationError("apple_root_certificates_invalid")
    certificates = []
    try:
        for value in values:
            encoded = "".join(str(value or "").split())
            if not encoded:
                raise ValueError
            certificates.append(base64.b64decode(encoded, validate=True))
    except (binascii.Error, ValueError) as error:
        raise AppStoreConfigurationError("apple_root_certificates_invalid") from error
    if expected_fingerprints is not None:
        actual = tuple(hashlib.sha256(value).hexdigest() for value in certificates)
        if actual != expected_fingerprints:
            raise AppStoreConfigurationError("apple_root_certificates_fingerprint_mismatch")
    return certificates


def make_signed_data_verifier(environment, root_certificates_base64=None):
    """Construct Apple's verifier lazily so local policy tests stay isolated."""
    environment_name = _environment_name(environment)
    try:
        from appstoreserverlibrary.models.Environment import Environment
        from appstoreserverlibrary.signed_data_verifier import SignedDataVerifier
    except ImportError as error:
        raise AppStoreConfigurationError("app_store_server_library_missing") from error

    library_environment = (
        Environment.PRODUCTION
        if environment_name == "Production"
        else Environment.SANDBOX
    )
    try:
        return SignedDataVerifier(
            load_root_certificates(root_certificates_base64),
            True,
            library_environment,
            BUNDLE_ID,
            APP_APPLE_ID if environment_name == "Production" else None,
        )
    except AppStoreConfigurationError:
        raise
    except Exception as error:
        raise AppStoreConfigurationError("app_store_verifier_configuration_invalid") from error


def _verification_failure(error):
    status = getattr(error, "status", None)
    status_name = str(getattr(status, "name", "") or "").strip()
    return AppStoreVerificationError(
        status_name.lower() or "verification_failed",
        retryable=status_name == "RETRYABLE_VERIFICATION_FAILURE",
    )


def verify_signed_transaction(signed_transaction, environment, verifier):
    if not isinstance(signed_transaction, str) or not signed_transaction.strip():
        raise AppStoreVerificationError("signed_transaction_required")
    environment_name = _environment_name(environment)
    try:
        transaction = verifier.verify_and_decode_signed_transaction(
            signed_transaction.strip()
        )
    except Exception as error:
        raise _verification_failure(error) from error
    if str(getattr(transaction, "bundleId", "") or "") != BUNDLE_ID:
        raise AppStoreVerificationError("invalid_app_identifier")
    raw_environment = str(
        getattr(transaction, "rawEnvironment", None)
        or getattr(getattr(transaction, "environment", None), "value", "")
        or ""
    )
    if raw_environment and raw_environment != environment_name:
        raise AppStoreVerificationError("invalid_environment")
    original_transaction_id = str(
        getattr(transaction, "originalTransactionId", "") or ""
    ).strip()
    transaction_id = str(getattr(transaction, "transactionId", "") or "").strip()
    product_id = str(getattr(transaction, "productId", "") or "").strip()
    expires_date_ms = int(getattr(transaction, "expiresDate", 0) or 0)
    signed_date_ms = int(getattr(transaction, "signedDate", 0) or 0)
    if not all((original_transaction_id, transaction_id, product_id, expires_date_ms, signed_date_ms)):
        raise AppStoreVerificationError("incomplete_subscription_transaction")
    try:
        entitlements_for_verified_subscription(
            product_id, "inactive", source="app_store_verified_transaction"
        )
    except ValueError as error:
        raise AppStoreVerificationError("unsupported_subscription_product") from error
    return transaction


def verify_signed_notification(signed_payload, verifier):
    if not isinstance(signed_payload, str) or not signed_payload.strip():
        raise AppStoreVerificationError("signed_payload_required")
    try:
        return verifier.verify_and_decode_notification(signed_payload.strip())
    except Exception as error:
        raise _verification_failure(error) from error


def subscription_state(transaction, *, raw_status=None, now_ms=None):
    if raw_status is not None:
        try:
            mapped = STATUS_STATES.get(int(raw_status))
        except (TypeError, ValueError):
            mapped = None
        if mapped:
            return mapped
    if getattr(transaction, "revocationDate", None):
        return "revoked"
    if getattr(transaction, "isUpgraded", False):
        return "expired"
    current_ms = int(now_ms if now_ms is not None else datetime.now(timezone.utc).timestamp() * 1000)
    return "active" if int(getattr(transaction, "expiresDate", 0) or 0) > current_ms else "expired"


def _iso_from_milliseconds(value):
    milliseconds = int(value or 0)
    if milliseconds <= 0:
        return ""
    return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat()


def _conditional_failure(error):
    response = getattr(error, "response", None) or {}
    return str((response.get("Error") or {}).get("Code") or "") == "ConditionalCheckFailedException"


def _binding_for(table, original_transaction_id):
    return table.get_item(
        Key={"original_transaction_id": original_transaction_id},
        ConsistentRead=True,
    ).get("Item")


def _persist_projection(
    *,
    transaction,
    environment,
    source,
    signed_date_ms,
    transactions_table,
    entitlements_table,
    account_id=None,
    household_id=None,
    profile_id=None,
    raw_status=None,
    notification_uuid="",
):
    original_transaction_id = str(transaction.originalTransactionId)
    existing = _binding_for(transactions_table, original_transaction_id)
    if existing:
        if account_id and str(existing.get("account_id") or "") != account_id:
            raise AppStoreBindingConflict("transaction_bound_to_different_account")
        account_id = str(existing.get("account_id") or "")
        household_id = str(existing.get("household_id") or "")
        profile_id = str(existing.get("profile_id") or "")
        if str(existing.get("environment") or "") != environment:
            raise AppStoreBindingConflict("transaction_environment_conflict")
        if int(existing.get("last_signed_date_ms") or 0) > int(signed_date_ms):
            return {
                "state": "stale_update_ignored",
                "subscription_state": str(existing.get("subscription_state") or ""),
            }
    if not all((account_id, household_id, profile_id)):
        raise AppStoreBindingMissing("transaction_binding_missing")

    state = subscription_state(transaction, raw_status=raw_status)
    product_id = str(transaction.productId)
    entitlements = entitlements_for_verified_subscription(
        product_id,
        state,
        source=source,
        renews_at=_iso_from_milliseconds(transaction.expiresDate),
        expires_at=_iso_from_milliseconds(transaction.expiresDate),
    )
    timestamp = datetime.now(timezone.utc).isoformat()
    binding = {
        "original_transaction_id": original_transaction_id,
        "entity_type": "AppStoreSubscriptionBinding",
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "environment": environment,
        "product_id": product_id,
        "transaction_id": str(transaction.transactionId),
        "subscription_state": state,
        "last_signed_date_ms": int(signed_date_ms),
        "last_notification_uuid": str(notification_uuid or ""),
        "created_at": str((existing or {}).get("created_at") or timestamp),
        "updated_at": timestamp,
    }
    try:
        transactions_table.put_item(
            Item=binding,
            ConditionExpression=(
                "attribute_not_exists(original_transaction_id) OR "
                "(account_id = :account_id AND environment = :environment "
                "AND last_signed_date_ms <= :signed_date)"
            ),
            ExpressionAttributeValues={
                ":account_id": account_id,
                ":environment": environment,
                ":signed_date": int(signed_date_ms),
            },
        )
    except Exception as error:
        if not _conditional_failure(error):
            raise
        latest = _binding_for(transactions_table, original_transaction_id)
        if latest and str(latest.get("account_id") or "") != account_id:
            raise AppStoreBindingConflict("transaction_bound_to_different_account") from error
        return {
            "state": "stale_update_ignored",
            "subscription_state": str((latest or {}).get("subscription_state") or ""),
        }

    existing_entitlement_item = entitlements_table.get_item(
        Key={"profile_id": profile_id},
        ConsistentRead=True,
    ).get("Item") or {}
    entitlement_item = {
        "profile_id": profile_id,
        "entitlements_json": json.dumps(entitlements, separators=(",", ":")),
        "app_store_original_transaction_id": original_transaction_id,
        "app_store_signed_date_ms": int(signed_date_ms),
        "created_at": str(existing_entitlement_item.get("created_at") or timestamp),
        "updated_at": timestamp,
    }
    try:
        entitlements_table.put_item(
            Item=entitlement_item,
            ConditionExpression=(
                "attribute_not_exists(app_store_signed_date_ms) "
                "OR app_store_signed_date_ms <= :signed_date"
            ),
            ExpressionAttributeValues={":signed_date": int(signed_date_ms)},
        )
    except Exception as error:
        if not _conditional_failure(error):
            raise
        return {"state": "stale_update_ignored", "subscription_state": state}
    return {
        "state": "subscription_updated",
        "subscription_state": state,
        "entitlements": entitlements,
    }


def sync_signed_transaction(
    *,
    signed_transaction,
    environment,
    session,
    transactions_table,
    entitlements_table,
    verifier,
):
    environment_name = _environment_name(environment)
    transaction = verify_signed_transaction(
        signed_transaction, environment_name, verifier
    )
    return _persist_projection(
        transaction=transaction,
        environment=environment_name,
        source="app_store_verified_transaction",
        signed_date_ms=int(transaction.signedDate),
        transactions_table=transactions_table,
        entitlements_table=entitlements_table,
        account_id=str(session.get("account_id") or ""),
        household_id=str(session.get("household_id") or ""),
        profile_id=str(session.get("profile_id") or ""),
    )


def process_signed_notification(
    *,
    signed_payload,
    environment,
    transactions_table,
    entitlements_table,
    verifier,
):
    environment_name = _environment_name(environment)
    notification = verify_signed_notification(signed_payload, verifier)
    notification_type = str(
        getattr(notification, "rawNotificationType", None)
        or getattr(getattr(notification, "notificationType", None), "value", "")
        or ""
    )
    if notification_type == "TEST":
        return {"state": "test_notification_verified"}
    data = getattr(notification, "data", None)
    signed_transaction = getattr(data, "signedTransactionInfo", None) if data else None
    if not signed_transaction:
        return {"state": "verified_notification_ignored"}
    transaction = verify_signed_transaction(
        signed_transaction, environment_name, verifier
    )
    return _persist_projection(
        transaction=transaction,
        environment=environment_name,
        source="app_store_server_notification",
        signed_date_ms=int(
            getattr(notification, "signedDate", 0)
            or getattr(transaction, "signedDate", 0)
            or 0
        ),
        transactions_table=transactions_table,
        entitlements_table=entitlements_table,
        raw_status=getattr(data, "rawStatus", None),
        notification_uuid=str(getattr(notification, "notificationUUID", "") or ""),
    )
